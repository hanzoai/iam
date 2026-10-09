// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Delegation: RFC 8693 token exchange with an ACTOR and no subject_token.
//
// A trusted orchestrator (cloud, as hanzo-cloud) runs work FOR a person in a
// process it does not trust: a sandbox executing a model's output. That process
// needs a credential for its model calls, and both credentials it could otherwise
// be handed are wrong. The orchestrator's own machine token bills the platform
// for every tenant's work and puts the deployment's identity in a box an attacker
// may control; the person's full token (tokens/issue) is everything the person may
// do. So the orchestrator asks for a third thing: a token whose subject is the
// person, in the one org the work bills, whose actor is the orchestrator, that
// reaches model inference and nothing else, and that dies with the work.
//
//	POST /v1/iam/oauth/token
//	grant_type=urn:ietf:params:oauth:grant-type:token-exchange
//	client_id, client_secret              the orchestrator, confidential
//	actor_token=<its own access token>    RFC 8693 §2.1
//	requested_subject=<sub | owner/name>  the person
//	org=<slug>                            the org the work bills
//	scope=ai:inference                    the one scope a delegation carries
//	resource=https://api.hanzo.ai         RFC 8707, an absolute https URI
//	lifetime=<seconds>                    at most delegationTTL, one way
//	run=<id>                              recorded, never signed
//
// There is no subject_token because the person is not present: a run a Slack
// message started holds no token of theirs. What stands in for that proof is the
// allow-list (IAM_DELEGATION_APPS: admin-owned clients only, fail closed), the
// membership IAM checks itself, and how little the token that comes back can do.
//
// What comes back is the person's token narrowed four ways, and each narrowing is
// a claim a consumer already reads:
//
//	orgs        the one org asked for, so no org switch reaches another, and the
//	            org is never a reserved one, so the token is never SuperAdmin
//	scope       ai:inference (schema.Confined): cloud serves it model calls only,
//	            and IAM accepts it as a bearer nowhere (verifyBearer)
//	aud         an https URI, never a client id, so no consumer that admits a
//	            token by its client (S3's federation) admits this one; azp is
//	            empty for the same reason
//	exp         the run's deadline, at most delegationTTL; no refresh token
//
// and `act` names the orchestrator, so every reader sees who acted.

// delegationTTL caps a delegated token's life. A run is bounded well inside it;
// the cap is what a client that forgets to say how long its run lasts gets.
const delegationTTL = 4 * time.Hour

// delegationAllowed reports whether app may obtain delegated tokens. Its own list,
// separate from IAM_TOKEN_EXCHANGE_APPS: a delegation reaches less than an
// exchange, and a client allowed the narrower act is not thereby allowed the
// wider. Same owner-pin as mintAllowed, so a tenant's colliding clientId acts for
// nobody. Unset, it allows nothing.
func delegationAllowed(app *schema.Application) bool {
	return policy.IsSigningOwner(app.Owner) && appInList("IAM_DELEGATION_APPS", app.ClientId)
}

// delegate answers a token exchange that names its subject (requested_subject).
// client has already proved its secret.
func delegate(c *zip.Ctx, db orm.DB, client *schema.Application) error {
	ctx := c.Context()
	now := nowFunc()
	d := delegation{
		client:  client.ClientId,
		subject: strings.TrimSpace(param(c, "requested_subject")),
		org:     param(c, "org"),
		run:     param(c, "run"),
		ip:      httpx.ClientIP(c),
		filed:   client.Owner,
	}
	refuse := func(status int, code, desc string) error {
		d.record(ctx, db, status, desc)
		return tokenError(c, status, code, desc)
	}

	if !delegationAllowed(client) {
		return refuse(403, "unauthorized_client", "client is not permitted to delegate")
	}
	// From here the client is trusted to name the org, so the row is filed where
	// that org's tenant reads it.
	if d.org == "" || len(d.org) > 128 || policy.HasUnsafeRune(d.org) {
		return refuse(400, "invalid_request", "org is required")
	}
	d.filed = d.org
	if param(c, "subject_token") != "" {
		return refuse(400, "invalid_request", "a delegation names its subject and presents no subject_token")
	}
	if len(d.run) > 128 || policy.HasUnsafeRune(d.run) {
		return refuse(400, "invalid_request", "run is not an identifier")
	}
	if rt := param(c, "requested_token_type"); rt != "" && rt != tokenTypeAccessToken {
		return refuse(400, "invalid_request", "only an access_token may be requested")
	}

	actor, why := actorProof(ctx, db, c, client)
	if why != "" {
		return refuse(400, "invalid_grant", why)
	}
	scope := strings.TrimSpace(param(c, "scope"))
	if scope != schema.Inference {
		return refuse(400, "invalid_scope", "the one scope a delegation carries is "+schema.Inference)
	}
	aud := resourceOf(c)
	if !resourceURI(aud) {
		return refuse(400, "invalid_target", "resource must be an absolute https URI")
	}

	user, err := store.GetUserBySubject(ctx, db, d.subject)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if user == nil || user.IsForbidden || user.IsDeleted || user.Machine() {
		return refuse(400, "invalid_grant", "the subject is not a person who may be acted for")
	}
	d.subject = user.Owner + "/" + user.Name
	// A reserved-org identity (every SuperAdmin) is never delegated: IAM reads its
	// authority off the ROW, so a token naming it is the platform's authority in a
	// box running model output, however narrow its claims. Its owner works in a
	// tenant through their tenant account.
	if policy.IsReservedOrg(user.Owner) {
		return refuse(403, "access_denied", "a reserved-org identity is never delegated")
	}
	if policy.IsReservedOrg(d.org) {
		return refuse(403, "access_denied", "a delegated token never acts in a reserved org")
	}
	ref, ok, err := membership(ctx, db, user, d.org)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if !ok {
		return refuse(403, "access_denied", "the subject is not a member of "+d.org)
	}

	// A caller may ask for less life than the cap and never more.
	ttl := min(appTTL(client), delegationTTL)
	if want := seconds(param(c, "lifetime")); want > 0 && want < ttl {
		ttl = want
	}
	d.ttl = ttl

	// The person as their own token states them, narrowed to the one org. The
	// billing claim names the HOME org's pool; acting anywhere else, the person's
	// own token spends by the shape rule (account.Payer ignores a claim naming
	// another org), so the delegated token carries none there and spends the same.
	id := identityOf(ctx, db, user)
	id.Orgs = []schema.OrgRef{ref}
	if d.org != user.Owner {
		id.Billing = ""
	}
	id.Act = &actor
	signer, err := signerFor(ctx, db, client, tokenIssuer(c))
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	access, err := signer.SignUserToken(id, d.org, aud, "", scope, ttl, now)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	row := &schema.Token{
		Owner:           d.org,
		Application:     client.Name,
		Organization:    d.org,
		User:            d.subject,
		Scope:           scope,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		AccessTokenHash: hashToken(access),
	}
	// 'dl-' beside 'tx-', 'iut-' and 'as-': revocable by the client that asked,
	// and live to introspection while the row stands.
	row.Name = "dl-" + hashToken(access)[:32]
	if err := store.PersistToken(ctx, db, row); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	d.record(ctx, db, 200, "")

	// RFC 8693 §2.2. No refresh_token: the token ends with the work it was for.
	return c.JSON(200, map[string]any{
		"access_token":      access,
		"issued_token_type": tokenTypeAccessToken,
		"token_type":        "Bearer",
		"expires_in":        int(ttl.Seconds()),
		"scope":             scope,
	})
}

// actorProof verifies the actor_token: the client's OWN machine credential, as
// client_credentials or the workload grant minted it, alive. Never a person's
// token, another client's, or one that is itself acted for or confined. The
// answer is the `act` the delegated token carries, or why it was refused.
func actorProof(ctx context.Context, db orm.DB, c *zip.Ctx, client *schema.Application) (Actor, string) {
	raw := param(c, "actor_token")
	if raw == "" {
		return Actor{}, "actor_token is required"
	}
	if t := param(c, "actor_token_type"); t != "" && t != subjectTokenTypeAccess && t != subjectTokenTypeJWTToken {
		return Actor{}, "unsupported actor_token_type"
	}
	claims, err := verifyBearer(ctx, db, raw)
	if err != nil {
		return Actor{}, "actor_token is invalid or expired"
	}
	if claims.Type != schema.Program || claims.Azp != client.ClientId || claims.Subject != client.GetId() ||
		claims.Act != nil || claims.Imp {
		return Actor{}, "actor_token is not this client's own credential"
	}
	if row, err := store.GetTokenByAccessTokenHash(ctx, db, hashToken(raw)); err != nil || row == nil {
		return Actor{}, "actor_token is invalid or expired"
	}
	return Actor{Sub: claims.Subject, Owner: client.Owner, Name: client.Name}, ""
}

// membership is the person's standing in org as their own token states it: the
// home org or a membership row (store.MemberOrgRefs), in an org that exists.
func membership(ctx context.Context, db orm.DB, user *schema.User, org string) (schema.OrgRef, bool, error) {
	o, err := store.GetOrganizationByName(ctx, db, org)
	if err != nil || o == nil {
		return schema.OrgRef{}, false, err
	}
	for _, r := range store.MemberOrgRefs(ctx, db, user) {
		if r.Org == org {
			return r, true, nil
		}
	}
	return schema.OrgRef{}, false, nil
}

// resourceURI reports whether s is an RFC 8707 resource: an absolute URI, here
// https with a host and nothing a server would not name itself by. It is never a
// client id, which is the point: a consumer that admits a token by its client
// must not find one here.
func resourceURI(s string) bool {
	u, err := url.Parse(s)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil &&
		u.RawQuery == "" && u.Fragment == ""
}

// delegation is one attempt's audit row: the person, the org asked for, the
// client that acts, the run, the lifetime granted and the answer.
type delegation struct {
	client, subject, org, run, ip string
	// filed is the org the row is filed under: the client's own until it is
	// known to be allowed to name an org, then the org it named.
	filed string
	ttl   time.Duration
}

// record writes the row. A failed write never fails the act; this is a record.
func (d delegation) record(ctx context.Context, db orm.DB, status int, why string) {
	object, _ := json.Marshal(map[string]any{
		"actor": d.client,
		"org":   clip(d.org, 128),
		"run":   clip(d.run, 128),
		"ttl":   int(d.ttl / time.Second),
		"scope": schema.Inference,
	})
	store.Record(ctx, db, &schema.AuditLog{
		Owner:        d.filed,
		Organization: d.filed,
		User:         clip(d.subject, 256),
		ClientIp:     d.ip,
		Method:       "POST",
		RequestUri:   PathToken,
		Action:       schema.ActionDelegate,
		Object:       string(object),
		Response:     why,
		StatusCode:   status,
	})
}
