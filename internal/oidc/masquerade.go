// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Stepping into an organization, and stepping back out.
//
//	POST /v1/iam/assume   {"org":"acme"}   step in
//	POST /v1/iam/release                   step back out
//
// A platform operator supports every tenant and therefore has to see what a
// tenant sees. What they must never do is become invisible while doing it, so
// nobody is impersonated here and no identity is swapped: both endpoints
// RE-SCOPE the credential the caller presents. The subject, owner and name on
// the token that comes back are the operator's own, unchanged, and the
// organization stepped into is named beside them in `assumed`. Every act
// downstream is attributed to the person who performed it.
//
// It is not a second way to authenticate. Nothing here reads a password, a code
// or a session — it takes a live access token and returns the same person's
// token with a different scope, so a caller who cannot already sign in gains
// nothing, and the credential it re-scopes expires on its own schedule.
//
// The tenant reaches the operator's token through `orgs`, which the assumed
// organization joins. That is the set a resource server already reads to admit
// an org switch, so the tenant becomes reachable through the mechanism the
// estate already has rather than a second one taught to every consumer.
//
// ONLY a SuperAdmin may, and the predicate is store.IsSuperAdmin — belonging to
// the reserved admin org — which is the same question authz.Principal.Super
// answers above this seam. A per-org isAdmin is a different, org-scoped fact:
// reading it here would let the admin of one tenant step into every other, and
// that is the entire escalation this endpoint would otherwise be.
const (
	PathAssume  = "/v1/iam/assume"
	PathRelease = "/v1/iam/release"
)

// assumeBody names the organization to step into. Release binds the same shape
// and names none, so the two acts share one binding and one resolution.
type assumeBody struct {
	Org string `json:"org"`

	// The credential being re-scoped, and the address it arrived from. Bound from
	// headers because zip hands a typed handler no request — and an audit row that
	// cannot say where the act came from is half a record.
	Auth      string `json:"-" header:"Authorization"`
	Forwarded string `json:"-" header:"X-Forwarded-For"`
}

// assumed is the answer both endpoints give: the re-scoped credential, and the
// organization it is scoped to. Release answers with the same shape and an empty
// `assumed`, so a client renders "acting as" from one field either way.
type assumed struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
	Assumed     string `json:"assumed,omitempty"`
}

// assumeHandler steps a platform operator into an organization: it returns their
// own access token re-scoped to that tenant, so they see what the tenant sees.
//
// The token still names the operator — stepping in is not becoming somebody
// else — and records the organization it was scoped to, so everything done with
// it is attributed to the person who did it. Only a platform operator may, and
// the attempt is recorded whether or not it succeeds.
func assumeHandler(db orm.DB) zip.TypedHandler[assumeBody, httpx.Answer] {
	return func(ctx context.Context, in *assumeBody) (*httpx.Answer, error) {
		if in.Org == "" {
			return httpx.Bad(400, "name the organization to step into", ""), nil
		}
		return rescope(ctx, db, in, in.Org)
	}
}

// releaseHandler steps a platform operator back out: it returns their own access
// token with no organization assumed, which is the credential they had before
// they stepped in. Recorded like the step in.
func releaseHandler(db orm.DB) zip.TypedHandler[assumeBody, httpx.Answer] {
	return func(ctx context.Context, in *assumeBody) (*httpx.Answer, error) {
		return rescope(ctx, db, in, "")
	}
}

// rescope re-mints the presented credential for the same person and the same
// application with org assumed — or with nothing assumed, which is what stepping
// back out is. ONE function, because the two acts differ in exactly one value and
// two copies would eventually differ in more than one.
func rescope(ctx context.Context, db orm.DB, in *assumeBody, org string) (*httpx.Answer, error) {
	bearer := httpx.BearerValue(in.Auth)
	if bearer == "" {
		return httpx.Bad(401, "present the access token you are re-scoping", CodeLoginRequired), nil
	}
	claims, err := verifyToken(ctx, db, bearer)
	if err != nil {
		return httpx.Bad(401, "the access token is not valid", CodeLoginRequired), nil
	}
	user, err := store.GetUserBySubject(ctx, db, claims.Subject)
	if err != nil {
		return httpx.Bad(500, "server_error", ""), nil
	}
	if user == nil || user.IsForbidden || user.IsDeleted {
		return httpx.Bad(401, "the access token names no usable account", CodeLoginRequired), nil
	}
	actor := user.Owner + "/" + user.Name

	// The gate. An unreadable membership set has to STOP the act rather than pass
	// it: the answer is spent on a refusal, so failing to read it is a refusal.
	super, err := store.IsSuperAdmin(ctx, db, user.Owner, user.Name)
	if err != nil {
		return httpx.Bad(500, "server_error", ""), nil
	}
	if !super {
		record(ctx, db, actionFor(org), actor, org, in.Forwarded, 403)
		return httpx.Bad(403, "only a platform operator may step into an organization", ""), nil
	}

	if org != "" {
		// The platform's own organizations are where an operator already is, so
		// stepping into one is not a scope at all.
		if store.IsReservedOrg(org) {
			return httpx.Bad(400, "that is a platform organization, not a tenant", ""), nil
		}
		target, err := store.GetOrganizationByName(ctx, db, org)
		if err != nil {
			return httpx.Bad(500, "server_error", ""), nil
		}
		if target == nil {
			return httpx.Bad(404, "the organization does not exist", ""), nil
		}
	}

	// The same application the presented credential was minted for, so the answer
	// is a replacement for that token and not a token for somewhere else: same
	// audience, same signing cert, same lifetime rule.
	app, err := store.GetApplicationByClientId(ctx, db, claims.Azp)
	if err != nil {
		return httpx.Bad(500, "server_error", ""), nil
	}
	if app == nil {
		return httpx.Bad(400, "the access token names no application", ""), nil
	}
	signer, err := signerFor(ctx, db, app, claims.Issuer)
	if err != nil {
		return httpx.Bad(500, "server_error", ""), nil
	}

	id := identityOf(ctx, db, user) // the ONE user→claims resolution
	id.Assumed = org
	if org != "" {
		id.Orgs = append(id.Orgs, schema.OrgRef{Org: org, Role: store.RoleAdmin})
	}
	ttl := appTTL(app)
	now := nowFunc()
	access, err := signer.SignUserToken(id, user.Owner, audienceOf(claims, app), app.ClientId, claims.Scope, ttl, now)
	if err != nil {
		return httpx.Bad(500, "server_error", ""), nil
	}

	row := &schema.Token{
		Owner:           user.Owner,
		Application:     app.Name,
		Organization:    user.Owner,
		User:            actor,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		AccessTokenHash: hashToken(access),
	}
	row.Name = "asm-" + hashToken(access)[:32]
	if err := store.PersistToken(ctx, db, row); err != nil {
		return httpx.Bad(500, "server_error", ""), nil
	}

	record(ctx, db, actionFor(org), actor, org, in.Forwarded, 200)

	return httpx.Good(assumed{
		AccessToken: access,
		ExpiresIn:   int(ttl.Seconds()),
		Assumed:     org,
	}), nil
}

// audienceOf keeps the presented token's audience, so the re-scoped credential is
// accepted by whatever accepted the one it replaces. A token that somehow carries
// none falls back to the application's own client id, which is what every other
// mint here defaults to.
func audienceOf(claims *Claims, app *schema.Application) string {
	if len(claims.Audience) > 0 && claims.Audience[0] != "" {
		return claims.Audience[0]
	}
	return app.ClientId
}

// record writes the privileged-access trail: WHO really acted (the operator's own
// owner/name, never the organization they stepped into), WHICH organization, WHEN,
// and from WHERE. Refusals are recorded too — an attempt to step into a tenant by
// somebody who may not is the row an auditor most wants to find.
//
// It is filed under the organization stepped into, so that tenant reading its own
// audit log sees who was in it; a release, and a refusal that named nothing, are
// filed under the actor's own organization instead. The action names are reserved
// (schema.PlatformWritten), so the generic audit-log CRUD refuses to create, alter
// or delete one and the trail cannot be forged or trimmed.
//
// A failed write never fails the act — the act already happened, and this is a
// record, not a gate.
// actionFor names the act by what it does: naming an organization is stepping
// in, naming none is stepping out. Both arms read it, so a refusal is recorded
// as the act that was refused rather than as the other one.
func actionFor(org string) string {
	if org == "" {
		return schema.ActionReleaseOrg
	}
	return schema.ActionAssumeOrg
}

func record(ctx context.Context, db orm.DB, action, actor, org, forwarded string, status int) {
	owner := org
	if owner == "" {
		owner, _ = splitSub(actor)
	}
	uri := PathAssume
	if action == schema.ActionReleaseOrg {
		uri = PathRelease
	}
	store.Record(ctx, db, &schema.AuditLog{
		Owner:        owner,
		Organization: org,
		User:         actor,
		ClientIp:     forwarded,
		Action:       action,
		Object:       org,
		Method:       "POST",
		RequestUri:   uri,
		StatusCode:   status,
	})
}
