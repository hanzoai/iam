// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Signing in AS another person, so support can reproduce what they see.
//
//	POST /v1/iam/impersonate  {"target":"acme/alice","reason":"…","clientId":"hanzo-platform"}
//
// It answers a single-use login_hint, never a token. The site that hint is for
// starts its own sign-in with it (OIDC Core §4, third-party-initiated login), so
// the SITE supplies state, nonce and the PKCE challenge, the code reaches only a
// redirect_uri the site registered, and the site redeems it at the ordinary token
// endpoint with its own verifier. The browser that spends the hint must also hold
// the operator's session at this issuer, so a hint that leaks is inert.
//
// What the site gets is the TARGET's token — sub, owner, name and orgs are
// theirs — with the operator in `act` and `imp: true` beside them, at most
// impersonationTTL long and never refreshable. The authority is the target's
// alone: unlike assume, the operator's own does not ride along.
//
// ONE predicate: schema.User.SuperAdmin on the operator's ROW, asked again at
// every step. Another SuperAdmin, a platform identity and a machine are never
// impersonated, a reason is required, and only an application named in
// IAM_IMPERSONATION_APPS takes one — a site that shows the mark and whose backend
// refuses an `imp` token every durable write. Unset, nothing does. Every step — the
// hint, the code, the token, and each IAM request the token makes — writes an
// ActionImpersonate row, refusals included.
const (
	PathImpersonate = "/v1/iam/impersonate"

	// envImpersonationApps lists, by clientId, the applications that take an
	// impersonated session. Fail closed: unset, impersonation reaches nothing.
	envImpersonationApps = "IAM_IMPERSONATION_APPS"

	// impersonationTTL caps the impersonated access token. Long enough to
	// reproduce a problem, short enough that nobody works as somebody else.
	impersonationTTL = 15 * time.Minute

	// hintPrefix marks a login_hint that names an impersonation rather than a
	// person. No username, address or subject holds a colon, so the two readings
	// of login_hint cannot collide.
	hintPrefix = "impersonation:"
)

// impersonateBody names who to sign in as, why, and where.
type impersonateBody struct {
	// Target is the person, "<owner>/<name>". Body only, like the reason: a URL
	// lands in access logs.
	Target string `json:"target" url:"-"`
	// Reason is why: a ticket, a sentence. Required — it is what the trail is for.
	Reason string `json:"reason" url:"-"`
	// ClientId is the application the operator will open as the target.
	ClientId string `json:"clientId"`

	// The operator's own credential, and the address the request came from.
	Auth      string `json:"-" header:"Authorization"`
	Forwarded string `json:"-" header:"X-Forwarded-For"`
}

// hint is the answer: the value the site's sign-in carries as login_hint.
type hint struct {
	LoginHint string `json:"loginHint"`
	ClientId  string `json:"clientId"`
	Target    string `json:"target"`
	ExpiresIn int    `json:"expiresIn"` // seconds the hint stays spendable
	TTL       int    `json:"ttl"`       // seconds the impersonated access token lives
}

// ticket is what the hint's challenge row carries beside its Subject (the
// target): who is acting, through which application, and why.
type ticket struct {
	Actor  string `json:"actor"`
	Client string `json:"client"`
	Reason string `json:"reason"`
}

// impersonateHandler lets a SuperAdmin open an application signed in as somebody
// else, to see what they see.
//
// It returns a one-time login_hint for that application, good for a few minutes
// and only in a browser where the operator is signed in here. The token the
// application finally receives belongs to the person, names the operator in `act`,
// carries `imp`, lasts at most fifteen minutes and cannot be refreshed. A reason
// is required and every attempt is recorded, refused or not.
func impersonateHandler(db orm.DB) zip.TypedHandler[impersonateBody, httpx.Answer] {
	return func(ctx context.Context, in *impersonateBody) (*httpx.Answer, error) {
		bearer := httpx.BearerValue(in.Auth)
		if bearer == "" {
			return httpx.Bad(401, "present your own access token", CodeLoginRequired), nil
		}
		claims, err := verifyBearer(ctx, db, bearer)
		if err != nil {
			return httpx.Bad(401, "the access token is not valid", CodeLoginRequired), nil
		}

		// What the caller sent is recorded bounded, refused or not.
		t := trail{
			target: clip(strings.TrimSpace(in.Target), 128),
			reason: clip(strings.TrimSpace(in.Reason), 512),
			client: clip(in.ClientId, 128),
			ip:     in.Forwarded,
			method: "POST",
			uri:    PathImpersonate,
		}
		refuse := func(status int, why string) (*httpx.Answer, error) {
			t.record(ctx, db, status, why)
			return httpx.Bad(status, why, ""), nil
		}

		// Impersonation does not chain, and the row names the operator holding
		// the session rather than the person it speaks for.
		if claims.Imp {
			t.actor = actorKey(claims.Act)
			return refuse(403, "an impersonated session cannot impersonate")
		}
		op, err := store.GetUserBySubject(ctx, db, claims.Subject)
		if err != nil {
			return httpx.Bad(500, "server_error", ""), nil
		}
		if op == nil {
			return httpx.Bad(401, "the access token names no account", CodeLoginRequired), nil
		}
		t.actor = op.Owner + "/" + op.Name
		// The operator's OWN sign-in: not a token a key minted for them, nor a
		// machine's.
		if claims.Act != nil || claims.Type != "" {
			return refuse(403, "present the token of your own sign-in")
		}

		// The operator first, so a refused caller learns nothing about the target.
		if status, why := operates(op); why != "" {
			return refuse(status, why)
		}
		if t.reason == "" {
			return refuse(400, "say why: a reason is required")
		}
		owner, name, _ := strings.Cut(t.target, "/")
		if owner == "" || name == "" {
			return refuse(400, "name the person as <owner>/<name>")
		}
		if t.client == "" {
			return refuse(400, "name the application to open (clientId)")
		}
		target, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return httpx.Bad(500, "server_error", ""), nil
		}
		app, err := store.GetApplicationByClientId(ctx, db, t.client)
		if err != nil {
			return httpx.Bad(500, "server_error", ""), nil
		}
		if target != nil {
			t.org, t.target = target.Owner, target.Owner+"/"+target.Name
		}
		if app != nil {
			t.ttl = lifetime(app)
		}
		if status, why := impersonable(target, app); why != "" {
			return refuse(status, why)
		}

		payload, err := json.Marshal(ticket{Actor: t.actor, Client: app.ClientId, Reason: t.reason})
		if err != nil {
			return httpx.Bad(500, "server_error", ""), nil
		}
		id, err := MintChallenge(ctx, db, KindImpersonate, t.target, string(payload), nil, nowFunc())
		if err != nil {
			return httpx.Bad(500, "server_error", ""), nil
		}
		t.record(ctx, db, 200, "")
		return httpx.Good(hint{
			LoginHint: hintPrefix + id,
			ClientId:  app.ClientId,
			Target:    t.target,
			ExpiresIn: int(challengeTTL / time.Second),
			TTL:       int(t.ttl / time.Second),
		}), nil
	}
}

// impersonation reads the challenge id out of a login_hint that names one.
func impersonation(loginHint string) (string, bool) {
	return strings.CutPrefix(loginHint, hintPrefix)
}

// impersonate answers an authorize request whose login_hint names an
// impersonation: an authorization code for the TARGET, minted through MintFor like
// every other code and bound to the client, redirect_uri, nonce and PKCE challenge
// the site sent, or an error on the site's (already validated) redirect_uri.
//
// The hint is spent before anything else is decided, so any presentation of it is
// its only one, whatever the outcome. It is honoured only for the application it was issued for, only in
// a browser where the operator who asked for it is signed in here, and only while
// the rule that admitted it still holds of the rows as they stand now. It never
// falls through to the login page: a request carrying it is answered here.
func impersonate(c *zip.Ctx, db orm.DB, app *schema.Application, q authorizeRequest, id string) error {
	ctx := c.Context()
	row, err := TakeChallenge(ctx, db, id, KindImpersonate, nowFunc())
	if err != nil {
		return authorizeErrorRedirect(c, q, errAccessDenied, "the impersonation is unknown, spent or expired")
	}
	var tk ticket
	_ = json.Unmarshal([]byte(row.Payload), &tk)
	t := trail{
		actor:  tk.Actor,
		target: row.Subject,
		reason: tk.Reason,
		client: q.clientID,
		ip:     httpx.ClientIP(c),
		method: c.Method(),
		uri:    PathAuthorize,
		ttl:    lifetime(app),
	}
	t.org, _ = splitSub(row.Subject)
	refuse := func(code, why string) error {
		t.record(ctx, db, 403, why)
		return authorizeErrorRedirect(c, q, code, why)
	}

	if !topLevelNavigation(c) {
		return refuse(errInteractionRequired, "an impersonation is opened by navigating, not by a frame or a fetch")
	}
	// The site's own verifier is what ties the code to the browser that started
	// this request. A confidential site still sends one here.
	if q.codeChallenge == "" {
		return refuse("invalid_request", "an impersonation requires a PKCE challenge")
	}
	if tk.Actor == "" || tk.Client != app.ClientId {
		return refuse(errAccessDenied, "the impersonation was issued for another application")
	}
	if !signedInHere(c, db, tk.Actor) {
		return refuse(errAccessDenied, "the operator who asked for this impersonation is not signed in on this browser")
	}
	if _, why := permitted(ctx, db, tk.Actor, row.Subject, app); why != "" {
		return refuse(errAccessDenied, why)
	}
	code, err := MintFor(ctx, db, app, row.Subject, Mint{
		Type:                "code",
		RedirectUri:         q.redirectURI,
		State:               q.state,
		Scope:               q.scope,
		Nonce:               q.nonce,
		CodeChallenge:       q.codeChallenge,
		CodeChallengeMethod: q.codeChallengeMethod,
		Resource:            q.resource,
		Actor:               tk.Actor,
		Reason:              tk.Reason,
	})
	if err != nil {
		return refuse(errAccessDenied, err.Error())
	}
	t.record(ctx, db, 200, "")
	return authorizeCodeRedirect(c, q, code)
}

// signedInHere reports whether actor ("owner/name") holds a live session on the
// browser making this request — the operator's own proof, beside the hint.
func signedInHere(c *zip.Ctx, db orm.DB, actor string) bool {
	for _, sc := range sessions.Accounts(c.Context(), c.Fiber(), db) {
		if sc.Owner+"/"+sc.Name == actor {
			return true
		}
	}
	return false
}

// permitted asks the whole rule again of the rows as they stand now: the hint
// was issued minutes ago and the code may be redeemed minutes after that, and an
// operator disabled, or a target promoted, in between must not still get through.
// It answers the HTTP status and reason of a refusal, or "" when the act may
// proceed.
func permitted(ctx context.Context, db orm.DB, actor, target string, app *schema.Application) (int, string) {
	op, err := userAt(ctx, db, actor)
	if err != nil {
		return 500, "server_error"
	}
	if status, why := operates(op); why != "" {
		return status, why
	}
	who, err := userAt(ctx, db, target)
	if err != nil {
		return 500, "server_error"
	}
	return impersonable(who, app)
}

// userAt loads the account "owner/name" names, or nil.
func userAt(ctx context.Context, db orm.DB, key string) (*schema.User, error) {
	owner, name := splitSub(key)
	if owner == "" || name == "" {
		return nil, nil
	}
	return store.GetUserByName(ctx, db, owner, name)
}

// operates reports why op may not impersonate anyone, or "" when they may. The
// ONE predicate is schema.User.SuperAdmin asked of the row: never a token claim,
// never an org's isAdmin, never a membership of the admin org.
func operates(op *schema.User) (int, string) {
	switch {
	case op == nil || op.IsForbidden || op.IsDeleted:
		return 403, "the operator's account is disabled"
	case !op.SuperAdmin():
		return 403, "only a SuperAdmin may sign in as another person"
	}
	return 0, ""
}

// impersonable reports why target may not be signed in as through app, or "".
// A SuperAdmin is never a target — that would hand one operator another's
// platform authority — and neither is anything in a platform org or a machine:
// impersonation exists to see what a tenant's person sees.
func impersonable(target *schema.User, app *schema.Application) (int, string) {
	switch {
	case target == nil:
		return 404, "the account does not exist"
	case target.SuperAdmin() || policy.IsReservedOrg(target.Owner) || target.Machine():
		return 403, "only a person in a tenant is impersonated; never a SuperAdmin, a platform identity or a machine"
	case target.IsForbidden || target.IsDeleted:
		return 400, "the account is disabled"
	case app == nil:
		return 400, "the application does not exist"
	case policy.IsReservedOrg(app.Organization):
		return 400, "that application serves a platform organization"
	case !policy.IsSigningOwner(app.Owner) || !appInList(envImpersonationApps, app.ClientId):
		return 400, "that application does not take an impersonated session"
	case target.Owner != app.Organization && !app.ServesAnyOrg():
		return 400, "that application does not sign this account in"
	}
	return 0, ""
}

// lifetime is how long an impersonated access token lives through app: the
// application's own lifetime, never more than impersonationTTL.
func lifetime(app *schema.Application) time.Duration {
	return min(appTTL(app), impersonationTTL)
}

// actorKey is the "owner/name" an `act` names, or "".
func actorKey(act *Actor) string {
	if act == nil || act.Owner == "" || act.Name == "" {
		return ""
	}
	return act.Owner + "/" + act.Name
}

// Operator is the operator ("owner/name") an impersonated token's `act` names,
// while they may still impersonate, and ErrImpersonation once they may not —
// disabled or demoted since the token was minted. The Guard asks it on every IAM
// request such a token makes, and the exchange before it carries one forward.
func Operator(ctx context.Context, db orm.DB, claims *Claims) (string, error) {
	actor := actorKey(claims.Act)
	op, err := userAt(ctx, db, actor)
	if err != nil {
		return "", err
	}
	if _, why := operates(op); why != "" {
		return "", ErrImpersonation
	}
	return actor, nil
}

// actorOf is the `act` an impersonation grant's token carries, after asking the
// rule again: the operator who opened the grant, still a SuperAdmin, and a
// target that is still somebody they may be.
func actorOf(ctx context.Context, db orm.DB, row *schema.Token, app *schema.Application) (*Actor, error) {
	if _, why := permitted(ctx, db, row.Actor, row.User, app); why != "" {
		return nil, ErrImpersonation
	}
	op, err := userAt(ctx, db, row.Actor)
	if err != nil || op == nil {
		return nil, ErrImpersonation
	}
	return &Actor{Sub: subjectOf(op), Owner: op.Owner, Name: op.Name}, nil
}

// ErrImpersonation is an impersonation grant the rule no longer admits: the
// operator was disabled or demoted, or the target changed, after the code was
// minted. The token endpoint answers invalid_grant.
var ErrImpersonation = errors.New("oidc: the impersonation is no longer permitted")

// trail is one impersonation audit row in the making: everything it records but
// how the step ended. org is the tenant it is filed under, so that tenant reads
// who was in it; it is set once the target resolves to a real account, and
// until then the row is filed under the operator's own org.
type trail struct {
	actor, target, reason, client, ip, method, uri, org string
	ttl                                                 time.Duration
}

// answered records the step from the response already written: its status, and
// on a refusal its body (an OAuth error, never a token).
func (t trail) answered(ctx context.Context, db orm.DB, c *zip.Ctx) {
	status, why := c.Fiber().Response().StatusCode(), ""
	if status != 200 {
		why = clip(string(c.Fiber().Response().Body()), 512)
	}
	t.record(ctx, db, status, why)
}

// record writes the row: the operator, the target, the reason, the application,
// the address and the token lifetime, with the answer. A failed write never fails
// the act — this is a record, not a gate.
func (t trail) record(ctx context.Context, db orm.DB, status int, why string) {
	org := t.org
	if org == "" {
		org, _ = splitSub(t.actor)
	}
	if org == "" {
		org = policy.AdminOrg
	}
	object, _ := json.Marshal(map[string]any{
		"target": t.target,
		"reason": t.reason,
		"client": t.client,
		"ttl":    int(t.ttl / time.Second),
	})
	store.Record(ctx, db, &schema.AuditLog{
		Owner:        org,
		Organization: org,
		User:         t.actor,
		ClientIp:     t.ip,
		Method:       t.method,
		RequestUri:   t.uri,
		Action:       schema.ActionImpersonate,
		Object:       string(object),
		Response:     why,
		StatusCode:   status,
	})
}
