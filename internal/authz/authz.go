// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package authz is the IAM v2 authorization seam in front of the Phase-1 entity
// CRUD, which is otherwise unauthenticated — the door an attacker would walk
// through to overwrite an admin-owned signing cert and forge tokens. It is two
// orthogonal decisions, never braided:
//
//   - AUTHENTICATION — the Guard middleware, mounted ONCE and FIRST via app.Use.
//     Every non-public request must carry a verified bearer; the resolved
//     Principal is attached to the request context for the authorization decision
//     and audit. Public routes pass straight through. Fails closed (401).
//
//   - AUTHORIZATION — the Authorize hook, installed ONCE via app.Authorize. It
//     runs at the framework's op-invoke seam, on the DECODED typed input the
//     handler will act on, for REST and MCP alike. The value it authorizes is by
//     construction the value the handler binds: there is no second parse of the
//     body for it to diverge from. Fails closed (403).
//
// Splitting the two removes the defect a single body-reparsing middleware had:
// authorizing a target extracted from the raw bytes divergently from where the
// handler binds it. A write's target now comes from the one decode the handler
// itself runs on. A read's target rides in the query string (a GET has no body
// for the op seam to decode), so the Guard authorizes reads there; a read invoked
// over MCP DOES decode a target into its input, and the op seam authorizes that.
//
// Three scopes, never conflated (conflation is privilege escalation):
//
//   - SuperAdmin — the principal's organization is the reserved "admin" org.
//     The ONLY cross-tenant scope. Required for every write to a platform-owned
//     (admin/built-in) resource: the signing-cert poisoning gate, admin-scoped
//     application/provider registration, every reserved surface.
//   - Org admin — IsAdmin, scoped to its OWN organization. Manages every
//     resource its org owns; never another org's, never a platform-owned one.
//   - Regular user — self-service only: reading its own user record.
//
// One predicate governs SuperAdmin everywhere: the principal's organization is
// "admin". That organization comes from the token SUBJECT — the authenticated
// principal's own owner/name — never from the token's `owner`/`organization`
// claims. Those name the APPLICATION's org and diverge from the user's org for a
// shared app, so trusting them would let a tenant user sign in through a shared
// admin-org app and read as SuperAdmin. Authenticity, expiry, algorithm, and
// signing-key trust are delegated to the same oidc.VerifyToken every protected
// route already uses; the org-admin flag comes from the loaded user record, the
// authoritative source (it is not a token claim).
package authz

import (
	"context"
	"errors"
	"reflect"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/oidc"
	"github.com/hanzoai/iam2/internal/store"
)

// adminOrg is the reserved organization whose membership IS SuperAdmin — the one
// cross-tenant scope, the one predicate. The broader reserved-owner set
// {admin, built-in} the poisoning gate protects lives in ONE place,
// store.IsSigningCertOwner, shared with the token verifier and the JWKS.
const adminOrg = "admin"

// Principal is the identity a gated request acts as, resolved from a verified
// bearer. Org is the tenant (the authenticated principal's own org, from the
// subject); User is its name within that org (empty for a machine token); Admin
// is the org-admin flag; Super is the SuperAdmin predicate (Org == adminOrg).
type Principal struct {
	Org   string
	User  string
	Admin bool
	Super bool
}

type ctxKey struct{}

// From returns the Principal the Guard attached to ctx for a gated request, and
// whether one is present (public routes carry none).
func From(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// Scope resolves the owner a listing is bound to: a SuperAdmin lists the owner
// it asks for (empty = every tenant), anyone else lists only its own org. The
// org comes from the verified bearer, so a request parameter can never widen a
// read beyond the caller's authority — the one value authorized is the one value
// queried. Every owner-scoped lister resolves its owner here.
func Scope(ctx context.Context, owner string) (string, error) {
	p, ok := From(ctx)
	if !ok {
		return "", zip.ErrForbidden("no principal")
	}
	if p.Super {
		return owner, nil
	}
	return p.Org, nil
}

// Fail-closed reasons. The Guard collapses all of them to one opaque 401 so a
// prober cannot tell a bad signature from an expired token from a revoked user.
var (
	errNoBearer  = errors.New("authz: no bearer")
	errNoSubject = errors.New("authz: token subject carries no org")
	errRevoked   = errors.New("authz: principal is forbidden or deleted")
)

// publicPaths is the CLOSED set of routes reachable without a bearer — the
// pre-authentication OIDC/OAuth2 and front-door surface a browser must reach
// before it can hold a token. Everything not listed here is gated: the default
// is fail-closed, so a newly mounted route (including the framework's own /mcp
// and /openapi projections of the typed handlers) is protected until it is
// deliberately published here. userinfo and logout are listed because they
// verify their own bearer (userinfo) or must clear a session without a live one
// (logout); gating them again would break their own OIDC contract.
var publicPaths = map[string]bool{
	"/healthz":                                 true, // liveness, unversioned
	"/.well-known/openid-configuration":        true, // OIDC discovery (root)
	"/v1/iam/.well-known/openid-configuration": true, // OIDC discovery (v1)
	"/.well-known/jwks":                        true, // JWKS public keys (root)
	"/v1/iam/.well-known/jwks":                 true, // JWKS public keys (v1)
	"/.well-known/oauth-authorization-server":        true, // RFC 8414 AS metadata (root)
	"/v1/iam/.well-known/oauth-authorization-server": true, // RFC 8414 AS metadata (v1)
	"/v1/iam/oauth/introspect":                       true, // RFC 7662 (client-authenticated)
	"/v1/iam/oauth/revoke":                           true, // RFC 7009 (client-authenticated)
	"/v1/iam/login":                            true, // credential login, mints the code
	"/v1/iam/oauth/authorize":                  true, // OAuth2 authorize
	"/v1/iam/oauth/token":                      true, // OAuth2 token
	"/v1/iam/oauth/userinfo":                   true, // self-verifying bearer read
	"/v1/iam/oauth/logout":                     true, // end session
	"/v1/iam/get-app-login":                    true, // pre-login app config (secrets masked)
	"/v1/iam/auth/methods":                     true, // pre-login method list
	"/v1/iam/mint-user-keys":                   true, // confidential-client auth (Basic + allow-list), not a bearer
	"/v1/iam/revoke-user-keys":                 true, // confidential-client auth (same authorizeMinter seam)
	// The front-door session/identity surface (oidc.MountFrontDoor). Each handler
	// RESOLVES the caller itself (callerOf: session cookie first, then bearer) and
	// SELF-SCOPES to that caller — so, like get-account, they are reachable without a
	// Guard-verified bearer (the portal + gateway admin-guard call them with a session
	// cookie) yet never act on anyone but the resolved caller. signup and
	// send-verification-code are pre-authentication by nature (no token exists yet).
	"/v1/iam/get-account":            true, // anonymous-safe account read (admin-guard contract)
	"/v1/iam/signup":                 true, // pre-auth account creation (own policy checks)
	"/v1/iam/send-verification-code": true, // pre-auth OTP send
	"/v1/iam/signin":                 true, // code→session exchange (the code is the credential)
	"/v1/iam/whoami":                 true, // lightweight caller identity (self-resolving)
	"/v1/iam/onboard":                true, // first-run org onboarding (self-move only)
	"/v1/iam/update-preferences":     true, // self preferences (writes only the caller's row)
	"/v1/iam/linked-accounts":        true, // the caller's own linked identities
}

// isPublic reports whether path is in the public allowlist. A trailing slash is
// trimmed first so /v1/iam/login/ resolves like /v1/iam/login — the same route
// fiber serves. It can only ever widen matches to the fixed public set, never
// turn a gated path into a public one (no gated path equals a public path plus a
// slash), so the fail-closed default holds.
func isPublic(path string) bool {
	if len(path) > 1 {
		path = strings.TrimRight(path, "/")
	}
	return publicPaths[path]
}

// isRead reports whether a method addresses its target through the query string
// rather than a body: a GET (or HEAD) has no body for the op-invoke seam to
// decode, so its target is authorized in the Guard. Every other method carries a
// body decoded once by the op and is authorized at that seam.
func isRead(method string) bool { return method == "GET" || method == "HEAD" }

// ReadTarget extracts the (owner, name) a GET addresses, from the query string.
// A native typed read files them as `?owner=&name=`; the Casdoor compat verbs
// (get-user, get-organization, …) file them as `?id=<owner>/<name>`. Explicit
// owner/name win; the id split is a fallback only when owner is absent, so this
// can only make an id-based read's authorization MORE precise than the empty
// target it resolves to today (which fail-closed denies every non-super). It
// never widens: the tenant rule still pins owner to the principal's org, and the
// handler independently re-scopes the query owner through Scope, so a request
// that spells one owner in `?owner` and another in `?id` cannot read across
// tenants — the authorized owner and the queried owner are both pinned.
//
// It is exported so the compat read aliases resolve their target through the
// SAME function the Guard authorizes with: one extraction, so a handler can
// never address a row the Guard did not authorize.
func ReadTarget(c *zip.Ctx) (owner, name string) {
	owner, name = c.Query("owner"), c.Query("name")
	if owner == "" {
		if o, n, ok := strings.Cut(c.Query("id"), "/"); ok && o != "" {
			return o, n
		}
	}
	return owner, name
}

// Guard is the AUTHENTICATION middleware. Mount it ONCE and FIRST, via app.Use,
// so it wraps every route — the typed CRUD handlers and the framework's /mcp and
// /openapi surfaces alike. Public routes pass straight through; every other route
// requires a valid bearer (401 otherwise) whose Principal is attached to the
// request context for the authorization hook downstream. A read's authorization
// target rides in the query string, so reads are authorized here; a write's rides
// in the body, decoded once by the op and authorized at the op-invoke seam
// (Authorize) on that exact decoded value — this middleware never re-parses a
// write body, which is what let the old target extraction diverge from execution.
func Guard(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		if isPublic(c.Path()) {
			return c.Continue()
		}
		p, err := principal(c, db)
		if err != nil {
			return zip.ErrUnauthorized("authentication required")
		}
		rOwner, rName := ReadTarget(c)
		if isRead(c.Method()) && !authorize(p, c.Method(), entityOf(c.Path()), rOwner, rName) {
			return zip.ErrForbidden("forbidden")
		}
		c.SetContext(context.WithValue(c.Context(), ctxKey{}, p))
		return c.Continue()
	}
}

// Authorize is the AUTHORIZATION hook, installed via app.Authorize so the
// framework runs it at every typed op's invoke seam — after the request is
// decoded into its typed In and validated, before the handler runs, for REST and
// MCP alike. It authorizes the DECODED target: the exact (owner, name) the
// handler will bind, read from the same struct the handler runs on, so the value
// authorized cannot diverge from the value written.
//
// A REST read carries its target in the query string, not the body, so its
// decoded In is empty and the Guard already authorized it there — such a call is
// admitted here (owner == ""). Every write, and any read invoked over MCP (whose
// arguments DO decode a target into In), is authorized against authorize().
func Authorize(ctx context.Context, op zip.Op, in any) error {
	if isPublic(op.Path) {
		return nil // pre-auth surface; the Guard admitted it without a principal
	}
	owner, name := decodedTarget(in)
	if owner == "" && isRead(op.Method) {
		return nil // REST read: target rode in the query, authorized by the Guard
	}
	p, present := From(ctx)
	if !present {
		return zip.ErrForbidden("forbidden") // gated op with no principal: fail closed
	}
	if !authorize(p, op.Method, entityOf(op.Path), owner, name) {
		return zip.ErrForbidden("forbidden")
	}
	return nil
}

// authorize is the pure authorization decision: may p act on a resource owned by
// `owner` (named `name`) on the given entity? The order IS the policy:
//
//  1. SuperAdmin may do anything — the only cross-tenant scope.
//  2. A platform-owned resource (admin/built-in — the reserved owners the token
//     verifier trusts to sign) is writable only by a SuperAdmin. This single
//     rule is the signing-cert poisoning gate, the admin-scoped app/provider
//     registration gate, AND the built-in-org gap, all at once: a built-in-org
//     principal is not SuperAdmin (that is admin only), so it cannot write a
//     built-in-owned signing cert either.
//  3. Tenant isolation: a normal principal may act only within its OWN org. An
//     empty or foreign owner is refused — the target org is bound to the
//     principal, never trusted from the request.
//  4. Inside its own org, an org admin manages everything; a regular user may
//     only READ its own user record (self-service). The users entity serves
//     reads as GET and writes as POST, so gating the self clause to GET keeps a
//     regular user from writing its own record — a raw entity write would
//     otherwise let it carry isAdmin and self-promote. Privileged self-mutation
//     is the Phase-5 provision-don't-promote concern; here it is closed by
//     denial.
func authorize(p *Principal, method, entity, owner, name string) bool {
	if p.Super {
		return true
	}
	if store.IsSigningCertOwner(owner) {
		return false
	}
	if owner == "" || owner != p.Org {
		return false
	}
	if p.Admin {
		return true
	}
	return method == "GET" && entity == "users" && name != "" && name == p.User
}

// owned is implemented by a typed input whose authorization target is NOT its
// top-level Owner/Name. The user create/update body nests the record under
// `user`, so its owner is in.User.Owner, not a top-level field; its AuthzTarget
// returns exactly what the handler binds — the handler calls the same method — so
// the value authorized is by construction the value written. Any future input
// that nests its owner implements this too: it is the ONE contract for nesting,
// so the seam never guesses which field the handler uses and never mistakes a
// read-only enrichment sub-struct (e.g. an application's resolved certObj, which
// carries its OWN owner) for the target.
type owned interface {
	AuthzTarget() (owner, name string)
}

// decodedTarget returns the (owner, name) a decoded request addresses — exactly
// the values the handler will bind, read from the SAME decoded struct the handler
// runs on, so there is no second parse to diverge from. An input that nests its
// owner declares it via owned; every other input files its owner at the top level
// (directly, or promoted from an embedded record), read reflectively so no entity
// needs bespoke wiring and an attacker-supplied nested sub-struct is never a
// target.
func decodedTarget(in any) (owner, name string) {
	if o, ok := in.(owned); ok {
		return o.AuthzTarget()
	}
	v := reflect.ValueOf(in)
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return "", ""
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return "", ""
	}
	return stringField(v, "Owner"), stringField(v, "Name")
}

// stringField returns the string value of the named field (traversing embedded
// anonymous fields via FieldByName), or "" when the field is absent or not a
// string. FieldByName does not descend named sub-fields, so it reads the record's
// own owner, never one nested under an unrelated field.
func stringField(v reflect.Value, name string) string {
	f := v.FieldByName(name)
	if f.IsValid() && f.Kind() == reflect.String {
		return f.String()
	}
	return ""
}

// principal resolves the verified bearer into a Principal, failing closed on a
// missing/malformed/expired/wrong-key token (oidc.VerifyToken enforces the
// algorithm allowlist and trusted signing-cert resolution), a subject with no
// org, a store error, or a forbidden/deleted user. Org, Admin, and Super are
// read from the LOADED user record — authoritative — never from the token
// claims: SuperAdmin is a real, live member of the admin org, not a subject that
// merely names one. A subject with no user row (a client_credentials machine
// token, or a since-deleted user) authenticates but carries no admin or
// SuperAdmin authority and no self-service identity — org-scoped only, which on
// the raw CRUD authorizes to nothing until a later phase grants machine
// identities explicit scope. This closes the phantom-admin subject: a token for
// "admin/<nobody>" resolves to no authority, not SuperAdmin.
func principal(c *zip.Ctx, db orm.DB) (*Principal, error) {
	bearer := httpx.Bearer(c)
	if bearer == "" {
		return nil, errNoBearer
	}
	ctx := c.Context()
	claims, err := oidc.VerifyToken(ctx, db, bearer)
	if err != nil {
		return nil, err
	}
	// The subject is "<owner>/<name>": the principal's OWN org and name, set
	// server-side at mint and signed. Never the `owner` claim (the app's org).
	owner, name, _ := strings.Cut(claims.Subject, "/")
	if owner == "" {
		return nil, errNoSubject
	}
	u, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, err // fail closed: cannot establish the principal
	}
	if u != nil {
		if u.IsForbidden || u.IsDeleted {
			return nil, errRevoked
		}
		return &Principal{Org: u.Owner, User: u.Name, Admin: u.IsAdmin, Super: u.Owner == adminOrg}, nil
	}
	return &Principal{Org: owner}, nil
}

// entityOf returns the resource segment of an /v1/iam/<entity>[/verb] path, or
// "" for anything else (e.g. /mcp). Only the users entity needs distinguishing —
// its regular-user self-service rule — so every other segment is treated
// uniformly by the tenant rule.
func entityOf(path string) string {
	const p = "/v1/iam/"
	if !strings.HasPrefix(path, p) {
		return ""
	}
	rest := path[len(p):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		return rest[:i]
	}
	return rest
}
