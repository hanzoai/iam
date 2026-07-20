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
	"crypto/subtle"
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
// bearer or from a confidential client's Basic credential. Org is the tenant
// (the authenticated principal's own org, from the subject); User is its name
// within that org (empty for a machine token); Admin is the org-admin flag;
// Super is the SuperAdmin predicate (Org == adminOrg).
//
// App is the application NAME when the request authenticated as a confidential
// client (client_secret_basic), and "" for every human. An app principal is
// never Admin and never Super — its whole authority is its capability allowlist
// (cap.go), so a leaked client credential can neither read another tenant nor
// touch signing material.
type Principal struct {
	Org   string
	User  string
	App   string
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
	"/v1/iam/login":                            true, // credential login, mints the code
	"/v1/iam/oauth/authorize":                  true, // OAuth2 authorize
	"/v1/iam/oauth/token":                      true, // OAuth2 token
	"/v1/iam/oauth/userinfo":                   true, // self-verifying bearer read
	"/v1/iam/oauth/logout":                     true, // end session
	"/v1/iam/get-app-login":                    true, // pre-login app config (secrets masked)
	"/v1/iam/auth/methods":                     true, // pre-login method list
}

// selfPaths is the CLOSED set of GATED routes that carry their OWN
// authorization — the verb face (HIP-0111 §6) the live consumers call. Their
// read target is an `id=<owner>/<name>` or an org-scoped listing, not the
// ?owner=&name= pair the generic rule reads, so the Guard has nothing to
// authorize here and would refuse every one of them on an empty owner.
//
// The Guard still AUTHENTICATES them (no credential ⇒ 401); it skips ONLY the
// target rule. Each handler then authorizes through the SAME pure policy — Can
// for a single target, Scope for a listing — before it touches the store. One
// policy, two faces. Listing a path here MOVES its check into that handler; it
// never removes it, and each is pinned by a test.
var selfPaths = map[string]bool{
	"/v1/iam/get-organization":  true, // ?id=admin/<slug> → Can(GET, organizations)
	"/v1/iam/get-organizations": true, // owner-scoped listing → Scope
	"/v1/iam/service-accounts":  true, // ?organization=<org> → the service-account read gate
	"/v1/iam/memberships":       true, // ?user=|?org= → Scope
}

// isPublic reports whether path is in the public allowlist. A trailing slash is
// trimmed first so /v1/iam/login/ resolves like /v1/iam/login — the same route
// fiber serves. It can only ever widen matches to the fixed public set, never
// turn a gated path into a public one (no gated path equals a public path plus a
// slash), so the fail-closed default holds.
func isPublic(path string) bool {
	return publicPaths[trimmed(path)]
}

// isSelf reports whether path authorizes itself (selfPaths), normalized the same
// way as isPublic.
func isSelf(path string) bool {
	return selfPaths[trimmed(path)]
}

// trimmed normalizes a request path for allowlist lookup by dropping a trailing
// slash, so /v1/iam/login/ resolves like /v1/iam/login — the same route fiber
// serves.
func trimmed(path string) string {
	if len(path) > 1 {
		return strings.TrimRight(path, "/")
	}
	return path
}

// isRead reports whether a method addresses its target through the query string
// rather than a body: a GET (or HEAD) has no body for the op-invoke seam to
// decode, so its target is authorized in the Guard. Every other method carries a
// body decoded once by the op and is authorized at that seam.
func isRead(method string) bool { return method == "GET" || method == "HEAD" }

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
		if isRead(c.Method()) && !isSelf(c.Path()) &&
			!authorize(p, c.Method(), entityOf(c.Path()), c.Query("owner"), c.Query("name")) {
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

// Can reports whether the ctx principal may act on (entity, owner, name) with
// method. It is the SAME pure policy the Guard applies to the entity face,
// exported for the verb face, whose target rides in `id=<owner>/<name>` rather
// than in ?owner=&name=. One policy, two faces — a verb handler never restates
// the rule, so the faces cannot drift apart. No principal (an unauthenticated
// request that reached a gated handler) is refused.
func Can(ctx context.Context, method, entity, owner, name string) bool {
	p, ok := From(ctx)
	if !ok {
		return false
	}
	return authorize(p, method, entity, owner, name)
}

// authorize is the pure authorization decision: may p act on a resource owned by
// `owner` (named `name`) on the given entity? The order IS the policy:
//
//  1. SuperAdmin may do anything — the only cross-tenant scope.
//
//  2. A resource under a reserved owner (admin/built-in — the owners the token
//     verifier trusts to sign) is SuperAdmin-only. This single rule is the
//     signing-cert poisoning gate, the admin-scoped app/provider registration
//     gate, AND the built-in-org gap at once: a built-in-org principal is not
//     SuperAdmin (that is admin only), so it cannot write a built-in-owned
//     signing cert either. It is also what keeps a user OUT of the reserved
//     admin org: no capability moves a user under owner=="admin", because a
//     user in the admin org IS a SuperAdmin — provision, never promote.
//
//     The ONE exception is the tenant registry. Every organization row is filed
//     under the admin owner (`admin/<slug>`), but an org row is the TENANT'S own
//     record, not platform trust material: a tenant reads its own org, its admin
//     edits its own org's branding, and an org-admin-capable confidential client
//     manages orgs during onboarding. That is exactly v1's rule
//     (controllers/organization.go:113-123, requireAppCapability(CapOrgAdmin)).
//     The exception is keyed on the entity, so certs, applications, providers,
//     and users under a reserved owner stay refused.
//
//  3. A confidential client's authority is its capability allowlist and nothing
//     else. It is checked here, once, for every entity and both faces — never
//     Super, never Admin, and an unmapped entity or unset allowlist denies.
//
//  4. Tenant isolation: a human may act only within its OWN org. An empty or
//     foreign owner is refused — the target org is bound to the principal, never
//     trusted from the request.
//
//  5. Inside its own org, an org admin manages everything; a regular user may
//     only READ its own user record (self-service). The users entity serves
//     reads as GET and writes as POST, so gating the self clause to GET keeps a
//     regular user from writing its own record — a raw entity write would
//     otherwise let it carry isAdmin and self-promote.
func authorize(p *Principal, method, entity, owner, name string) bool {
	if p.Super {
		return true
	}
	if store.IsSigningCertOwner(owner) {
		if entity != "organizations" {
			return false
		}
		if p.App != "" {
			return Allowed(p, CapOrgAdmin)
		}
		// The tenant's OWN org row: anyone in it reads it, its admin writes it.
		return name == p.Org && (isRead(method) || p.Admin)
	}
	if p.App != "" {
		return Allowed(p, capFor(entity))
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
	if p, ok := app(c, db); ok {
		return p, nil
	}
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

// app resolves an `Authorization: Basic <clientId>:<clientSecret>` credential
// into a confidential-client Principal — the transport every live server-side
// consumer authenticates with (RFC 6749 §2.3.1 client_secret_basic; cloud reads
// IAM_MINT_CLIENT_ID/SECRET and sends exactly this). The application NAME is the
// identity, because the capability allowlists key on the name.
//
// It is deliberately NOT an authority: the returned Principal is never Admin and
// never Super, so the ONLY thing it can do is what its name is allowlisted for
// (authorize → Allowed). This is what keeps the v1 "every confidential client is
// a global admin" hole closed as the transport is re-added.
//
// Fail-closed: an unparseable header, an unknown clientId, an application with no
// registered secret, an empty presented secret (a public client must never
// authenticate as an app), or a mismatch all report false — the caller then
// finds no bearer either and answers 401. The comparison is constant-time, so a
// prober cannot recover a secret byte by byte.
func app(c *zip.Ctx, db orm.DB) (*Principal, bool) {
	id, secret, ok := httpx.Basic(c)
	if !ok || id == "" || secret == "" {
		return nil, false
	}
	a, err := store.GetApplicationByClientId(c.Context(), db, id)
	if err != nil || a == nil || a.ClientSecret == "" {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(a.ClientSecret), []byte(secret)) != 1 {
		return nil, false
	}
	return &Principal{App: a.Name, Org: a.Organization}, true
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
