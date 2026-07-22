// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package authz is the IAM v2 authorization seam in front of the Phase-1 entity
// CRUD, which is otherwise unauthenticated — the door an attacker would walk
// through to overwrite an admin-owned signing cert and forge tokens. It is two
// orthogonal decisions, never braided:
//
//   - AUTHENTICATION — the Guard middleware, mounted ONCE via app.Use, AFTER the
//     public group and BEFORE the authed routes. Public (pre-authentication)
//     routes are registered first, so a matched one terminates fiber's middleware
//     walk and the Guard never runs on it — public vs gated is structural (which
//     group a route is on), not an allow-list. Every request the Guard wraps must
//     carry a verified bearer; the resolved Principal is attached to the request
//     context for the authorization decision and audit. Fails closed (401).
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

// Can reports whether the ctx principal may perform `method` on the entity's
// (owner, name) — the SAME policy the op-invoke seam (Authorize) applies, exposed
// for a RAW handler that does not pass through app.Authorize (e.g. SCIM, whose
// writes call the CRUD directly). Owner-pinning via Scope alone is NOT sufficient
// for a write: it enforces tenant isolation but not the admin/self clause, so a
// raw handler MUST call this. Fails closed when no principal is present.
func Can(ctx context.Context, method, entity, owner, name string) bool {
	p, ok := From(ctx)
	if !ok {
		return false
	}
	return authorize(p, method, entity, owner, name)
}

// IsSuper reports whether the ctx principal is a SuperAdmin — used by a raw
// handler to gate a privileged field (e.g. provision-don't-promote: only a super
// may set isAdmin). Fails closed when no principal is present.
func IsSuper(ctx context.Context) bool {
	p, ok := From(ctx)
	return ok && p.Super
}

// Fail-closed reasons. The Guard collapses all of them to one opaque 401 so a
// prober cannot tell a bad signature from an expired token from a revoked user.
var (
	errNoBearer  = errors.New("authz: no bearer")
	errNoSubject = errors.New("authz: token subject carries no org")
	errRevoked   = errors.New("authz: principal is forbidden or deleted")
)

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

// handlerAuthorizedPrefixes are path subtrees whose target rides in the PATH, not
// the query — the Guard authenticates them (a bearer is still required) but does
// NOT pre-authorize the read; the handler authorizes on the path id via
// authz.Scope. SCIM (RFC 7644, /v1/iam/scim/v2/Users/{id}) is path-targeted, so it
// belongs here. This is the read analogue of a write deferring to the op-invoke
// seam — the target is authorized where it is bound, not guessed from the query.
// get-organization-projects is the one Casdoor read verb whose target rides in
// ?organization= (the ScopeSwitcher's project list), not ?owner=/?id=/the path,
// so the Guard cannot pre-authorize it generically; the handler scopes it through
// authz.Scope instead (the read analogue of SCIM's path-targeted authorization).
var handlerAuthorizedPrefixes = []string{"/v1/iam/scim/", "/v1/iam/get-organization-projects"}

// pathAuthorized reports whether path is under a handler-authorized subtree.
func pathAuthorized(path string) bool {
	for _, p := range handlerAuthorizedPrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	return false
}

// Guard is the AUTHENTICATION middleware. Mount it via app.Use AFTER the public
// group and BEFORE the authed routes: the public (pre-authentication) routes are
// registered first, so a matched public route terminates fiber's middleware walk
// and the Guard never runs on it — public vs gated is decided structurally, by
// which group a route is registered on, not by an allow-list. Every route the
// Guard does wrap — the typed CRUD handlers and the framework's /mcp and /openapi
// surfaces alike — requires a valid bearer (401 otherwise) whose Principal is
// attached to the request context for the authorization hook downstream. A read's
// authorization target rides in the query string, so reads are authorized here; a
// write's rides in the body, decoded once by the op and authorized at the op-invoke
// seam (Authorize) on that exact decoded value — this middleware never re-parses a
// write body, which is what let the old target extraction diverge from execution.
func Guard(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		p, err := principal(c, db)
		if err != nil {
			return zip.ErrUnauthorized("authentication required")
		}
		// A path-targeted resource (SCIM: /Users/{id}) carries its target in the
		// PATH, not the query — so, like a write whose target rides in the body, the
		// Guard authenticates (bearer required, principal attached) and the handler
		// authorizes via authz.Scope on the path id. The Guard never authorizes an
		// empty query target for these (which would fail-closed deny every non-super
		// before the handler could scope). Every other read is authorized here.
		if !pathAuthorized(c.Path()) {
			rOwner, rName := ReadTarget(c)
			if isRead(c.Method()) && !authorize(p, c.Method(), entityOf(c.Path()), rOwner, rName) {
				return zip.ErrForbidden("forbidden")
			}
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
//
// Every typed op is authed by construction — the public surface is raw handlers
// in the pre-Guard group, none of which is a typed op — so this hook needs no
// public bypass: whenever it runs, the Guard has already run and attached a
// principal (over REST, before the op; over MCP, on the gated /mcp route).
func Authorize(ctx context.Context, op zip.Op, in any) error {
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
