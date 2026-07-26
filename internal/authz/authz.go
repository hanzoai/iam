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
	"crypto/subtle"
	"errors"
	"reflect"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/store"
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
	Org  string
	User string
	// App is the application NAME when the request authenticated as a confidential
	// client (client_secret_basic), and "" for every human. An app principal is
	// never Admin and never Super — its whole authority is its capability allowlist
	// (cap.go), so a leaked client credential can neither read another tenant nor
	// touch signing material.
	App string
	// AppOwner is the OWNING organization of that application row — "admin"/"built-in"
	// for a platform app, the tenant's own org for a customer app. It is NOT App's
	// served Organization. A capability (cap.go Allowed) is granted ONLY when this is
	// a reserved platform signing owner, so a tenant that registers an app whose NAME
	// (or clientId) collides with a platform console inherits none of its authority:
	// the allowlist keys on the name, and the owner-pin binds that name to the
	// platform. Empty for every human.
	AppOwner string
	Admin    bool
	Super    bool
}

type ctxKey struct{}

// From returns the Principal the Guard attached to ctx for a gated request, and
// whether one is present (public routes carry none).
func From(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// WithPrincipal returns ctx carrying p as the request principal — the ONE
// constructor for an authorized context, symmetric with From. The Guard uses it
// to attach the principal it authenticated; a handler-level gate (e.g. the
// application field gate) reads it back through From. It only labels a context —
// a principal's AUTHORITY still derives from the Guard's bearer verification, not
// from holding this key — so nothing outside the Guard should fabricate one.
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, ctxKey{}, p)
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

// CanSetOrg reports whether principal p may point a resource at organization
// `org` — the tenant an application SERVES (the org every credential minted
// through that app lands in), authorized EXACTLY as an owner target through the
// one policy: a SuperAdmin may set any org; anyone else only their OWN org, never
// a reserved platform org (admin/built-in — the SuperAdmin/signing vector) nor
// another tenant (cross-tenant mint). It is the gate the application create/update
// path applies to the Organization FIELD — closing the hole where authorizing only
// the top-level Owner let a tenant admin register an app whose Organization named
// the admin org (SuperAdmin) or a victim tenant. Fails closed on a nil principal.
func CanSetOrg(p *Principal, org string) bool {
	if p == nil {
		return false
	}
	return authorize(p, "POST", "applications", org, "")
}

// Optional resolves the Principal a PUBLIC route's caller happens to carry, or
// nil when the request is anonymous or its bearer does not verify. The Guard
// admits a public path WITHOUT resolving a principal (a browser must reach the
// pre-auth surface before it holds a token), so From() is empty there — a public
// handler that legitimately honors an authenticated caller resolves it here.
//
// It is the same fail-closed resolution every gated route runs (one verifier,
// one user load, one revocation check); only the outcome differs — a bad bearer
// is nil rather than a 401, because the caller's flow continues anonymously.
// A handler must therefore treat a nil Principal as "anonymous", never as an
// error, and must never widen authority on the strength of this alone: it proves
// only WHO the caller is, not that the caller INTENDED this request (the wallet
// link branch pairs it with a same-site check for exactly that reason).
func Optional(c *zip.Ctx, db orm.DB) *Principal {
	p, err := principal(c, db)
	if err != nil {
		return nil
	}
	return p
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
// get-organization-projects (and its workspace tier, get-organization-workspaces)
// is the Casdoor read verb whose target rides in ?organization= (the
// ScopeSwitcher's project/workspace list), not ?owner=/?id=/the path, so the Guard
// cannot pre-authorize it generically; the handler scopes it through authz.Scope
// instead (the read analogue of SCIM's path-targeted authorization).
// get-memberships is the Casdoor alias of /v1/iam/memberships whose target rides in
// ?user=/?org=, so it belongs here for the same reason its REST twin does — the
// membership list handler's own scoped() check is the tenant gate.
var handlerAuthorizedPrefixes = []string{"/v1/iam/scim/", "/v1/iam/get-organization-projects", "/v1/iam/get-organization-workspaces", "/v1/iam/service-accounts", "/v1/iam/memberships", "/v1/iam/get-memberships"}

// handlerAuthorizedExact are SINGLE routes (not subtrees) the handler authorizes
// itself. get-user is here — not a prefix — because "/v1/iam/get-user" IS a prefix
// of "/v1/iam/get-users" (the generic, Guard-authorized list): a prefix entry would
// silently strip the Guard's read gate from get-users and let a request parameter
// narrow rather than deny a cross-tenant list. get-user carries a `?accessKey=`
// variant whose target is a secret key (no owner/name for the Guard to authorize),
// so the get-user handler authorizes BOTH its variants — the owner/name read through
// the SAME authz.Can the Guard would have applied, the key read behind CapKeyResolve.
var handlerAuthorizedExact = map[string]bool{"/v1/iam/get-user": true}

// pathAuthorized reports whether path is handler-authorized: an exact single-route
// match, or under a handler-authorized subtree.
func pathAuthorized(path string) bool {
	if handlerAuthorizedExact[path] {
		return true
	}
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
		c.SetContext(WithPrincipal(c.Context(), p))
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
//  2. A platform-owned resource — one under a RESERVED system org (store.IsReservedOrg:
//     admin/built-in, the signing owners, PLUS "app", the service-principal org) — is
//     writable only by a SuperAdmin. This single rule is the signing-cert poisoning
//     gate, the admin-scoped app/provider registration gate, the built-in-org gap, AND
//     the service-org ("app") consistency the self-service surfaces already enforce, all
//     at once: a built-in-org principal is not SuperAdmin (that is admin only), so it
//     cannot write a built-in-owned signing cert; and no capability app nor "app"-org
//     admin can land a user under owner="app" (a platform identity) — the raw CRUD now
//     consults the SAME predicate signup/onboarding do, so the reserved set never
//     drifts between surfaces.
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
	if store.IsReservedOrg(owner) {
		// The ONE exception to the reserved-owner gate is the tenant registry: every
		// organization row is filed under the admin owner, but an org row is the
		// TENANT'S own record, not platform trust material — a tenant reads its own
		// org, its admin edits it, and an org-admin-capable confidential client
		// manages orgs during onboarding (v1 requireAppCapability(CapOrgAdmin)).
		// Certs, applications, providers, and users under a reserved owner
		// (admin/built-in/app) stay SuperAdmin-only.
		if entity != "organizations" {
			return false
		}
		if p.App != "" {
			return Allowed(p, CapOrgAdmin)
		}
		return name == p.Org && (isRead(method) || p.Admin)
	}
	// A confidential client's authority is its capability allowlist and nothing
	// else — never Super, never Admin; an unmapped entity or unset allowlist denies.
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
	// The subject is the principal's OWN stable identity, set server-side at mint and
	// signed — a UUID for a v2 token, or "<owner>/<name>" pre-cutover. Resolve it to
	// the live user through the ONE subject decoder (Id-or-name), and read Org/Admin/
	// Super from the LOADED record — never from the `owner` claim (the app's org), so
	// a token whose owner claim names admin but whose subject is a tenant user gets
	// the tenant's authority, not the claim's (the org-confusion defense).
	u, err := store.GetUserBySubject(ctx, db, claims.Subject)
	if err != nil {
		return nil, err // fail closed: cannot establish the principal
	}
	if u != nil {
		if u.IsForbidden || u.IsDeleted {
			return nil, errRevoked
		}
		return &Principal{Org: u.Owner, User: u.Name, Admin: u.IsAdmin, Super: u.Owner == adminOrg}, nil
	}
	// No user row. A machine token's subject is "<appOwner>/<appName>" — org-scoped
	// to the app's owner half, carrying no admin/super authority. Anything else — an
	// opaque UUID subject with no live user row (a since-deleted user, or a forgery
	// the trusted-key verify already blocks) — establishes NO principal, fail closed.
	owner, _, hasSlash := strings.Cut(claims.Subject, "/")
	if !hasSlash || owner == "" {
		return nil, errNoSubject
	}
	return &Principal{Org: owner}, nil
}

// app resolves an `Authorization: Basic <clientId>:<clientSecret>` credential into
// a confidential-client Principal — the transport every live server-side consumer
// authenticates with (RFC 6749 §2.3.1 client_secret_basic; cloud reads
// IAM_MINT_CLIENT_ID/SECRET and sends exactly this). The application NAME is the
// identity, because the capability allowlists key on the name.
//
// It is deliberately NOT an authority: the returned Principal is never Admin and
// never Super, so the ONLY thing it can do is what its name is allowlisted for
// (authorize → Allowed). This is what keeps the v1 "every confidential client is a
// global admin" hole closed as the transport is re-added.
//
// Fail-closed: an unparseable header, an unknown clientId, an application with no
// registered secret, an empty presented secret (a public client must never
// authenticate as an app), or a mismatch all report false — the caller then finds
// no bearer either and answers 401. The comparison is constant-time.
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
	// AppOwner is the app row's OWNING org (a.Owner: "admin"/"built-in" for a platform
	// app), NOT a.Organization (the tenant it SERVES). cap.go pins every capability to
	// this being a reserved signing owner, so a tenant-owned app named/clientId'd like
	// a console holds nothing. Org carries the served tenant, as before.
	return &Principal{App: a.Name, AppOwner: a.Owner, Org: a.Organization}, true
}

// entityFor resolves a leading path segment that does NOT spell its own entity to
// the entity it addresses. Exactly two families need it:
//
//   - the Casdoor VERB surface (internal/compat) — add-organization, get-users, … —
//     where the segment names an ACTION, not a resource. Every one is an alias of a
//     REST route over the same store and the same handlers, so it must reach
//     authorize() with the same entity its twin does. Left unresolved it matched no
//     entity and no capability, which denied the entire compat surface to every
//     confidential client while the identical REST call passed.
//   - /v1/iam/application, the one REST route spelling its entity singular while the
//     policy layer spells it plural (CanSetOrg authorizes "applications"). One
//     entity, one name: two spellings would let a future capability attach to one
//     route of an entity and silently not the other.
//
// It is a TABLE, not a rule, because the failure directions are not symmetric.
// authorize() reads the entity in exactly three places — the reserved-owner gate
// (entity == "organizations"), the confidential-client gate (capFor, which maps
// ONLY organizations and users), and the regular-user self-read (entity ==
// "users") — so the entity space has exactly three classes: organizations, users,
// and everything else, every member of which denies at all three. A missing entry
// therefore falls through to the segment itself and DENIES; only a wrong entry can
// GRANT. A rule fails in the granting direction: "strip the leading verb" resolves
// get-organization-projects and get-organization-workspaces — which name their
// parent org but address the CHILD collection — to "organizations", handing every
// org-admin-capable client (CapOrgAdmin) a grant on a collection it holds no
// capability for. They resolve to the child entity their REST twins resolve to.
//
// Absent by design, and authority-neutral by the rule above: the raw handlers that
// authorize their own target through authz.Can (get-memberships, add-membership,
// delete-membership, delete-mfa, set-preferred-mfa) and the public front door
// registered before the Guard (get-account, get-app-login, update-preferences, …).
// Neither seam ever asks entityOf about those, so listing them would make this a
// second inventory of the route surface, free to drift from the first.
var entityFor = map[string]string{
	// organizations — the tenant registry, and the ONE entity the reserved-owner gate
	// lets a non-Super past: every org row is filed under the admin owner, so a tenant
	// reads its own and an org-admin-capable client creates customer orgs during
	// onboarding. These five verbs are the only ones that may resolve here. Everything
	// else under a reserved owner — certs, applications, providers, users — stays
	// SuperAdmin-only, and stays so precisely BECAUSE its verb does not resolve here.
	"get-organizations":   "organizations", // GET  /v1/iam/organizations
	"get-organization":    "organizations", // GET  /v1/iam/organizations/get
	"add-organization":    "organizations", // POST /v1/iam/organizations
	"update-organization": "organizations", // POST /v1/iam/organizations/update
	"delete-organization": "organizations", // POST /v1/iam/organizations/delete

	// users — the other authority-carrying entity (capFor → CapUserAdmin, plus the
	// regular-user self-read clause). get-global-users is Casdoor's cross-tenant
	// spelling, but this deployment serves it from the SAME owner-scoped lister as
	// get-users — one handler, one authz.Scope, no cross-tenant widening — so it is a
	// users read exactly like its twin, and resolving it anywhere else would only
	// desynchronise two spellings of one read.
	"get-users":        "users", // GET  /v1/iam/users
	"get-global-users": "users", // GET  /v1/iam/users
	"get-user":         "users", // GET  /v1/iam/users/get
	"add-user":         "users", // POST /v1/iam/users
	"update-user":      "users", // POST /v1/iam/users/update
	"delete-user":      "users", // POST /v1/iam/users/delete

	// Below here every value is authority-neutral: none is "organizations" or "users",
	// so none can grant. They are resolved anyway so that a verb and its REST twin are
	// governed by one entity rather than two, which is what keeps a future capability
	// from attaching to half an entity.
	"application":        "applications", // the singular REST route; plural is the policy's name
	"get-applications":   "applications", // GET    /v1/iam/applications
	"get-application":    "applications", // GET    /v1/iam/application
	"add-application":    "applications", // POST   /v1/iam/application
	"update-application": "applications", // PUT    /v1/iam/application
	"delete-application": "applications", // DELETE /v1/iam/application

	"get-providers":   "providers", // GET  /v1/iam/providers
	"get-provider":    "providers", // POST /v1/iam/providers/get
	"add-provider":    "providers", // POST /v1/iam/providers
	"update-provider": "providers", // POST /v1/iam/providers/update
	"delete-provider": "providers", // POST /v1/iam/providers/delete

	"get-roles":   "roles", // GET  /v1/iam/roles
	"get-role":    "roles", // POST /v1/iam/roles/get
	"add-role":    "roles", // POST /v1/iam/roles
	"update-role": "roles", // POST /v1/iam/roles/update
	"delete-role": "roles", // POST /v1/iam/roles/delete

	// The compound reads: named for the parent org, addressed at the child collection.
	// Their targets ride in ?organization=, so both are handler-authorized (see
	// handlerAuthorizedPrefixes) and the Guard does not consult this today — they are
	// resolved truthfully so that removing that entry later denies rather than grants.
	"get-organization-projects":   "projects",   // GET  /v1/iam/projects
	"add-project":                 "projects",   // POST /v1/iam/projects
	"delete-project":              "projects",   // POST /v1/iam/projects/delete
	"get-organization-workspaces": "workspaces", // GET  /v1/iam/workspaces
	"add-workspace":               "workspaces", // POST /v1/iam/workspaces
	"delete-workspace":            "workspaces", // POST /v1/iam/workspaces/delete

	"get-certs":       "certs",       // GET /v1/iam/certs
	"get-cert":        "certs",       // POST /v1/iam/certs/get
	"get-permissions": "permissions", // GET /v1/iam/permissions
	"get-permission":  "permissions", // GET /v1/iam/permissions/get
	"get-invitations": "invitations", // GET /v1/iam/invitations
	"get-records":     "audit-logs",  // GET /v1/iam/audit-logs — "records" is Casdoor's name for them
}

// entityOf returns the ENTITY an /v1/iam/… path addresses — the resource the policy
// is about — or "" for anything else (e.g. /mcp). It is the ONE resolver: the Guard
// authorizes a read through it and the op-invoke seam authorizes a write through it,
// so a REST route and its Casdoor verb alias arrive at authorize() carrying the same
// entity and are therefore governed by the same rule. Nothing else normalises a path;
// a second resolver would be a second policy.
//
// The leading segment IS the entity across the REST surface (/v1/iam/users/update →
// users), so it is the answer unless entityFor says otherwise. An unlisted segment
// returning itself is not a gap: only "organizations" and "users" carry authority in
// authorize(), so any other value — a verb spelling, an unknown route, a mixed-case
// variant — denies exactly as "" does. This resolver can widen authorization only by
// naming one of those two for a path that does not address it.
func entityOf(path string) string {
	const p = "/v1/iam/"
	if !strings.HasPrefix(path, p) {
		return ""
	}
	seg := path[len(p):]
	if i := strings.IndexByte(seg, '/'); i >= 0 {
		seg = seg[:i]
	}
	if e, ok := entityFor[seg]; ok {
		return e
	}
	return seg
}
