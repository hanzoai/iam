// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package authz is the IAM v2 authorization seam in front of the Phase-1 entity
// CRUD, which is otherwise unauthenticated — the entry point an attacker would
// use to overwrite an admin-owned signing cert and forge tokens. It is two
// orthogonal decisions, never braided:
//
//   - AUTHENTICATION — the Guard middleware, registered ONCE via app.Use, AFTER the
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
//   - SuperAdmin — the principal belongs to the reserved "admin" org.
//     The ONLY cross-tenant scope. Required for every write to a platform-owned
//     (admin/built-in) resource: the signing-cert poisoning gate, admin-scoped
//     application/provider registration, every reserved surface.
//   - Org admin — IsAdmin, scoped to its OWN organization. Manages every
//     resource its org owns; never another org's, never a platform-owned one.
//   - Regular user — self-service only: reading its own user record.
//
// One predicate governs SuperAdmin everywhere: the principal BELONGS to the
// reserved "admin" org — its home org is "admin", or it holds a membership there.
// Membership is how an operator is actually made (an existing SuperAdmin grants
// it; memberships.mayGrant refuses a reserved target to anyone else), and it is
// the same question the published authz.Claims.Sudo asks of the signed
// `orgs` set, so one token reads identically here and at every consumer. Asking
// only the home org denied every operator anchored in a brand org — which is
// every operator who also does ordinary work.
//
// The home org comes from the token SUBJECT — the authenticated
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
	"net/http"
	"os"
	"reflect"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Env is the capability allowlist as THIS process sees it. The decision takes the
// lookup as an INPUT so it stays free of config; IAM is the process that HAS an
// environment, so it binds one here, once. Every capability question in the
// service therefore reads the same allowlists, and a test supplies its own by
// assigning a map lookup.
var Env policy.Env = os.Getenv

// Deny renders a principal.Scope refusal in the envelope the caller's surface
// speaks — the SAME shaping the Guard's own refusal uses, so one refusal looks
// the same whether it was raised before the handler or inside it. A handler that
// answered it with httpx.Err would send HTTP 200 carrying {"status":"error"},
// which is how a refusal gets logged as a success.
func Deny(c *zip.Ctx, err error) error { return refuse(c, http.StatusForbidden, err.Error()) }

// Can reports whether the ctx principal may perform `method` on the entity's
// (owner, name) — the SAME policy the op-invoke seam (Authorize) applies, exposed
// for a RAW handler that does not pass through app.Authorize (e.g. SCIM, whose
// writes call the CRUD directly). Owner-pinning via Scope alone is NOT sufficient
// for a write: it enforces tenant isolation but not the admin/self clause, so a
// raw handler MUST call this. Fails closed when no principal is present.
func Can(ctx context.Context, method, entity, owner, name string) bool {
	p, ok := principal.From(ctx)
	if !ok {
		return false
	}
	return p.CanEntity(policy.VerbOf(method), policy.Entity{Kind: entity, Owner: owner, Name: name}, Env)
}

// IsSuper reports whether the ctx principal is a SuperAdmin — used by a raw
// handler to gate a privileged field (e.g. provision-don't-promote: only a super
// may set isAdmin). Fails closed when no principal is present.
func IsSuper(ctx context.Context) bool {
	p, ok := principal.From(ctx)
	return ok && p.Sudo
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
func CanSetOrg(p *principal.Principal, org string) bool {
	if p == nil {
		return false
	}
	return p.CanEntity(policy.Write, policy.Entity{Kind: "applications", Owner: org}, Env)
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
func Optional(c *zip.Ctx, db orm.DB) *principal.Principal {
	p, err := resolve(c, db)
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

// readTarget extracts the (owner, name) a GET addresses. It reads the path
// first, then `?owner=&name=`, then splits `?id=<owner>/<name>`. Explicit
// owner/name win; the id split is a fallback only when owner is absent, so this
// can only make an id-based read's authorization MORE precise than the empty
// target it would otherwise resolve to (which fail-closed denies every
// non-super). It never widens: the tenant rule still pins owner to the
// principal's org, and the handler independently re-scopes the query owner
// through Scope, so a request that spells one owner in `?owner` and another in
// `?id` cannot read across tenants — the authorized owner and the queried owner
// are both pinned.
func readTarget(c *zip.Ctx) (owner, name string) {
	// THE PATH FIRST, because the path is the addressing authority. An item lives
	// at /v1/iam/<entity>/{owner}/{name}, so that is where its identity is; the
	// Guard has to read the target the same way the handler binds it, or it
	// authorizes one row while the handler writes another.
	//
	// This is the half a rename forgets. When the address moved from a query
	// (?owner=&name=) into the path, everything downstream kept working and the
	// Guard alone went blind: it read two empty strings, built an entity with no
	// owner, and fail-closed refused a caller reading its own record.
	if o, n := c.Param("owner"), c.Param("name"); o != "" {
		return o, n
	}
	owner, name = c.Query("owner"), c.Query("name")
	if owner == "" {
		if id := c.Query("id"); id != "" {
			if o, n, ok := strings.Cut(id, "/"); ok && o != "" {
				return o, n
			}
			// A BARE id carries the name alone — `?id=cert-hanzo`, which is how a
			// relying party asks for the cert its application row names. Previously
			// this resolved to NO target at all (owner "" AND name ""), so the
			// authorizer was handed nothing to reason about and fail-closed denied
			// every caller including the one reading its own. Resolving the name half
			// can only make the decision MORE precise: an empty owner still fails the
			// tenant rule (owner != p.Org) and IsReservedOrg(""), so no clause is
			// widened by knowing the name — only the self-read clause, which pins that
			// name to the principal's own cert, can act on it.
			if !strings.Contains(id, "/") {
				return "", id
			}
		}
	}
	return owner, name
}

// handlerAuthorizedPrefixes are path subtrees whose target rides in the PATH, not
// the query — the Guard authenticates them (a bearer is still required) but does
// NOT pre-authorize the read; the handler authorizes on the path id via
// principal.Scope. SCIM (RFC 7644, /v1/iam/scim/v2/Users/{id}) is path-targeted, so it
// belongs here. This is the read analogue of a write deferring to the op-invoke
// seam — the target is authorized where it is bound, not guessed from the query.
// memberships is here because its target rides in ?user=/?org= rather than
// ?owner=/?id=/the path, so the Guard cannot pre-authorize it generically — the
// list handler's own scoped() check is the tenant gate.
var handlerAuthorizedPrefixes = []string{"/v1/iam/scim/", "/v1/iam/service-accounts", "/v1/iam/memberships"}

// handlerAuthorizedExact are SINGLE routes (not subtrees) the handler authorizes
// itself.
//
// The two key endpoints are here because their target is an opaque key riding in
// ?accessKey=, with no owner/name for the Guard to authorize. Each authorizes
// itself behind its own capability: keys/principal behind CapKeyResolve, and
// keys/org behind CapPublishableResolve, which returns ONLY the org and never a
// principal. They are exact rather than a prefix so neither can reach
// /v1/iam/keys, the Guard-authorized key collection beside them.
//
// The organization collection is here because it NAMES no target: it asks which
// organizations the CALLER may act in, so the answer is derived from the
// principal and there is nothing in the query for the Guard to authorize. An
// empty target fails the tenant rule, which would deny every non-SuperAdmin the
// list of their own organizations. It is exact rather than a prefix so it reaches
// the collection alone and never an item under it, which is addressed by
// (owner, name) and authorized here like every other item read.
//
// The project and workspace COLLECTIONS are here because BELONGING opens them
// (ScopeRead), which is a wider clause than the tenant rule the Guard applies —
// a person's account lives in one org while the orgs they work in are a set, and
// a switcher that lists them must be able to read them. Each list handler asks
// ScopeRead itself, which honours an org the caller belongs to and refuses a
// stranger. Exact, never a prefix: the ITEM beneath (/v1/iam/projects/{owner}/
// {name}) authorizes nowhere but the Guard, so a prefix would take its gate away.
var handlerAuthorizedExact = map[string]bool{
	"/v1/iam/keys/org":             true,
	"/v1/iam/keys/principal":       true,
	"/v1/iam/organizations":        true,
	"/v1/iam/webauthn-credentials": true,
	"/v1/iam/projects":             true,
	"/v1/iam/workspaces":           true,
}

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

// refuse writes the Guard's rejection in the envelope the CALLER can actually
// parse, so one surface answers in one shape.
//
// The verb-shaped addresses (/v1/iam/get-account, delete-membership, …) are a
// contract: every client of them branches on a STRING `status` of "ok"/"error" and
// reads `msg`. The handlers honour that — get-account answers
// {"status":"error","msg":"please sign in first"} — but the Guard short-circuits
// BEFORE any handler runs, and zip's own error shape is {"status":401,
// "error":"…"}: `status` an int where the client expects a string, and the text
// under `error` where the client reads `msg`. So the same endpoint spoke two
// languages depending on whether it got far enough to answer for itself, and a
// client written against the documented one silently saw neither an ok nor a
// recognizable error. The fix belongs here, at the source, not in every client
// learning to tolerate both.
//
// Only the verb surface is reshaped. The resource routes keep zip's
// numeric-status error, which is THEIR contract — this is one envelope per
// surface, not one envelope everywhere. The HTTP status code is unchanged in both
// cases (401/403), so anything reading the code rather than the body is unaffected.
func refuse(c *zip.Ctx, status int, msg string) error {
	if legacyVerb(c.Path()) {
		return c.JSON(status, httpx.Response{Status: "error", Msg: msg})
	}
	if status == 401 {
		return zip.ErrUnauthorized(msg)
	}
	return zip.ErrForbidden(msg)
}

// verbs are the prefixes of the addresses that still carry the verb in the path
// (get-account, delete-membership) and answer in the {status,msg} envelope. The
// resource surface is noun-shaped (/v1/iam/users, /v1/iam/organizations), so the
// prefix is what distinguishes the two contracts without a second list to keep
// in sync.
var verbs = []string{"get-", "add-", "update-", "delete-"}

// legacyVerb reports whether path carries the verb in its first segment.
func legacyVerb(path string) bool {
	const p = "/v1/iam/"
	if !strings.HasPrefix(path, p) {
		return false
	}
	rest := path[len(p):]
	for _, v := range verbs {
		if strings.HasPrefix(rest, v) {
			return true
		}
	}
	return false
}

// Guard is the AUTHENTICATION middleware. Mount it with Use on the GROUP that
// holds the routes it gates — routes.Route registers IAM's authed surface on
// such a group — never on the app itself. zip places middleware by depth: on the
// app it becomes router middleware, a barrier in front of every request the
// binary will ever serve, so IAM embedded beside other subsystems authenticated
// THEIR routes against IAM's store and 401'd every valid request. Inside a
// group it is composed into that group's own route chains and reaches nothing
// else.
//
// Public vs gated stays structural — a public route is one registered on the
// pre-authentication group instead of on the guarded one, never an entry in an
// allow-list — and scoping now runs in the other direction too: a sibling
// subsystem sharing the app is not IAM's to authenticate.
//
// Every route it wraps requires a valid bearer (401 otherwise) whose Principal
// is attached to the request context for the authorization hook downstream. A
// read's authorization target rides in the query string, so reads are authorized
// here; a write's rides in the body, decoded once by the op and authorized at
// the op-invoke seam (Authorize) on that exact decoded value — this middleware
// never re-parses a write body, which is what let the old target extraction
// diverge from execution.
func Guard(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		// A CORS preflight carries no credentials BY DEFINITION — the browser
		// strips them — so authenticating one is a category error: it can only
		// ever fail. It also fails usefully for nobody, because a 401 preflight
		// is indistinguishable to the page from "this origin is not allowed",
		// which is how a legitimately-registered SPA gets told its own IdP is
		// unreachable. Whether the path is actually open to a browser is CORS's
		// question, already answered upstream (internal/cors): if it opened the
		// path it terminated the walk with 204 and we never run; if it did not,
		// falling through emits no allow-origin header and the browser blocks
		// the real request anyway. Either way this is not a request to authorize.
		if c.Method() == http.MethodOptions {
			return c.Continue()
		}
		p, err := resolve(c, db)
		if err != nil {
			return refuse(c, 401, "authentication required")
		}
		// A path-targeted resource (SCIM: /Users/{id}) carries its target in the
		// PATH, not the query — so, like a write whose target rides in the body, the
		// Guard authenticates (bearer required, principal attached) and the handler
		// authorizes via principal.Scope on the path id. The Guard never authorizes an
		// empty query target for these (which would fail-closed deny every non-super
		// before the handler could scope). Every other read is authorized here.
		if v := policy.VerbOf(c.Method()); v == policy.Read && !pathAuthorized(c.Path()) {
			owner, name := readTarget(c)
			if !p.CanEntity(v, policy.Entity{Kind: entityOf(c.Path()), Owner: owner, Name: name}, Env) {
				return refuse(c, 403, "forbidden")
			}
		}
		c.SetContext(principal.Bind(c.Context(), p))
		return c.Continue()
	}
}

// mcpPath is where zip mounts the MCP server. zip exports SpecPath and DocsPath
// but keeps this one unexported (zip/mcp.go defaultMCPPath), and IAM never moves
// it — MCPConfig.Path is left at its default wherever IAM builds an app.
const mcpPath = "/mcp"

// Control gates the framework's OWN projections of the typed-op registry: the MCP
// server, the OpenAPI document, the docs UI, the GraphQL endpoint, the plugin
// declaration, and the by-name op-call plane. It is the SECOND mounting of the one
// Guard, and it exists because those addresses are not routes anybody registered.
//
// zip installs them at Build, directly onto the served app's router, with no
// middleware and after every entry in the program (zip/build.go materialise:
// "control routes are not entries at all"). A scoped seam therefore cannot reach
// them — a group's middleware is composed into that group's own route chains,
// and these are in no group — so the only seam that can is a depth-0 one.
//
// That is the whole reason authentication is mounted twice. Gating them matters
// because each dispatches into the same typed ops the REST surface exposes, reached
// by a different transport: MCP tools/call and the op-call plane invoke an op
// directly, and GraphQL resolves through the registry. Every door must attach a
// principal, or the op-invoke hook decides on nobody — the empty-target read it
// admits on the REST-shaped assumption that the Guard already ran then runs
// unauthenticated. Whichever door is left open lists users.
//
// Narrow by construction, and that is what keeps it from being the bug it
// replaces: it is a depth-0 handler, consulted on every request, but it ACTS only
// on the addresses the framework itself owns and hands every other path straight
// on. A sibling subsystem's route is not one of them. The op-call plane addresses
// one op per path (CallPath + the op name), so it is matched by PREFIX; every other
// door is a fixed address.
func Control(db orm.DB) zip.Handler {
	guard := Guard(db) // one authentication decision, mounted twice, never copied
	return func(c *zip.Ctx) error {
		switch p := c.Path(); {
		case p == mcpPath, p == zip.SpecPath, p == zip.DocsPath,
			p == zip.GraphPath, p == zip.PluginPath,
			strings.HasPrefix(p, zip.CallPath):
			return guard(c)
		}
		return c.Continue()
	}
}

// Authorize is the AUTHORIZATION hook. It is installed with Authorize on the
// GROUP the typed ops register on — never on the app, which on a shared binary
// would make IAM's rules the HOST's and refuse a sibling subsystem's ops 403 —
// and the framework runs it at every typed op's invoke seam: after the request
// is decoded into its typed In and validated, before the handler runs, for REST
// and MCP alike. It authorizes the DECODED target: the exact (owner, name) the
// handler will bind, read from the same struct the handler runs on, so the value
// authorized cannot diverge from the value written.
//
// A REST read carries its target in the query string, not the body, so its
// decoded In is empty and the Guard already authorized it there — such a call is
// admitted here (owner == ""). Every write, and any read invoked over MCP (whose
// arguments DO decode a target into In), is authorized against authorize().
//
// Every typed op is authed by construction — the public surface is raw handlers
// on the unguarded group, none of which is a typed op — so this hook needs no
// public bypass: whenever it runs, the Guard has already run and attached a
// principal (over REST, on the guarded group the op registered on; over MCP, the
// graph and the call plane, on the door authz.Control gates). That second clause
// is why Control gates every door and this hook requires a principal FIRST — even
// for the handler-authorized reads that skip the target check. The owner == ""
// read admitted below trusts the Guard to have authorized the query-string target;
// over the other transports the arguments decode into In rather than the query, so
// requiring the principal here is what keeps a door left open from reaching an
// admission with nobody attached.
func Authorize(ctx context.Context, op zip.Op, in any) error {
	owner, name := decodedTarget(in)
	v := policy.VerbOf(op.Method)
	// A PRINCIPAL is required before any admission — including the handler-authorized
	// early return below. That clause skips the TARGET check, not the caller: the
	// handler authorizes WHICH row, but only for a caller there is one to authorize
	// FOR. Reaching it with no principal means a door let an unauthenticated request
	// through, and a handler that then forgets to self-check (a discovery read that
	// discards ctx) runs for nobody. Fail closed first, decide the target second.
	p, present := principal.From(ctx)
	if !present {
		return zip.ErrForbidden("forbidden") // gated op with no principal: fail closed
	}
	// A READ is authorized once, and pathAuthorized says where. Off the list, the
	// Guard did it on the way in and an input naming no owner has nothing left to
	// check. ON the list, the HANDLER does it — and it has to, because those are
	// the reads whose rule is wider than the tenant rule: belonging opens a
	// project or workspace list (ScopeRead), which this seam would refuse.
	//
	// The same predicate the Guard consults, so the two cannot answer differently
	// about which reads they are each responsible for.
	if v == policy.Read && pathAuthorized(op.Path) {
		return nil
	}
	if !p.CanEntity(v, policy.Entity{Kind: entityOf(op.Path), Owner: owner, Name: name}, Env) {
		return zip.ErrForbidden("forbidden")
	}
	return nil
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
// needs bespoke binding and an attacker-supplied nested sub-struct is never a
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

// resolve turns the verified bearer into a Principal, failing closed on a
// missing/malformed/expired/wrong-key token (oidc.VerifyToken enforces the
// algorithm allowlist and trusted signing-cert resolution), a subject with no
// org, a store error, or a forbidden/deleted user. Org, Admin, and Sudo are
// read from the LOADED user record — authoritative — never from the token
// claims: SuperAdmin is a real, live member of the admin org, not a subject that
// merely names one. A subject with no user row (a client_credentials machine
// token, or a since-deleted user) authenticates but carries no admin or
// SuperAdmin authority and no self-service identity — org-scoped only, which on
// the raw CRUD authorizes to nothing until a later phase grants machine
// identities explicit scope. This closes the phantom-admin subject: a token for
// "admin/<nobody>" resolves to no authority, not SuperAdmin.
func resolve(c *zip.Ctx, db orm.DB) (*principal.Principal, error) {
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
		// Sudo is MEMBERSHIP of the reserved org, never the home org. Home is where an
		// identity is ANCHORED — its billing, its default scope. Platform authority is
		// a different question, and its answer is that an existing SuperAdmin put this
		// identity IN the reserved org: a deliberate, signed, revocable grant that only
		// a SuperAdmin can make (memberships.mayGrant refuses a reserved target to
		// anyone else). Most operators are anchored in a brand org because they also do
		// ordinary work there, so the home org alone cannot answer it. memberOf answers
		// home-or-membership in one place, off the set this principal already carries,
		// which is what policy.Claims.Sudo asks of the signed set — so one token reads
		// the same here and at every consumer.
		p := &principal.Principal{
			Org: u.Owner, User: u.Name, Admin: u.IsAdmin,
			Orgs: membershipRoles(ctx, db, u.Owner+"/"+u.Name),
		}
		p.Sudo = principal.MemberOf(p, policy.AdminOrg)
		return p, nil
	}
	// No user row. A machine token's subject is "<appOwner>/<appName>", which names
	// an APPLICATION — so it resolves to the SAME confidential-client Principal the
	// Basic path builds, from the same row. A client is one principal however it
	// presents its credential: client_secret_basic on the request, or the bearer it
	// minted with client_credentials from that identical secret. It was not, and the
	// asymmetry was silent and total — a bearer took the branch below, arriving with
	// App empty (so every capability clause was skipped: an allowlisted client could
	// not exercise the one capability it is allowlisted FOR) and Org set to the app
	// row's OWNER half rather than the tenant it SERVES (so even the tenant rule
	// refused it). Both halves of its authority were wrong at once, which is why the
	// console's org reads and membership grants answered 403 while the same client,
	// on the same secret, was authorized over Basic.
	//
	// This grants nothing new: the Principal is built by the same helper, from the
	// same row, and is still never Admin and never Super — its whole authority
	// remains its capability allowlist, pinned to a reserved signing owner.
	owner, name, hasSlash := strings.Cut(claims.Subject, "/")
	if !hasSlash || owner == "" {
		return nil, errNoSubject
	}
	if name != "" {
		if a, err := store.GetApplicationByName(ctx, db, owner, name); err == nil && a != nil {
			return appPrincipal(a), nil
		}
	}
	// A subject that names neither a live user nor a live application — an opaque
	// UUID with no row (a since-deleted user, or a forgery the trusted-key verify
	// already blocks) — is org-scoped only, carrying no admin, super, or app
	// authority. Fail closed by construction: on the raw CRUD this authorizes to
	// nothing.
	return &principal.Principal{Org: owner}, nil
}

// membershipRoles reads the org->role set a person may act in. A store error is
// not fatal: it yields an EMPTY set, which is the same authority the policy gave
// before memberships existed (home org only), so a store blip narrows a decision
// and never widens one. The read is one indexed query on the user key.
func membershipRoles(ctx context.Context, db orm.DB, user string) map[string]policy.Role {
	rows, err := store.MembershipsByUser(ctx, db, user)
	if err != nil || len(rows) == 0 {
		return nil
	}
	out := make(map[string]policy.Role, len(rows))
	for _, m := range rows {
		if m != nil && m.Org != "" {
			out[m.Org] = policy.Role(m.Role)
		}
	}
	return out
}

// app resolves an `Authorization: Basic <clientId>:<clientSecret>` credential into
// a confidential-client Principal — the transport every live server-side consumer
// authenticates with (RFC 6749 §2.3.1 client_secret_basic; cloud reads
// IAM_MINT_CLIENT_ID/SECRET and sends exactly this). The application NAME is the
// identity, because the capability allowlists key on the name.
//
// It is deliberately NOT an authority: the returned Principal is never Admin and
// never Super, so the ONLY thing it can do is what its name is allowlisted for
// (CanEntity → Holds). This is what keeps the v1 "every confidential client is a
// global admin" hole closed as the transport is re-added.
//
// Fail-closed: an unparseable header, an unknown clientId, a row carrying no NAME
// (the name is what every capability keys on, so a nameless one authorizes
// nothing and is refused here rather than downstream), an application with no
// registered secret, an empty presented secret (a public client must never
// authenticate as an app), or a mismatch all report false — the caller then finds
// no bearer either and answers 401. The comparison is constant-time.
func app(c *zip.Ctx, db orm.DB) (*principal.Principal, bool) {
	id, secret, ok := httpx.Basic(c)
	if !ok || id == "" || secret == "" {
		return nil, false
	}
	a, err := store.GetApplicationByClientId(c.Context(), db, id)
	if err != nil || a == nil || a.Name == "" || a.ClientSecret == "" {
		return nil, false
	}
	if subtle.ConstantTimeCompare([]byte(a.ClientSecret), []byte(secret)) != 1 {
		return nil, false
	}
	return appPrincipal(a), true
}

// appPrincipal is the ONE shape a confidential client's authority takes, so the
// two ways it can present that authority — client_secret_basic on the request,
// or the bearer it minted with those same credentials — cannot resolve to
// different principals.
//
// App.Owner is the app row's OWNING org (a.Owner: "admin"/"built-in" for a
// platform app), NOT a.Organization (the tenant it SERVES). Principal.Holds pins
// every capability to this being a reserved signing owner, so a tenant-owned app
// named/clientId'd like a console holds nothing. Org carries the served tenant.
func appPrincipal(a *schema.Application) *principal.Principal {
	return &principal.Principal{
		App: &policy.App{Name: a.Name, Owner: a.Owner, Cert: a.Cert},
		Org: a.Organization,
	}
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
		rest = rest[:i]
	}
	return entityNoun(rest)
}

// entityNoun folds a verb-carrying path segment onto the entity noun the policy
// is written in: delete-membership -> memberships, get-account -> accounts. An
// address that still spells the verb addresses the SAME rows as its resource
// twin, so the two must resolve to the same entity.
//
// Without the fold a capability keyed on an entity is inert wherever the verb
// survives: /v1/iam/memberships resolves to "memberships" and matches, while
// /v1/iam/delete-membership resolves to the literal "delete-membership", matches
// no clause, falls through to the reserved-owner gate and 403s. A client on the
// verb never sees the grant fire, and capFor("delete-membership") is not
// capFor("memberships"). Folding here — the ONE place a path becomes an entity —
// gives every address the documented policy at once rather than teaching each
// clause two spellings.
func entityNoun(seg string) string {
	for _, v := range verbs {
		if strings.HasPrefix(seg, v) {
			seg = seg[len(v):]
			break
		}
	}
	if seg == "" {
		return ""
	}
	// EVERY policy clause is written in the plural — applications, certs,
	// projects, users, organizations, keys — so every path segment is folded to
	// the plural, not just the ones that carried a verb prefix.
	//
	// Pluralising only after stripping a verb is what split the policy in two.
	// /v1/iam/get-application folded to "applications" and matched the app
	// self-read clause; the NATIVE /v1/iam/application carries no verb, fell
	// through as the singular "application", matched no clause, and hit the
	// reserved-owner gate — so a relying party could read its own row over the
	// legacy verb and was refused 403 over the native route. One policy, two
	// answers, decided by spelling.
	//
	// Folding here is safe precisely because the clauses are plural: the only
	// segments this newly changes are the singular natives (application, cert,
	// key, user, organization, project), and each folds onto the entity it IS.
	if !strings.HasSuffix(seg, "s") {
		seg += "s"
	}
	return seg
}
