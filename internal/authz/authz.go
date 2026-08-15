// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package authz is the IAM v2 authorization seam in front of the Phase-1 entity
// CRUD, which is otherwise unauthenticated — the door an attacker would walk
// through to overwrite an admin-owned signing cert and forge tokens. It is two
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
// the same question the published authz.Claims.PlatformSudo asks of the signed
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
	"reflect"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// adminOrg is the reserved organization whose membership IS SuperAdmin — the one
// cross-tenant scope, the one predicate. It is store's value, not a copy of it,
// so the word is spelled once. The broader reserved-owner set {admin, built-in}
// the poisoning gate protects lives in ONE place, store.IsSigningCertOwner,
// shared with the token verifier and the JWKS.
const adminOrg = store.AdminOrg

// Principal is the identity a gated request acts as, resolved from a verified
// bearer. Org is the tenant (the authenticated principal's own org, from the
// subject); User is its name within that org (empty for a machine token); Admin
// is the org-admin flag; Super is the SuperAdmin predicate (memberOf adminOrg).
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
	// AppCert is the NAME of the signing cert that application row references
	// (schema.Application.Cert). It is carried on the principal so the self-read
	// clause can permit an app exactly one cert — its own — without the pure
	// authorize() decision having to reach into the store. Empty for every human.
	AppCert string
	Admin   bool
	Super   bool
	// Orgs is the set of organizations this person may act in — their HOME org
	// plus every org they hold a membership in, which is the SAME set the token's
	// `orgs` claim carries. It exists because "the org you belong to" and "the org
	// that owns your account" are different questions, and the policy used to
	// answer the first with the second: an org's own member could not read that
	// org's row unless it happened to be their account's owner. One person, many
	// orgs is the product; this is where the policy learns it. Empty for an app
	// principal (a machine's scope is its served tenant, never a membership).
	Orgs map[string]string // org -> role (owner|admin|member)
}

// memberOf reports whether p may act in org through its HOME org or a
// membership. It is the ONE membership question the policy asks, so a clause
// never re-derives the set.
func (p *Principal) memberOf(org string) bool {
	if org == "" {
		return false
	}
	if org == p.Org {
		return true
	}
	_, ok := p.Orgs[org]
	return ok
}

// adminOf reports whether p may CHANGE org — its own org as an org admin, or an
// org it holds an owner/admin membership in. A plain member never qualifies:
// belonging to an org is permission to see it, not to edit it.
func (p *Principal) adminOf(org string) bool {
	if org == "" {
		return false
	}
	if org == p.Org && p.Admin {
		return true
	}
	switch p.Orgs[org] {
	case store.RoleOwner, store.RoleAdmin:
		return true
	}
	return false
}

type ctxKey struct{}

// From returns the Principal the Guard attached to ctx for a gated request, and
// whether one is present (public routes carry none).
func From(ctx context.Context) (*Principal, bool) {
	p, ok := ctx.Value(ctxKey{}).(*Principal)
	return p, ok
}

// Scope resolves the owner an org-scoped request is bound to. It is the ONE
// place the rule lives, and the rule is:
//
//	AN ORG-SCOPED REQUEST IS HONOURED OR REFUSED, NEVER SILENTLY REINTERPRETED.
//
// A SuperAdmin — the only cross-tenant scope — is bound to the owner it names
// (empty = every tenant). Everyone else is bound to its OWN org and may say so:
// naming its own org, or naming none, both resolve to it. Naming a DIFFERENT org
// is refused, because the one thing this function must never do is answer a
// request about org B with org A's rows.
//
// It used to return p.Org for ANY owner, silently discarding the parameter.
// Measured against production 2026-07-28 with the hanzo-console credential (home
// org hanzo): ?owner=lux, ?owner=zoo and ?owner=nonexistent-org-xyz each answered
// 200/ok with 262 `hanzo` accounts. No tenant's rows escaped IAM — the pin held —
// so it was not a confidentiality breach here; it was MISATTRIBUTION, which is
// worse in one specific way. Nothing in the status code, the `status` field, the
// message or the count said the filter had been dropped, so the caller believed
// it held tenant B while holding tenant A. An operator asked for lux, was handed
// 262 hanzo accounts, and was one filter-and-delete from purging the wrong
// tenant. Downstream it WAS a leak: cloud's IAM edge (cloud/iam_edge.go) checks
// ?owner= against the calling tenant and then forwards it under ONE confidential
// client, so every tenant's team page asked for its own org and was served the
// edge credential's org instead. A pin that lies composes into a breach; a
// refusal cannot.
//
// The refusal is NOT an org-existence oracle, and by construction rather than by
// care: the decision is taken from the verified principal alone and never touches
// the store, so `lux` (a real tenant), `built-in` (reserved) and
// `nonexistent-org-xyz` (a fabrication) are the same comparison and the same
// bytes out. Its text names the CREDENTIAL's org, never the requested one. That
// is the same collapse cloud's per-org KMS store makes for this class of leak —
// every spelling the caller may not have routes to ONE existence-independent
// answer. It differs only in WHICH answer: KMS has no org parameter to refuse (it
// reads the org from the token), so absence is its only observable and it answers
// 404; here the org is a stated request parameter, so there IS an authorization
// decision to report, and reporting it is the entire point.
//
// An empty p.Org is refused too. A non-super with no org has no org scope, and
// returning "" would resolve to "no filter" — every tenant's rows, which is the
// exact branch TestListRoutesNeverLeakAnotherTenant exists to keep shut. Fail
// closed.
func Scope(ctx context.Context, owner string) (string, error) {
	p, ok := From(ctx)
	if !ok {
		return "", zip.ErrForbidden("no principal")
	}
	if p.Super {
		return owner, nil
	}
	if p.Org == "" || (owner != "" && owner != p.Org) {
		return "", errForeignOrg(p)
	}
	return p.Org, nil
}

// ScopeRead is [Scope] for a READ: the org a listing is filtered by.
//
// It differs in ONE clause, and that clause is not new — [Can] already states it
// for the org registry: "a person reads any org they BELONG to, and edits the ones
// they help run." A human's account lives in one IAM tenant while the orgs they
// work in are a set, so keying a read on p.Org alone refuses an org's own admin
// the org they administer. Measured in production: get-organization-projects
// ?organization=lux answered 403 for a caller holding an admin membership in lux,
// the console's switcher swallowed it, and an org the picker said you ran would
// not open. The membership set is read from the store when the principal is built
// (membershipRoles) — it is never a claim the caller supplies.
//
// WRITES DO NOT COME THROUGH HERE, and that is the whole reason this is a second
// entry point rather than a widened Scope. Scope keeps its stricter clause, so a
// plain member still cannot mint a token or a cert in an org they merely belong
// to, and the handler-authorized write surfaces (SCIM, service-accounts,
// memberships) are untouched. Only a read whose target rides in the QUERY — the
// switcher's project and workspace lists — asks this question.
func ScopeRead(ctx context.Context, owner string) (string, error) {
	p, ok := From(ctx)
	if !ok {
		return "", zip.ErrForbidden("no principal")
	}
	if p.Super {
		return owner, nil
	}
	// No org named: the caller's own, exactly as Scope resolves it. An empty p.Org
	// has no scope to fall back to and returning "" would mean "no filter".
	if owner == "" {
		if p.Org == "" {
			return "", errForeignOrg(p)
		}
		return p.Org, nil
	}
	if !p.memberOf(owner) {
		return "", errForeignOrg(p)
	}
	return owner, nil
}

// errForeignOrg is the refusal a foreign owner earns. It is built from the
// PRINCIPAL's own org and never from the requested one, so every org the caller
// may not have — real, reserved, or invented — produces the byte-identical
// answer. Naming the caller's own org discloses nothing (its rows already carry
// it) and is what turns a bare "forbidden" into a diagnosis: you are pinned here,
// you asked for somewhere else.
func errForeignOrg(p *Principal) error {
	if p.Org == "" {
		return zip.ErrForbidden("forbidden: this credential carries no organization scope")
	}
	return zip.ErrForbidden("forbidden: this credential is scoped to organization " + p.Org)
}

// Deny renders a Scope/ScopeFor refusal in the envelope the caller's surface
// speaks — the SAME shaping the Guard's own refusal uses, so one refusal looks
// the same whether it was raised before the handler or inside it. A handler that
// answered it with httpx.Err would send HTTP 200 carrying {"status":"error"},
// which is how a refusal gets logged as a success.
func Deny(c *zip.Ctx, err error) error { return refuse(c, http.StatusForbidden, err.Error()) }

// ScopeFor resolves the owner a compat READ should query — the same decision as
// Scope, except that a self-read addresses its own owner verbatim.
//
// Scope pins a non-SuperAdmin to p.Org, which for an app principal is the tenant it
// SERVES (hanzo), not the org that OWNS its row (admin). So a confidential client
// authorized by the Guard to read admin/hanzo-cloud then had the query rewritten to
// hanzo/hanzo-cloud and got "the entity does not exist" — authorized and still
// unable to read itself, a 200 that is functionally the 403 it replaced.
//
// Rather than loosen Scope (whose binding IS the tenant gate on the handler-authorized
// paths — SCIM, service-accounts, memberships), the ONE self-read clause is asked
// again here, through the same authorize() it is defined in. There is no second copy
// of the rule: if authorize would admit this exact read, the owner it admitted is the
// owner we query; otherwise Scope decides, and Scope now REFUSES a foreign owner
// rather than rewriting it. That is the honour-or-refuse rule reaching this path
// too: a grant honours the org it names and answers with THAT org's row, correctly
// attributed; everything else is refused. Neither branch can hand back a row the
// request did not ask for.
//
// The grant is honoured WHOLE. An earlier shape re-narrowed the honoured set to
// supers and app self-reads after authorize() had already admitted the read —
// a second copy of the policy, and a stale one: it predated the organizations
// exception (a tenant's own org row lives under the reserved admin owner), so a
// member's GET of admin/<their org> was admitted by the policy and then refused
// by this re-narrowing. The native REST twin, authorized by the Guard alone,
// answered 200 for the same principal and row — one policy, two answers. If
// authorize() says yes to this exact (owner, name) read, that IS the decision.
func ScopeFor(ctx context.Context, path, owner, name string) (string, error) {
	if p, ok := From(ctx); ok && owner != "" && authorize(p, "GET", entityOf(path), owner, name) {
		return owner, nil
	}
	return Scope(ctx, owner)
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
// A native typed read files them as `?owner=&name=`; the the legacy surface compat verbs
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
// authz.Scope. SCIM (RFC 7644, /v1/iam/scim/v2/Users/{id}) is path-targeted, so it
// belongs here. This is the read analogue of a write deferring to the op-invoke
// seam — the target is authorized where it is bound, not guessed from the query.
// get-organization-projects (and its workspace tier, get-organization-workspaces)
// is the the legacy surface read verb whose target rides in ?organization= (the
// ScopeSwitcher's project/workspace list), not ?owner=/?id=/the path, so the Guard
// cannot pre-authorize it generically; the handler scopes it through authz.Scope
// instead (the read analogue of SCIM's path-targeted authorization).
// get-memberships is the the legacy surface alias of /v1/iam/memberships whose target rides in
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
//
// resolve-key is here for the same reason: its target is a publishable pk- riding in
// ?accessKey= (no owner/name for the Guard to authorize), and its handler authorizes
// itself behind CapPublishableResolve, returning ONLY the org — never a principal.
//
// organizations/search is here because it NAMES no target: it asks which
// organizations the CALLER may act in, so the answer is derived from the
// principal and there is nothing in the query for the Guard to authorize. An
// empty target fails the tenant rule, which would deny every non-SuperAdmin the
// list of their own organizations. It is exact rather than a prefix so it cannot
// reach /v1/iam/organizations, the Guard-authorized entity list beside it.
var handlerAuthorizedExact = map[string]bool{
	"/v1/iam/get-user":             true,
	"/v1/iam/resolve-key":          true,
	"/v1/iam/organizations/search": true,
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
// The the legacy surface-compatible verbs (/v1/iam/get-user, add-organization, …) are a
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
// Only the compat surface is reshaped. The native REST/OIDC routes keep zip's
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

// legacyVerbs are the request-shaped prefixes of the compat surface — the
// verb-per-path the legacy surface spelling (get-/add-/update-/delete-) that the console BFF,
// the @hanzo/iam SDK and the cloud clients hard-code. The native surface is
// noun-shaped (/v1/iam/users, /v1/iam/organizations), so the verb prefix is what
// distinguishes the two contracts without a second list to keep in sync.
var legacyVerbs = []string{"get-", "add-", "update-", "delete-"}

// legacyVerb reports whether path is one of the compat verbs.
func legacyVerb(path string) bool {
	const p = "/v1/iam/"
	if !strings.HasPrefix(path, p) {
		return false
	}
	rest := path[len(p):]
	for _, v := range legacyVerbs {
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
		p, err := principal(c, db)
		if err != nil {
			return refuse(c, 401, "authentication required")
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
				return refuse(c, 403, "forbidden")
			}
		}
		c.SetContext(context.WithValue(c.Context(), ctxKey{}, p))
		return c.Continue()
	}
}

// mcpPath is where zip mounts the MCP door. zip exports SpecPath and DocsPath
// but keeps this one unexported (zip/mcp.go defaultMCPPath), and IAM never moves
// it — MCPConfig.Path is left at its default wherever IAM builds an app.
const mcpPath = "/mcp"

// Control gates the framework's OWN projections: the MCP door, the OpenAPI
// document and the docs UI. It is the SECOND mounting of the one Guard, and it
// exists because those three addresses are not routes anybody registered.
//
// zip installs them at Build, directly onto the served app's router, with no
// middleware and after every entry in the program (zip/build.go materialise:
// "control routes are not entries at all"). A scoped seam therefore cannot reach
// them — a group's middleware is composed into that group's own route chains,
// and these are in no group — so the only seam that can is a depth-0 one.
//
// That is the whole reason authentication is mounted twice. Gating them matters
// because the MCP door dispatches tools/call straight into the typed ops: it is
// the same admin CRUD the REST surface exposes, reached by a different
// transport, and the op-invoke hook alone does not close it (Authorize admits a
// read whose decoded target is empty, on the REST-shaped assumption that the
// Guard already ran). Unauthenticated, that combination lists users.
//
// Narrow by construction, and that is what keeps it from being the bug it
// replaces: it is a depth-0 handler, so it is consulted on every request, but it
// ACTS only on the three addresses the framework itself owns and hands every
// other path straight on. A sibling subsystem's route is not one of them.
func Control(db orm.DB) zip.Handler {
	guard := Guard(db) // one authentication decision, mounted twice, never copied
	return func(c *zip.Ctx) error {
		switch c.Path() {
		case mcpPath, zip.SpecPath, zip.DocsPath:
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
// principal (over REST, on the guarded group the op registered on; over MCP, on
// the /mcp route authz.Control gates). That second clause is why Control is not
// optional. The owner == "" read admitted just below trusts the Guard to have
// authorized the query-string target, and over MCP the arguments decode into In
// rather than the query — so an ungated door would reach this line with no
// principal, no decoded target, and an admission.
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
	// An app may READ THE ROW IT AUTHENTICATED AS, and no other. Reading its own
	// registration is the ordinary bootstrap of an OIDC relying party — it is how a
	// client discovers its own cert, redirect URIs and enabled methods — and it
	// reveals nothing the holder of that client's credential does not already have.
	//
	// The owner-pin that closed the "every client credential is a global admin"
	// escalation is not wrong; it was missing this case, and applications are not in
	// capFor(), so a confidential client could not read even itself and every cloud
	// deploy 403'd on its own bootstrap.
	//
	// Narrow by construction, in four ways at once: only an app principal (a human's
	// authority is decided below), only a READ (never a write to its own row — that
	// would let a client widen its own redirect URIs or grants), only the
	// applications entity, and only the exact (AppOwner, App) pair the request
	// authenticated as. Both halves of the key must match, so this is self-read and
	// not "apps may read applications": a sibling in the same org differs in `name`
	// and stays refused, and admin/<app> vs <tenant>/<app> — the same NAME under a
	// different owner — differs in `owner`, so neither direction of that collision
	// is admitted. That pairing is the same one Allowed() pins capabilities to.
	if p.App != "" && isRead(method) {
		// its own application row — both halves of the key must match
		if entity == "applications" && owner != "" && owner == p.AppOwner && name == p.App {
			return true
		}
		// ...and the ONE signing cert that row references. A relying party cannot
		// bootstrap without it: InitAuthConfig reads its application, then reads
		// application.Cert, then InitConfig(cert.Certificate) — so granting only the
		// application fixes one line and panics identically on the next.
		//
		// Scoped to the cert its OWN application names, never "apps may read certs":
		// name must equal the cert on the authenticated row, so an app cannot walk to
		// another brand's signing cert. Read-only, and the read is masked anyway
		// (Cert.Mask blanks PrivateKey and AccessSecret), so what crosses the wire is
		// the PUBLIC certificate this client already has to trust to verify our
		// tokens. A bare `?id=cert-hanzo` carries no owner half, so an empty owner is
		// admitted ONLY here, where the cert NAME is already pinned to this principal.
		// The owner half varies by CALLER, so all three shapes are admitted — what
		// pins this read is the NAME, not the owner. ai/internal/iam/cert.go sends
		// "<IAM_ORG>/<name>" (hanzo/cert-hanzo), GetApplication hardcodes admin/, and
		// a bare id carries no owner at all. Measured: admin/cert-hanzo and
		// hanzo/cert-hanzo are two rows seeded 3ms apart carrying the IDENTICAL 4096-bit
		// modulus, both matching the single JWKS kid=cert-hanzo — so the owner half
		// selects between duplicates of one keypair, not between different keys.
		//
		// name == p.AppCert is the whole gate and it is unchanged: an app reaches the
		// one cert its own application row names and no other, whichever owner it
		// spells. Read-only, and Cert.Mask blanks PrivateKey, so this discloses the
		// PUBLIC key already published at /v1/iam/.well-known/jwks.
		if entity == "certs" && p.AppCert != "" && name == p.AppCert &&
			(owner == "" || owner == p.AppOwner || owner == p.Org) {
			return true
		}
		// An org's OWN PaaS machine identity may READ that org's projects, and
		// nothing else. This is how cloud's platform resolves a tenant's
		// projects from the canonical store here instead of a second embedded
		// database — the split-brain where a project created at /v1/iam was
		// invisible to the PaaS and vice versa.
		//
		// Narrow by construction, four ways at once, mirroring the self-read
		// blocks above: only a READ; only the projects entity; only the
		// caller's OWN org (owner == p.Org, so one tenant's identity can never
		// walk another's list); and only the identity the "<org>-platform-kms"
		// contract names — the same string cloud's SanitizeIdentity recognises
		// in order to DENY that principal SuperAdmin. The contract is the
		// grant, stated once; no env allowlist to drift.
		if entity == "projects" && owner != "" && owner == p.Org &&
			p.App == p.Org+"-platform-kms" {
			return true
		}
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
		// A person reads any org they BELONG to, and edits the ones they help run.
		// Membership is the authority, not the account's owner half: a human's
		// account lives in one IAM tenant while the orgs they work in are a set, so
		// keying this on p.Org alone refused an org's own admin the org they
		// administer — which is what made a second org invisible in every console.
		if isRead(method) {
			return p.memberOf(name)
		}
		return p.adminOf(name)
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
		// Super is MEMBERSHIP of the reserved org, never the home org. Home is where
		// an identity is ANCHORED — its billing, its default scope. Platform authority
		// is a different question, and its answer is that an existing SuperAdmin put
		// this identity IN the reserved org: a deliberate, signed, revocable grant that
		// only a SuperAdmin can make (memberships.mayGrant refuses a reserved target to
		// anyone else). Asking the home org instead conflated the two and denied every
		// operator anchored in a brand org — which is every operator who also does
		// ordinary work — so the reserved org was unreachable in practice while the
		// code looked right. memberOf answers home-or-membership in one place, which is
		// what the published authz.Claims.PlatformSudo asks of the signed set, so one
		// token now reads the same here and at every consumer.
		p := &Principal{
			Org: u.Owner, User: u.Name, Admin: u.IsAdmin,
			Orgs: membershipRoles(ctx, db, u.Owner+"/"+u.Name),
		}
		p.Super = p.memberOf(adminOrg)
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
	// remains capFor()/Allowed(), pinned to a reserved signing owner.
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
	return &Principal{Org: owner}, nil
}

// membershipRoles reads the org->role set a person may act in. A store error is
// not fatal: it yields an EMPTY set, which is the same authority the policy gave
// before memberships existed (home org only), so a store blip narrows a decision
// and never widens one. The read is one indexed query on the user key.
func membershipRoles(ctx context.Context, db orm.DB, user string) map[string]string {
	rows, err := store.MembershipsByUser(ctx, db, user)
	if err != nil || len(rows) == 0 {
		return nil
	}
	out := make(map[string]string, len(rows))
	for _, m := range rows {
		if m != nil && m.Org != "" {
			out[m.Org] = m.Role
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
	return appPrincipal(a), true
}

// appPrincipal is the ONE shape a confidential client's authority takes, so the
// two ways it can present that authority — client_secret_basic on the request,
// or the bearer it minted with those same credentials — cannot resolve to
// different principals.
//
// AppOwner is the app row's OWNING org (a.Owner: "admin"/"built-in" for a
// platform app), NOT a.Organization (the tenant it SERVES). cap.go pins every
// capability to this being a reserved signing owner, so a tenant-owned app
// named/clientId'd like a console holds nothing. Org carries the served tenant.
func appPrincipal(a *schema.Application) *Principal {
	return &Principal{App: a.Name, AppOwner: a.Owner, AppCert: a.Cert, Org: a.Organization}
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

// entityNoun folds the legacy VERB spelling of a path segment onto the entity
// noun the policy is written in: get-application -> applications, add-organization
// -> organizations. Both surfaces address the SAME rows, so they must resolve to
// the same entity — and they did not.
//
// This is what made the app self-read grant look inert in production. The native
// route /v1/iam/applications resolved to "applications" and matched; the compat
// alias /v1/iam/get-application resolved to the literal string "get-application",
// matched no clause, fell through to the reserved-owner gate and 403'd. Cloud calls
// the alias, so the grant never fired on the only path anyone uses.
//
// It is the wider bug too, not just this grant's: EVERY capability keyed on an
// entity was dead on the compat surface, because capFor("add-organization") is not
// capFor("organizations"). The allowlists that exist precisely so the brand consoles
// can manage orgs during onboarding were being consulted with a key that could never
// match. Folding here — the ONE place a path becomes an entity — restores the
// documented policy on both surfaces at once rather than teaching each clause two
// spellings.
func entityNoun(seg string) string {
	for _, v := range legacyVerbs {
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
