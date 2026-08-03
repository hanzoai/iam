// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package routes registers the IAM HTTP surface on a zip App.
//
// Authentication is STRUCTURAL, decided by which group a route is registered on,
// never by a hand-maintained path list. Route binds the surface as two groups:
//
//   - the PUBLIC group (oidc.Route and the other pre-auth doors) holds no Guard,
//     so membership in it IS "public".
//   - the AUTHED group holds authz.Guard. Every route registered on it — the
//     typed entity CRUD, the legacy verb aliases, the SCIM surface — requires a
//     verified bearer.
//
// A public route therefore can never be accidentally gated, and an authed route
// can never be accidentally public: the decision is where you register, not an
// allow-list that can drift out of sync with the routes.
//
// THE GUARD IS SCOPED, and it is a group rather than app.Use for that reason.
// zip places middleware by depth: on the app it becomes router middleware, in
// front of every request the BINARY will ever serve. IAM is one subsystem among
// many in the cloud binary, so that seam authenticated its siblings' routes
// against IAM's own store — and answered for addresses no one had declared. A
// group reaches its own routes and stops.
//
// Authentication is therefore mounted TWICE, and the second is not a duplicate:
// authz.Control gates the framework's own /mcp, OpenAPI and docs projections,
// which zip installs directly on the served app's router with no middleware and
// which no group can reach. Scoping the Guard is exactly what takes those out of
// its reach, so the two lines are one decision with two mounting points.
//
// LIVENESS IS NOT HERE. /healthz, /readyz and /metrics are zip's ops surface
// (zip/ops.go, HIP-0119 §1): a SECOND listener the DEPLOYMENT brings up when it
// names OPS_PORT, never the public one — a liveness probe must not queue behind
// public traffic. A route this package registered was iam hand-rolling a path
// the framework owns, on the wrong listener, and it made iam unable to be
// composed into a host: cloud registers /healthz as the HOST's, because it must
// answer while every subsystem is still cold. Two claimants on one liveness
// address is the shape that already served {"binary":"iam2"} out of the shared
// cloud binary. One address, one owner, and this is not iam's.
package routes

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/applications"
	"github.com/hanzoai/iam/internal/auditlogs"
	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/bootstrap"
	"github.com/hanzoai/iam/internal/certs"
	"github.com/hanzoai/iam/internal/compat"
	"github.com/hanzoai/iam/internal/cors"
	"github.com/hanzoai/iam/internal/invitations"
	"github.com/hanzoai/iam/internal/keys"
	"github.com/hanzoai/iam/internal/memberships"
	"github.com/hanzoai/iam/internal/mfa"
	"github.com/hanzoai/iam/internal/oidc"
	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/internal/permission"
	"github.com/hanzoai/iam/internal/projects"
	"github.com/hanzoai/iam/internal/providers"
	"github.com/hanzoai/iam/internal/registry"
	"github.com/hanzoai/iam/internal/roles"
	"github.com/hanzoai/iam/internal/scim"
	"github.com/hanzoai/iam/internal/serviceaccounts"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/tokens"
	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/internal/wallet"
	"github.com/hanzoai/iam/internal/webauthn"
	"github.com/hanzoai/iam/internal/workspaces"
)

// Route registers the whole IAM route surface on app, threading the entity
// store db into every handler. This is the route table server.Route embeds — the
// one Route(app, db) is the public entry; everything below is Route.
func Route(app *zip.App, db orm.DB) {
	// ─────────────────────────── PUBLIC ───────────────────────────
	// The pre-authentication surface: OIDC discovery/JWKS + RFC 8414 AS metadata,
	// the oauth/* protocol endpoints (authorize, token, userinfo, logout,
	// introspect, revoke), credential login, the confidential-client key minters,
	// and the front door (get-app-login, auth/methods, get-account, signup, signin,
	// whoami, onboard, …). Registered on a root (empty-prefix) group that holds no
	// Guard, at their absolute paths. There is no allow-list to keep in sync, and
	// no ordering to preserve: a route is public because it is registered here.
	// CORS for the browser-side OIDC surface, BEFORE any route matches so it
	// covers the public group without a route opting in. The allowlist is derived
	// from registered redirect URIs — provision a host and login works from it.
	app.Use(cors.Allow(db))

	public := app.Group("")
	oidc.Route(public, db)
	// Operator bootstrap upsert (admin/{applications,users}/upsert) — self-authenticated
	// by the unified service token (Bearer), not a user principal, so it is PUBLIC.
	bootstrap.Route(public, db)
	// Native multi-chain wallet sign-in (CAIP-122): GET /v1/iam/web3/nonce +
	// POST /v1/iam/web3/verify. Public by construction — a wallet holder has no
	// token until this flow gives them one.
	wallet.Route(public, db)

	// Docker Registry v2 token auth: GET;POST /v1/iam/registry/token +
	// GET /v1/iam/registry/jwks. Public by construction — a docker client holds
	// no IAM bearer; it presents a Basic credential the token endpoint verifies.
	// registry:2 at registry.hanzo.ai points REGISTRY_AUTH_TOKEN_REALM here and
	// trusts these tokens via the served JWKS (its ROOTCERTBUNDLE).
	registry.Route(public, db)

	// ─────────────────────────── GUARD ────────────────────────────
	// The ONE authentication seam, on a group that HOLDS the routes it guards.
	// Every route registered on `authed` requires a verified bearer — the typed
	// entity CRUD below, the legacy verb aliases, the SCIM surface. The resolved
	// Principal rides the request context for the write-authz hook above; reads
	// are authorized here (their target rides the query string, or the handler
	// scopes a path target itself). Fails closed (401).
	//
	// It is a GROUP that holds the Guard, not app.Use, and that difference IS the
	// fix. zip places middleware by DEPTH (zip/build.go materialise): a handler
	// on the app becomes ROUTER middleware — a barrier in front of every request
	// the binary will ever serve, including addresses this package never
	// declared — while a handler inside an included definition is composed into
	// the CHAIN of that definition's own routes and reaches nothing else.
	//
	// Under app.Use, IAM mounted at position 9 gated ai's /v1/models at position
	// 106 and resolved its bearer against the embedded iam.db, which has never
	// seen a token minted by the external hanzo.id — 401 on every valid request.
	// The tell was the body: {"status":401,"error":"authentication required"} is
	// this Guard, not ai's OpenAI-shaped error. The same barrier also answered
	// addresses NOTHING declares, which is why a typo'd path returned this
	// Guard's 401 where a 404 was the truth. A group confines both: a definition
	// does not answer for addresses it does not declare.
	//
	// The prefix is empty because IAM's routes are registered at their canonical
	// ABSOLUTE paths (/v1/iam/…, /scim/v2/…, /login/oauth/…) and a group prefix
	// would rewrite every one of them. A group earns its scope from being a
	// subtree, not from having a prefix — the public group above is the same
	// shape, and this one differs only in holding the Guard.
	//
	// Group returns the Router interface, but a group IS an *App (zip/compose.go
	// group) and this needs the concrete type twice over: the sub-Routes below
	// take *zip.App because zipdoc must resolve each op's path prefix statically,
	// and the group needs its OWN Authorize hook.
	authed := app.Group("").(*zip.App)
	authed.Use(authz.Guard(db))

	// AUTHORIZATION of writes, on the SAME group, for the same reason. The
	// op-invoke hook authorizes every typed op on the DECODED input the handler
	// binds — for REST and MCP alike, so the value authorized is the value
	// written. Writes to the reserved admin/built-in owners (the signing-cert
	// poisoning gate) stay SuperAdmin-only. It fires inside each typed op rather
	// than as middleware, so it is order-independent; what it is NOT is
	// app-independent.
	//
	// zip reads `app.authorizer` off the app an op was REGISTERED on, and a group
	// inherits nothing. That cuts both ways, and both cuts are load-bearing:
	//
	//   - the group MUST have it. Without it every decoded write here runs
	//     unauthorized — authenticated by the Guard, then unchecked — which is a
	//     regular user editing another org's records with a valid bearer.
	//   - the app must NOT. On the host app it became the HOST's authorizer, so a
	//     sibling subsystem's typed op was authorized by IAM's rules against a
	//     principal IAM's Guard never attached: 403 forbidden on every valid
	//     call. That is the Guard's 401 wearing a different status code — same
	//     overreach, same cause, one seam over — and scoping only the Guard would
	//     have left every TYPED sibling op broken while the raw ones recovered.
	authed.Authorize(authz.Authorize)

	// The same authentication, mounted a second time for the ONE surface a
	// scoped seam cannot reach: the framework's own /mcp door and OpenAPI
	// document, which Build installs directly on the served app's router with no
	// middleware, having never been registered through any group. Control is
	// depth-0 for that reason and acts on those three addresses only — see
	// authz.Control. Without it the MCP door would dispatch tools/call into this
	// same admin CRUD unauthenticated.
	app.Use(authz.Control(db))

	// ─────────────────────────── AUTHED ───────────────────────────
	// Typed entity CRUD. Each registers its typed ops on `authed` — a *zip.App,
	// which the projection into REST + OpenAPI + MCP and zipdoc's static prefix
	// resolution both need. On the guarded group, so all are gated.
	users.Route(authed, db)
	organizations.Route(authed, db)
	applications.Route(authed, db)
	providers.Route(authed, db)
	roles.Route(authed, db)
	projects.Route(authed, db)
	workspaces.Route(authed, db)
	permission.Route(authed, db)
	certs.Route(authed, db)
	keys.Route(authed, db)
	webauthn.Route(authed, db)
	sessions.Route(authed, db)
	tokens.Route(authed, db)
	auditlogs.Route(authed, db)
	invitations.Route(authed, db)

	// legacy verb-alias layer: the get-users / get-organizations / add-organization
	// / … spellings (in the v1 {status,data,data2} envelope) every live console/
	// gateway/portal client hard-codes, served over the SAME store, redaction, and
	// authz as the REST surface above — the transparent backend swap. On the
	// guarded group, so it shares the one Guard/Authorize seam.
	compat.Route(authed, db)

	// SCIM 2.0 (RFC 7644/7643) — the STANDARD identity-provisioning surface that
	// replaces the the legacy surface entity verbs (HIP-0111). On the guarded group, so
	// it is authenticated; each handler owner-scopes via authz.Scope on the path target.
	scim.Route(authed, db)

	// Agent/bot identities (service accounts) + the (User x Org x Role) membership
	// relation. On the guarded group: each self-authorizes writes via the Principal +
	// capabilities the Guard attached, and org-scopes reads via authz.Scope.
	serviceaccounts.Route(authed, db)
	memberships.Route(authed, db)

	// TOTP multi-factor enrollment (RFC 6238) — the account security page's
	// initiate/verify/enable/disable flow. On the guarded group: self-service on the
	// caller's own user (authz.From); a cross-user reset needs admin (authz.Can).
	mfa.Route(authed, db)
}
