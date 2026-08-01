// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package routes registers the IAM HTTP surface on a zip App.
//
// Authentication is STRUCTURAL, decided by which group a route is registered on,
// never by a hand-maintained path list. Route binds the surface in two phases
// around one authentication seam:
//
//   - the PUBLIC group (oidc.Route and the other pre-auth doors) is registered
//     FIRST, before the Guard. A matched public route terminates fiber's
//     middleware walk, so the Guard never runs on it — membership in this group
//     IS "public".
//   - app.Use(authz.Guard) is the ONE authentication seam. Every route registered
//     AFTER it — the typed entity CRUD, the legacy verb aliases, the SCIM
//     surface, and the framework's own /mcp + /openapi projections — requires a
//     verified bearer.
//
// A public route therefore can never be accidentally gated, and an authed route
// can never be accidentally public: the decision is where you register, not an
// allow-list that can drift out of sync with the routes.
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

// guardedPrefixes are the URL subtrees IAM authenticates — everything this
// subsystem serves that is not in the public group.
//
//   - /v1/iam      the entity CRUD, the legacy verb aliases, SCIM, service
//     accounts, memberships and MFA all live here.
//   - /login/oauth the interactive authorize surface.
//   - /mcp and /.well-known/openapi.json the framework's own projections of the typed ops registered
//     below. They are IAM's side doors onto the same rows, so they must stay
//     gated; when IAM is EMBEDDED the host binary owns these paths and should
//     mount its own guard, which is why they are named here rather than assumed.
var guardedPrefixes = []string{"/v1/iam", "/login/oauth", "/mcp", "/.well-known/openapi.json"}

// Route registers the whole IAM route surface on app, threading the entity
// store db into every handler. This is the route table server.Route embeds — the
// one Route(app, db) is the public entry; everything below is Route.
func Route(app *zip.App, db orm.DB) {
	// AUTHORIZATION of writes: the op-invoke hook authorizes every typed op on the
	// DECODED input the handler binds — for REST and MCP alike, so the value
	// authorized is the value written. Writes to the reserved admin/built-in owners
	// (the signing-cert poisoning gate) stay SuperAdmin-only. Installed once; it is
	// order-independent (it fires inside each typed op, not as middleware).
	app.Authorize(authz.Authorize)

	// ─────────────────────────── PUBLIC ───────────────────────────
	// The pre-authentication surface: OIDC discovery/JWKS + RFC 8414 AS metadata,
	// the oauth/* protocol endpoints (authorize, token, userinfo, logout,
	// introspect, revoke), credential login, the confidential-client key minters,
	// and the front door (get-app-login, auth/methods, get-account, signup, signin,
	// whoami, onboard, …). Registered on a root (empty-prefix) group BEFORE the
	// Guard, at their absolute paths, so a matched public route terminates the
	// middleware walk and the Guard never runs on it. There is no allow-list to
	// keep in sync: a route is public because it is registered here.
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
	// The ONE authentication seam. Every route registered AFTER it requires a
	// verified bearer — the typed entity CRUD below, the legacy verb aliases, the
	// SCIM surface, and the framework's own /mcp + /openapi projections (added at
	// Prepare). The resolved Principal rides the request context for the write-authz
	// hook above; reads are authorized here (their target rides the query string, or
	// the handler scopes a path target itself). Fails closed (401).
	// Mounted on the prefixes THIS SUBSYSTEM OWNS, not on the app.
	//
	// app.Use puts the Guard in front of every route the *zip.App will ever serve.
	// That is coherent while IAM owns the whole app and false the moment it does
	// not: embedded in the cloud binary IAM mounts at position 9 and `ai` registers
	// /v1/models at 106, so IAM's Guard gated ai's routes 97 positions later — and
	// then resolved the bearer against the EMBEDDED iam.db, which has never seen a
	// token minted by the external hanzo.id, so it failed closed on every valid
	// request. The tell was the body: {"status":401,"error":"authentication
	// required"} is this file's Guard, not ai's OpenAI-shaped error.
	//
	// Reordering the mounts would also have fixed it today and broken on the next
	// reorder: a position in a slice is not a security boundary. A path prefix is.
	//
	// This is a SCOPING change, not a relaxation — every prefix the Guard covered
	// that IAM actually serves is still covered, in the same order, with the same
	// fail-closed behaviour. The public group is still registered first and still
	// terminates the walk before this runs.
	for _, owned := range guardedPrefixes {
		app.Group(owned, authz.Guard(db))
	}

	// ─────────────────────────── AUTHED ───────────────────────────
	// Typed entity CRUD. Each registers its typed ops on app (the projection into
	// REST + OpenAPI + MCP needs *App); registered after the Guard, so all are
	// gated.
	users.Route(app, db)
	organizations.Route(app, db)
	applications.Route(app, db)
	providers.Route(app, db)
	roles.Route(app, db)
	projects.Route(app, db)
	workspaces.Route(app, db)
	permission.Route(app, db)
	certs.Route(app, db)
	keys.Route(app, db)
	webauthn.Route(app, db)
	sessions.Route(app, db)
	tokens.Route(app, db)
	auditlogs.Route(app, db)
	invitations.Route(app, db)

	// legacy verb-alias layer: the get-users / get-organizations / add-organization
	// / … spellings (in the v1 {status,data,data2} envelope) every live console/
	// gateway/portal client hard-codes, served over the SAME store, redaction, and
	// authz as the REST surface above — the transparent backend swap. After the
	// Guard, so it shares the one Guard/Authorize seam.
	compat.Route(app, db)

	// SCIM 2.0 (RFC 7644/7643) — the STANDARD identity-provisioning surface that
	// replaces the the legacy surface entity verbs (HIP-0111). After the Guard, so it is
	// authenticated; each handler owner-scopes via authz.Scope on the path target.
	scim.Route(app, db)

	// Agent/bot identities (service accounts) + the (User x Org x Role) membership
	// relation. After the Guard: each self-authorizes writes via the Principal +
	// capabilities the Guard attached, and org-scopes reads via authz.Scope.
	serviceaccounts.Route(app, db)
	memberships.Route(app, db)

	// TOTP multi-factor enrollment (RFC 6238) — the account security page's
	// initiate/verify/enable/disable flow. After the Guard: self-service on the
	// caller's own user (authz.From); a cross-user reset needs admin (authz.Can).
	mfa.Route(app, db)
}
