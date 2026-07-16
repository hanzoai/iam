// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package routes mounts the IAM v2 HTTP surface on a zip App.
//
// Authentication is STRUCTURAL, decided by which group a route is registered on,
// never by a hand-maintained path list. Mount wires the surface in two phases
// around one authentication seam:
//
//   - the PUBLIC group (oidc.Route + /healthz) is registered FIRST, before the
//     Guard. A matched public route terminates fiber's middleware walk, so the
//     Guard never runs on it — membership in this group IS "public".
//   - app.Use(authz.Guard) is the ONE authentication seam. Every route registered
//     AFTER it — the typed entity CRUD, the Casdoor verb aliases, the SCIM
//     surface, and the framework's own /mcp + /openapi projections — requires a
//     verified bearer.
//
// A public route therefore can never be accidentally gated, and an authed route
// can never be accidentally public: the decision is where you register, not an
// allow-list that can drift out of sync with the routes.
package routes

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/applications"
	"github.com/hanzoai/iam2/internal/auditlogs"
	"github.com/hanzoai/iam2/internal/authz"
	"github.com/hanzoai/iam2/internal/certs"
	"github.com/hanzoai/iam2/internal/compat"
	"github.com/hanzoai/iam2/internal/invitations"
	"github.com/hanzoai/iam2/internal/keys"
	"github.com/hanzoai/iam2/internal/oidc"
	"github.com/hanzoai/iam2/internal/organizations"
	"github.com/hanzoai/iam2/internal/permission"
	"github.com/hanzoai/iam2/internal/providers"
	"github.com/hanzoai/iam2/internal/roles"
	"github.com/hanzoai/iam2/internal/scim"
	"github.com/hanzoai/iam2/internal/sessions"
	"github.com/hanzoai/iam2/internal/tokens"
	"github.com/hanzoai/iam2/internal/users"
	"github.com/hanzoai/iam2/internal/webauthn"
)

// Route registers the whole IAM v2 route surface on app, threading the entity
// store db into every handler. This is the route table server.Mount embeds — the
// one Mount(app, db) is the public entry; everything below is Route.
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
	public := app.Group("")
	public.Get("/healthz", health)
	oidc.Route(public, db)

	// ─────────────────────────── GUARD ────────────────────────────
	// The ONE authentication seam. Every route registered AFTER it requires a
	// verified bearer — the typed entity CRUD below, the Casdoor verb aliases, the
	// SCIM surface, and the framework's own /mcp + /openapi projections (added at
	// Prepare). The resolved Principal rides the request context for the write-authz
	// hook above; reads are authorized here (their target rides the query string, or
	// the handler scopes a path target itself). Fails closed (401).
	app.Use(authz.Guard(db))

	// ─────────────────────────── AUTHED ───────────────────────────
	// Typed entity CRUD. Each registers its typed ops on app (the projection into
	// REST + OpenAPI + MCP needs *App); registered after the Guard, so all are
	// gated.
	users.Route(app, db)
	organizations.Route(app, db)
	applications.Route(app, db)
	providers.Route(app, db)
	roles.Route(app, db)
	permission.Route(app, db)
	certs.Route(app, db)
	keys.Route(app, db)
	webauthn.Route(app, db)
	sessions.Route(app, db)
	tokens.Route(app, db)
	auditlogs.Route(app, db)
	invitations.Route(app, db)

	// Casdoor verb-alias layer: the get-users / get-organizations / add-organization
	// / … spellings (in the v1 {status,data,data2} envelope) every live console/
	// gateway/portal client hard-codes, served over the SAME store, redaction, and
	// authz as the REST surface above — the transparent backend swap. After the
	// Guard, so it shares the one Guard/Authorize seam.
	compat.Route(app, db)

	// SCIM 2.0 (RFC 7644/7643) — the STANDARD identity-provisioning surface that
	// replaces the Casdoor entity verbs (HIP-0111). After the Guard, so it is
	// authenticated; each handler owner-scopes via authz.Scope on the path target.
	scim.Route(app, db)
}

// health is the Phase-1 liveness probe.
func health(c *zip.Ctx) error {
	return c.JSON(200, map[string]string{
		"status": "ok",
		"phase":  "1",
		"binary": "iam2",
	})
}
