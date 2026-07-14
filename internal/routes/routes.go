// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package routes mounts the IAM v2 HTTP surface on a zip App.
//
// Phase 1 serves GET /v1/iam/v2/health plus the typed CRUD surface for all
// thirteen identity entities (users, organizations, applications, providers,
// roles, permissions, certs, keys, webauthn credentials, sessions, tokens,
// audit logs, invitations). Each entity owns its own package under internal/;
// every package exposes one uniform entry point — Mount(app, db) — so this
// file is the single place the whole resource surface is wired.
//
// The OIDC/OAuth2 surface (/v1/iam/oauth/*, /v1/iam/.well-known/*) lands in
// Phase 2. The /v1/iam/v2 prefix keeps these routes orthogonal to the live v1
// mount at /v1/iam/* during the transition; it collapses at Phase 5 cutover.
package routes

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/applications"
	"github.com/hanzoai/iam2/internal/auditlogs"
	"github.com/hanzoai/iam2/internal/certs"
	"github.com/hanzoai/iam2/internal/invitations"
	"github.com/hanzoai/iam2/internal/keys"
	"github.com/hanzoai/iam2/internal/oidc"
	"github.com/hanzoai/iam2/internal/organizations"
	"github.com/hanzoai/iam2/internal/permission"
	"github.com/hanzoai/iam2/internal/providers"
	"github.com/hanzoai/iam2/internal/roles"
	"github.com/hanzoai/iam2/internal/sessions"
	"github.com/hanzoai/iam2/internal/tokens"
	"github.com/hanzoai/iam2/internal/users"
	"github.com/hanzoai/iam2/internal/webauthn"
)

// Mount registers every Phase-1 route on app, threading the entity store db
// into each entity's typed CRUD handlers.
func Mount(app *zip.App, db orm.DB) {
	app.Get("/v1/iam/v2/health", health)

	// Phase 2 — the OIDC surface at the canonical /v1/iam/* paths (SDK contract).
	oidc.Mount(app)

	users.Mount(app, db)
	organizations.Mount(app, db)
	applications.Mount(app, db)
	providers.Mount(app, db)
	roles.Mount(app, db)
	permission.Mount(app, db)
	certs.Mount(app, db)
	keys.Mount(app, db)
	webauthn.Mount(app, db)
	sessions.Mount(app, db)
	tokens.Mount(app, db)
	auditlogs.Mount(app, db)
	invitations.Mount(app, db)
}

// health is the Phase-1 liveness probe.
func health(c *zip.Ctx) error {
	return c.JSON(200, map[string]string{
		"status": "ok",
		"phase":  "1",
		"binary": "iam2",
	})
}
