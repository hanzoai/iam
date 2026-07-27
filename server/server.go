// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package server is the PUBLIC embedding surface of iam2: a host binary (cloud)
// imports this and registers the full IAM v2 HTTP surface onto its own zip app,
// over its own orm.DB. This is how iam2 goes live embedded in hanzoai/cloud
// without a separate pod — the same multi-mode pattern cloud already uses for
// the Casdoor iamserver, but zip-native and lean.
//
// SHADOW-FIRST: the caller decides the route prefix. Registered under a shadow
// prefix (e.g. /v2-iam) iam2 runs ALONGSIDE the live Casdoor /v1/iam/* with zero
// impact; only once verified against real traffic does the host flip iam2 onto
// the canonical /v1/iam/* paths. Never blind-replace live auth.
package server

import (
	"context"
	"net/http"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/fiber/v3/middleware/adaptor"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/feature"
	"github.com/hanzoai/iam/internal/featurestore"
	"github.com/hanzoai/iam/internal/routes"
	_ "github.com/hanzoai/iam/internal/schema" // registers the entity kinds
	"github.com/hanzoai/iam/internal/seed"
)

// Route registers the entire IAM v2 surface (OIDC discovery/JWKS, get-app-login,
// auth/methods, token, login, and the v2 entity CRUD) onto app, backed by db.
// This is the one call a host binary makes to embed iam2.
func Route(app *zip.App, db orm.DB) {
	routes.Route(app, db)
	// Enterprise features (hanzoai/iam2/feature — SCIM/SAML/LDAP live in the
	// hanzoiam/* modules and Register themselves). No-op until a host registers
	// one; fail-fast if a registered module cannot register (a boot misconfiguration).
	if err := feature.RouteAll(app, featurestore.New(db)); err != nil {
		panic("iam2: enterprise feature registration failed: " + err.Error())
	}
}

// NewApp builds a STANDALONE iam2 zip.App over db — the whole IAM v2 surface
// registered and Prepared as one self-contained app. A host that registers iam2 as a
// wildcard sub-handler (app.All("/v1/iam/*", zip.AdaptNetHTTP(h))) rather than
// co-mingling iam2's routes onto its own app uses this together with Handler; the
// caller owns the returned app's Shutdown.
func NewApp(db orm.DB) *zip.App {
	app := zip.New(zip.Config{AppName: "iam2", DisableStartupMessage: true})
	Route(app, db)
	app.Prepare()
	return app
}

// Handler adapts a standalone iam2 app (NewApp) to a net/http handler, so a host
// router serves the whole IAM v2 surface behind ONE wildcard route. This is the
// drop-in shape hanzoai/cloud uses to swap the legacy Beego IAM catch-all for
// iam2: registered at the /v1/iam/* (and root /.well-known/*) wildcards, the
// specific self-service routes layered in front still win by Fiber specificity,
// so the swap is collision-free — the same topology the Beego catch-all had.
func Handler(db orm.DB) http.Handler {
	return adaptor.FiberApp(NewApp(db).Fiber())
}

// OpenSQLite opens an embedded SQLite store for iam2 at path (WAL). The host may
// instead pass its own orm.DB (e.g. hanzoai/sql over ZAP) to Route.
func OpenSQLite(path string) (orm.DB, error) {
	return orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   path,
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
}

// Seed bootstraps the config (orgs/apps/providers/certs) from an init_data.json
// path — the same file Casdoor uses. New-only + idempotent; ${VAR} from env.
// Returns the created/skipped counts. Call once at host startup after opening db.
func Seed(ctx context.Context, db orm.DB, initDataPath string) (*seed.Summary, error) {
	return seed.FromInitData(ctx, db, initDataPath)
}
