// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package server is the PUBLIC embedding surface of iam: a host binary (cloud)
// imports this and registers the full IAM HTTP surface onto its own zip app,
// over its own orm.DB. This is how iam goes live embedded in hanzoai/cloud
// without a separate pod.
//
// The caller decides the route prefix. It is normally the canonical /v1/iam/*;
// a shadow prefix still works if a host wants to stand a second instance up
// beside the live one before moving traffic.
package server

import (
	"context"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/feature"
	"github.com/hanzoai/iam/internal/featurestore"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/seed"
	_ "github.com/hanzoai/iam/pkg/schema" // registers the entity kinds
)

// Route registers the entire IAM surface (OIDC discovery/JWKS, get-app-login,
// auth/methods, token, login, and the v2 entity CRUD) onto app, backed by db.
// This is the one call a host binary makes to embed iam.
func Route(app *zip.App, db orm.DB) {
	routes.Route(app, db)
	// Enterprise features (hanzoai/iam/feature — SAML and LDAP live in the
	// hanzoiam/* modules and Register themselves; SCIM is core, registered above by
	// routes.Route). No-op until a host registers one; fail-fast if a registered
	// module cannot register (a boot misconfiguration).
	if err := feature.RouteAll(app, featurestore.New(db)); err != nil {
		panic("iam: enterprise feature registration failed: " + err.Error())
	}
}

// NewApp builds a STANDALONE iam zip.App over db — the whole IAM surface
// registered as one self-contained app. It is what a host GRAFTS:
//
//	app.Graft(iamserver.NewApp(db))
//
// zip.Graft composes the app in process — the host's router learns iam's route
// patterns and its OP REGISTRY, while iam's own router keeps iam's behaviour
// (its Use chain, its Guard, its error handler). The caller owns the returned
// app's Shutdown; a Graft adopts it.
//
// Prepare renders iam's OWN document, tool list and call plane onto iam's own
// control plane. A graft does not adopt those — a zip Declaration excludes the
// control plane, so the host keeps its own /docs, MCP door and op plane and the
// composed document is the HOST's.
//
// There is no net/http adaptation any more. Handler() used to exist for a host
// that hung the whole surface on one wildcard, and it went through
// adaptor.FiberApp: the App went in, an http.Handler came out, and iam's 94
// typed ops went with it — invisible to the host's OpenAPI document, MCP tool
// list, CLI and call plane. A host published a wildcard where 94 typed
// operations were. Graft is the composition that keeps them.
func NewApp(db orm.DB) *zip.App {
	app := zip.New(zip.Config{AppName: "iam", DisableStartupMessage: true})
	Route(app, db)
	app.Prepare()
	return app
}

// OpenSQLite opens an embedded SQLite store for iam at path (WAL). The host may
// instead pass its own orm.DB (e.g. hanzoai/sql over ZAP) to Route.
func OpenSQLite(path string) (orm.DB, error) {
	return orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   path,
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
}

// Seed bootstraps the config (orgs/apps/providers/certs) from an init_data.json
// path — the same file the legacy surface uses. New-only + idempotent; ${VAR} from env.
// Returns the created/skipped counts. Call once at host startup after opening db.
func Seed(ctx context.Context, db orm.DB, initDataPath string) (*seed.Summary, error) {
	return seed.FromInitData(ctx, db, initDataPath)
}
