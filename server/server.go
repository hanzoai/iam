// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package server is the PUBLIC embedding surface of iam2: a host binary (cloud)
// imports this and mounts the full IAM v2 HTTP surface onto its own zip app,
// over its own orm.DB. This is how iam2 goes live embedded in hanzoai/cloud
// without a separate pod — the same multi-mode pattern cloud already uses for
// the Casdoor iamserver, but zip-native and lean.
//
// SHADOW-FIRST: the caller decides the mount prefix. Mounted under a shadow
// prefix (e.g. /v2-iam) iam2 runs ALONGSIDE the live Casdoor /v1/iam/* with zero
// impact; only once verified against real traffic does the host flip iam2 onto
// the canonical /v1/iam/* paths. Never blind-replace live auth.
package server

import (
	"context"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/feature"
	"github.com/hanzoai/iam2/internal/featurestore"
	"github.com/hanzoai/iam2/internal/routes"
	_ "github.com/hanzoai/iam2/internal/schema" // registers the entity kinds
	"github.com/hanzoai/iam2/internal/seed"
)

// Mount registers the entire IAM v2 surface (OIDC discovery/JWKS, get-app-login,
// auth/methods, token, login, and the v2 entity CRUD) onto app, backed by db.
// This is the one call a host binary makes to embed iam2.
func Mount(app *zip.App, db orm.DB) {
	routes.Mount(app, db)
	// Enterprise features (hanzoai/iam2/feature — SCIM/SAML/LDAP live in the
	// hanzoiam/* modules and Register themselves). No-op until a host registers
	// one; fail-fast if a registered module can't mount (a boot misconfiguration).
	if err := feature.MountAll(app, featurestore.New(db)); err != nil {
		panic("iam2: enterprise feature mount failed: " + err.Error())
	}
}

// OpenSQLite opens an embedded SQLite store for iam2 at path (WAL). The host may
// instead pass its own orm.DB (e.g. hanzoai/sql over ZAP) to Mount.
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
