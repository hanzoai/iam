// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

//go:build migration

// These exercise the drift-gate helpers under the same `migration` tag the tool
// ships with, so legacyDriver here is the real Postgres/MySQL mapping (not the
// stub). The pure helpers need no database; the two count helpers use a throwaway
// store on each side — an orm sqlite store for v2, a database/sql sqlite handle
// standing in for the v1 legacy surface — and Run's setup arms are reached with a
// bad DSN or a cancelled context, the seams that fail before any live server is
// needed. Run's happy path reads a live v1 database and is out of scope here.
package compare

import (
	"context"
	"database/sql"
	"io"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// newV2 opens a throwaway v2 entity store through the ONE store-open path, the
// same shape every other package test uses (store.Open("sqlite", …)).
func newV2(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "v2.db"), "")
	if err != nil {
		t.Fatalf("open v2 store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// newLegacy opens a database/sql sqlite handle standing in for the v1 legacy
// surface — the shape countLegacy reads with a bare SELECT COUNT(*).
func newLegacy(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "v1.db"))
	if err != nil {
		t.Fatalf("open v1 handle: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// cancelled is a context already past its deadline, so a ctx-bound query fails at
// the seam without waiting on a live server.
func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

func TestDsnScheme(t *testing.T) {
	for _, c := range []struct {
		name, dsn, want string
	}{
		{"postgres", "postgres://u:p@h:5432/db", "postgres"},
		{"postgresql normalizes to postgres", "postgresql://h/db", "postgres"},
		{"mysql", "mysql://u@tcp(h:3306)/db", "mysql"},
		{"unknown scheme passes through", "sqlite://x.db", "sqlite"},
		{"no scheme", "user@tcp/db", ""},
		{"empty", "", ""},
		{"separator but empty scheme", "://h/db", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := dsnScheme(c.dsn); got != c.want {
				t.Fatalf("dsnScheme(%q) = %q; want %q", c.dsn, got, c.want)
			}
		})
	}
}

func TestLegacyArg(t *testing.T) {
	for _, c := range []struct {
		name, scheme, dsn, want string
	}{
		{"mysql strips scheme", "mysql", "mysql://u@tcp(h)/db", "u@tcp(h)/db"},
		{"mysql without separator is unchanged", "mysql", "u@tcp(h)/db", "u@tcp(h)/db"},
		{"postgres keeps full url", "postgres", "postgres://u@h/db", "postgres://u@h/db"},
		{"empty scheme is unchanged", "", "raw", "raw"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := legacyArg(c.scheme, c.dsn); got != c.want {
				t.Fatalf("legacyArg(%q, %q) = %q; want %q", c.scheme, c.dsn, got, c.want)
			}
		})
	}
}

func TestCount(t *testing.T) {
	for _, c := range []struct {
		name string
		n    int64
		want string
	}{
		{"absent table is n/a", -1, "n/a"},
		{"any negative is n/a", -7, "n/a"},
		{"zero", 0, "0"},
		{"positive", 42, "42"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := count(c.n); got != c.want {
				t.Fatalf("count(%d) = %q; want %q", c.n, got, c.want)
			}
		})
	}
}

func TestDrift(t *testing.T) {
	for _, c := range []struct {
		name string
		a, b int64
		want string
	}{
		{"equal is zero drift", 5, 5, "0"},
		{"v1 ahead", 5, 2, "3"},
		{"v2 ahead takes absolute value", 2, 5, "3"},
		{"v1 missing is unknown", -1, 5, "?"},
		{"v2 missing is unknown", 5, -1, "?"},
		{"both missing is unknown", -1, -1, "?"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := drift(c.a, c.b); got != c.want {
				t.Fatalf("drift(%d, %d) = %q; want %q", c.a, c.b, got, c.want)
			}
		})
	}
}

func TestLegacyDriver(t *testing.T) {
	for _, c := range []struct {
		scheme     string
		wantDriver string
		wantOK     bool
	}{
		{"postgres", "pgx", true},
		{"mysql", "mysql", true},
		{"sqlite", "", false},
		{"", "", false},
	} {
		t.Run(c.scheme, func(t *testing.T) {
			gotDriver, gotOK := legacyDriver(c.scheme)
			if gotDriver != c.wantDriver || gotOK != c.wantOK {
				t.Fatalf("legacyDriver(%q) = (%q, %v); want (%q, %v)",
					c.scheme, gotDriver, gotOK, c.wantDriver, c.wantOK)
			}
		})
	}
}

func TestCountV2(t *testing.T) {
	db := newV2(t)
	ctx := context.Background()

	if got := countV2(ctx, db, "users"); got != 0 {
		t.Fatalf("countV2 on an empty store = %d; want 0", got)
	}

	for _, id := range []string{"hanzo/alice", "hanzo/bob"} {
		u := orm.New[schema.User](db)
		u.Owner, u.Name = "hanzo", id
		u.SetId(id)
		if err := u.CreateCtx(ctx); err != nil {
			t.Fatalf("seed %s: %v", id, err)
		}
	}
	if got := countV2(ctx, db, "users"); got != 2 {
		t.Fatalf("countV2 after two writes = %d; want 2", got)
	}

	db.Close() // a store that has gone away is an error, reported as -1
	if got := countV2(ctx, db, "users"); got != -1 {
		t.Fatalf("countV2 on a closed store = %d; want -1", got)
	}
}

func TestCountLegacy(t *testing.T) {
	db := newLegacy(t)
	ctx := context.Background()

	if got := countLegacy(ctx, db, "user"); got != -1 {
		t.Fatalf("countLegacy on an absent table = %d; want -1", got)
	}

	if _, err := db.ExecContext(ctx, `CREATE TABLE "user" (id INTEGER)`); err != nil {
		t.Fatalf("create legacy table: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO "user" (id) VALUES (1), (2), (3)`); err != nil {
		t.Fatalf("seed legacy rows: %v", err)
	}
	if got := countLegacy(ctx, db, "user"); got != 3 {
		t.Fatalf("countLegacy over three rows = %d; want 3", got)
	}
}

// Run's setup arms fail before a live v1 server is needed: a DSN with no scheme,
// a scheme this build links no driver for, and a legacy that never answers the
// ping (reached with an already-cancelled context).
func TestRunSetupErrors(t *testing.T) {
	v2 := newV2(t)
	for _, c := range []struct {
		name string
		ctx  context.Context
		dsn  string
	}{
		{"no scheme", context.Background(), "user@tcp/db"},
		{"no driver for scheme in this build", context.Background(), "sqlite://x.db"},
		{"legacy ping fails", cancelled(), "postgres://127.0.0.1:1/db"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := Run(c.ctx, v2, c.dsn, io.Discard); err == nil {
				t.Fatalf("Run(%q) = nil; want a setup error", c.dsn)
			}
		})
	}
}
