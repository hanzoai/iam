// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package main

import (
	"context"
	"database/sql"
	"path/filepath"
	"sort"
	"testing"

	"github.com/hanzoai/iam/internal/store"
)

// MEMBERSHIP MIGRATION. migrate-v1 carried no memberships, so a multi-org user's
// `orgs` claim collapsed to the home org alone. Casdoor's `membership` table
// (owner,name,user,org,role) migrates verbatim; store.MemberOrgRefs then
// reproduces the full tenancy set (home ∪ explicit).

// newLegacyMembershipDB builds a legacy iam.db with the organizations, the user,
// and a `membership` table wiring hanzo/z into hanzo, lux, zoo, and pars.
func newLegacyMembershipDB(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "iam.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE organization (owner text, name text, created_time text, display_name text)`,
		`CREATE TABLE user (owner text, name text, created_time text, id text, email text, is_admin integer)`,
		`CREATE TABLE membership (owner text, name text, created_time text, user text, org text, role text)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("create table: %v\n%s", err, s)
		}
	}
	exec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	for _, org := range []string{"hanzo", "lux", "zoo", "pars"} {
		exec(`INSERT INTO organization VALUES(?,?,?,?)`, "admin", org, "2020-01-02T03:04:05Z", org)
	}
	exec(`INSERT INTO user VALUES(?,?,?,?,?,?)`,
		"hanzo", "z", "2020-01-02T03:04:05Z", "uuid-0001", "z@hanzo.ai", 1)
	// Four casdoor membership rows: z acts in hanzo (home), lux, zoo, pars.
	rows := []struct{ org, role string }{
		{"hanzo", "admin"}, {"lux", "member"}, {"zoo", "member"}, {"pars", "owner"},
	}
	for _, r := range rows {
		exec(`INSERT INTO membership VALUES(?,?,?,?,?,?)`,
			"admin", "z|"+r.org, "2020-01-02T03:04:05Z", "hanzo/z", r.org, r.role)
	}
	return path
}

func TestMigrate_Memberships(t *testing.T) {
	ctx := context.Background()
	srcPath := newLegacyMembershipDB(t)

	src, err := sql.Open("sqlite", srcPath)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()

	dst, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam2.db"))
	if err != nil {
		t.Fatalf("open dest: %v", err)
	}
	t.Cleanup(func() { dst.Close() })

	// Migrate in dependency order: orgs, users, then memberships.
	results, err := Migrate(ctx, src, dst, []string{"orgs", "users", "memberships"}, options{})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	byEntity := indexResults(results)

	// N casdoor rows migrate to N clean rows, zero skipped.
	m := byEntity["memberships"]
	if m == nil {
		t.Fatal("memberships entity was not migrated")
	}
	if m.Read != 4 || m.Created != 4 || m.Skipped != 0 {
		t.Fatalf("membership counts = read %d/created %d/skipped %d, want 4/4/0", m.Read, m.Created, m.Skipped)
	}

	// The migrated relation reproduces all four orgs through MemberOrgRefs
	// (home ∪ explicit).
	u, err := store.GetUserByName(ctx, dst, "hanzo", "z")
	if err != nil || u == nil {
		t.Fatalf("user z not migrated: %v", err)
	}
	refs := store.MemberOrgRefs(ctx, dst, u)
	got := make([]string, 0, len(refs))
	for _, r := range refs {
		got = append(got, r.Org)
	}
	sort.Strings(got)
	want := []string{"hanzo", "lux", "pars", "zoo"}
	if len(got) != len(want) {
		t.Fatalf("orgs = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orgs = %v, want %v", got, want)
		}
	}
}

func TestMigrate_Memberships_Idempotent(t *testing.T) {
	ctx := context.Background()
	src, err := sql.Open("sqlite", newLegacyMembershipDB(t))
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()

	dst, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam2.db"))
	if err != nil {
		t.Fatalf("open dest: %v", err)
	}
	t.Cleanup(func() { dst.Close() })

	only := []string{"orgs", "users", "memberships"}
	if _, err := Migrate(ctx, src, dst, only, options{}); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	results, err := Migrate(ctx, src, dst, only, options{})
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	m := indexResults(results)["memberships"]
	if m.Created != 0 || m.Updated != 0 || m.Read != m.Unchanged {
		t.Errorf("re-run not idempotent: created=%d updated=%d read=%d unchanged=%d",
			m.Created, m.Updated, m.Read, m.Unchanged)
	}
}
