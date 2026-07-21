// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/schema"
)

func memDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "iam2test.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// EnsureMembership is the ONE way a membership is made: idempotent on the
// (user, org) pair and never a downgrade, so a routine backfill can neither
// duplicate a row nor quietly strip authority.
func TestEnsureMembership_IdempotentAndNoDowngrade(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	added, err := EnsureMembership(ctx, db, "hanzo/alice", "hanzo", RoleOwner)
	if err != nil || !added {
		t.Fatalf("first ensure: added=%v err=%v", added, err)
	}
	// Same pair again: no new row, and the role is NOT downgraded owner→member.
	added, err = EnsureMembership(ctx, db, "hanzo/alice", "hanzo", RoleMember)
	if err != nil || added {
		t.Fatalf("re-ensure must add nothing: added=%v err=%v", added, err)
	}
	m, err := GetMembership(ctx, db, "hanzo/alice", "hanzo")
	if err != nil || m == nil {
		t.Fatalf("membership vanished: %v", err)
	}
	if m.Role != RoleOwner {
		t.Fatalf("role = %q, want owner — re-ensure downgraded authority", m.Role)
	}
	if m.Owner != MembershipOwner {
		t.Fatalf("owner = %q, want the reserved %q", m.Owner, MembershipOwner)
	}
}

// The two hot lookups: a user's orgs, and an org's roster.
func TestMembershipsByUserAndByOrg(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	for _, m := range []struct{ user, org, role string }{
		{"hanzo/alice", "hanzo", RoleMember},
		{"hanzo/alice", "team-x", RoleAdmin}, // alice also acts in a team org
		{"hanzo/bob", "hanzo", RoleMember},
	} {
		if _, err := EnsureMembership(ctx, db, m.user, m.org, m.role); err != nil {
			t.Fatal(err)
		}
	}

	byUser, err := MembershipsByUser(ctx, db, "hanzo/alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(byUser) != 2 {
		t.Fatalf("alice acts in %d orgs, want 2", len(byUser))
	}

	byOrg, err := MembershipsByOrg(ctx, db, "hanzo")
	if err != nil {
		t.Fatal(err)
	}
	if len(byOrg) != 2 {
		t.Fatalf("hanzo roster = %d, want 2 (alice, bob)", len(byOrg))
	}

	// Empty inputs resolve to nothing, never a table scan.
	if rows, _ := MembershipsByUser(ctx, db, ""); rows != nil {
		t.Fatal("empty user must resolve to no rows")
	}
}

// The boot backfill seeds the HOME-org membership for every user, idempotently.
func TestBackfillMemberships(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	for _, u := range []struct {
		owner, name string
		admin       bool
	}{
		{"hanzo", "alice", false},
		{"hanzo", "boss", true},
	} {
		row := orm.New[schema.User](db)
		row.Owner, row.Name, row.IsAdmin = u.owner, u.name, u.admin
		row.SetId(u.owner + "/" + u.name)
		if err := row.CreateCtx(ctx); err != nil {
			t.Fatal(err)
		}
	}

	created, err := BackfillMemberships(ctx, db)
	if err != nil || created != 2 {
		t.Fatalf("backfill created=%d err=%v, want 2", created, err)
	}
	// An admin's home role is admin; a regular user's is member.
	if m, _ := GetMembership(ctx, db, "hanzo/boss", "hanzo"); m == nil || m.Role != RoleAdmin {
		t.Fatalf("boss home role = %+v, want admin", m)
	}
	if m, _ := GetMembership(ctx, db, "hanzo/alice", "hanzo"); m == nil || m.Role != RoleMember {
		t.Fatalf("alice home role = %+v, want member", m)
	}
	// Idempotent: a second backfill creates nothing.
	if created, _ := BackfillMemberships(ctx, db); created != 0 {
		t.Fatalf("second backfill created %d, want 0", created)
	}
}
