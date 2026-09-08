// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func scopedDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "iam.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// One user holds a separate grant at each scope. Without a scope in the key the
// second write would find the first and do nothing, so a workspace roster could
// never differ from the org's.
func TestMembershipIsPerScope(t *testing.T) {
	db := scopedDB(t)
	ctx := context.Background()

	for _, c := range []struct{ ws, proj, role string }{
		{"", "", "member"},
		{"studio", "", "admin"},
		{"studio", "atlas", "owner"},
	} {
		created, err := store.EnsureMembershipIn(ctx, db, "hanzo/ann", "hanzo", c.ws, c.proj, c.role)
		if err != nil {
			t.Fatalf("ensure %+v: %v", c, err)
		}
		if !created {
			t.Fatalf("scope %q/%q did not create a row — the key ignores the scope", c.ws, c.proj)
		}
	}

	for _, c := range []struct{ ws, proj, want string }{
		{"", "", "member"},
		{"studio", "", "admin"},
		{"studio", "atlas", "owner"},
	} {
		got, err := store.MembershipIn(ctx, db, "hanzo/ann", "hanzo", c.ws, c.proj)
		if err != nil || got == nil {
			t.Fatalf("read %q/%q: %v", c.ws, c.proj, err)
		}
		if got.Role != c.want {
			t.Errorf("scope %q/%q role = %q, want %q", c.ws, c.proj, got.Role, c.want)
		}
	}
}

// Re-ensuring is idempotent and never downgrades — the property EnsureMembership
// already had, held at a scope.
func TestScopedEnsureNeverDowngrades(t *testing.T) {
	db := scopedDB(t)
	ctx := context.Background()
	if _, err := store.EnsureMembershipIn(ctx, db, "hanzo/ann", "hanzo", "studio", "", "owner"); err != nil {
		t.Fatalf("ensure: %v", err)
	}
	created, err := store.EnsureMembershipIn(ctx, db, "hanzo/ann", "hanzo", "studio", "", "member")
	if err != nil {
		t.Fatalf("re-ensure: %v", err)
	}
	if created {
		t.Fatal("re-ensuring created a second row")
	}
	got, _ := store.MembershipIn(ctx, db, "hanzo/ann", "hanzo", "studio", "")
	if got == nil || got.Role != "owner" {
		t.Errorf("role = %v, want owner — a re-ensure stripped authority", got)
	}
}

// A project scope without a workspace is refused: it names a place that cannot
// exist, and accepting it would file the grant somewhere nothing reads.
func TestProjectScopeNeedsAWorkspace(t *testing.T) {
	db := scopedDB(t)
	if _, err := store.EnsureMembershipIn(context.Background(), db, "hanzo/ann", "hanzo", "", "atlas", "member"); err == nil {
		t.Fatal("a project grant with no workspace was accepted")
	}
}

// seed a user of the given type so Seats can classify it.
func seedPerson(t *testing.T, db orm.DB, owner, name, typ string, deleted bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Type, u.IsDeleted = owner, name, typ, deleted
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

// A person in three workspaces is ONE seat. Counting rows would bill them three
// times, which is the whole reason this counts distinct users.
func TestSeatsCountsAPersonOnce(t *testing.T) {
	db := scopedDB(t)
	ctx := context.Background()
	seedPerson(t, db, "hanzo", "ann", "normal-user", false)

	for _, ws := range []string{"", "studio", "atlas"} {
		if _, err := store.EnsureMembershipIn(ctx, db, "hanzo/ann", "hanzo", ws, "", "member"); err != nil {
			t.Fatalf("ensure %q: %v", ws, err)
		}
	}
	seats, guests, err := store.Seats(ctx, db, "hanzo")
	if err != nil {
		t.Fatalf("seats: %v", err)
	}
	if seats != 1 || guests != 0 {
		t.Fatalf("seats=%d guests=%d, want 1/0 — a person in three scopes was billed more than once", seats, guests)
	}
}

// Machines and disabled accounts are not seats: an org does not pay for its own
// automation, nor for someone who cannot sign in.
func TestSeatsExcludesMachinesAndDisabled(t *testing.T) {
	db := scopedDB(t)
	ctx := context.Background()
	seedPerson(t, db, "hanzo", "ann", "normal-user", false)
	seedPerson(t, db, "hanzo", "bot", schema.ServiceAccount, false)
	seedPerson(t, db, "hanzo", "gone", "normal-user", true)

	for _, u := range []string{"hanzo/ann", "hanzo/bot", "hanzo/gone"} {
		if _, err := store.EnsureMembershipIn(ctx, db, u, "hanzo", "", "", "member"); err != nil {
			t.Fatalf("ensure %s: %v", u, err)
		}
	}
	seats, _, err := store.Seats(ctx, db, "hanzo")
	if err != nil {
		t.Fatalf("seats: %v", err)
	}
	if seats != 1 {
		t.Fatalf("seats = %d, want 1 (ann alone)", seats)
	}
}

// A guest somewhere and a member elsewhere is a MEMBER. Counting them as a guest
// would under-bill.
func TestGuestElsewhereIsStillAMember(t *testing.T) {
	db := scopedDB(t)
	ctx := context.Background()
	seedPerson(t, db, "hanzo", "ann", "normal-user", false)
	seedPerson(t, db, "hanzo", "vic", "normal-user", false)

	if _, err := store.EnsureMembershipIn(ctx, db, "hanzo/ann", "hanzo", "studio", "", "guest"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureMembershipIn(ctx, db, "hanzo/ann", "hanzo", "atlas", "", "member"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureMembershipIn(ctx, db, "hanzo/vic", "hanzo", "studio", "", "guest"); err != nil {
		t.Fatal(err)
	}
	seats, guests, err := store.Seats(ctx, db, "hanzo")
	if err != nil {
		t.Fatalf("seats: %v", err)
	}
	if seats != 2 || guests != 1 {
		t.Fatalf("seats=%d guests=%d, want 2/1 — ann is a member, vic is the only guest", seats, guests)
	}
}
