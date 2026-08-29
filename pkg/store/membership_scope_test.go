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
