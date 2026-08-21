// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"path/filepath"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

// closedDB opens a store and shuts it, so every read fails the way a degraded
// store does.
func closedDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "closed.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}
	return db
}

// The answer is spent in both directions: some callers GRANT on a true, others
// REFUSE on it. So an unreadable membership set cannot be folded into a bare
// false — that reads as "ordinary user, go ahead" at every site that refuses, and
// the guard stops guarding exactly when the store is degraded. It has to be
// reported, and it is the caller that decides which way is safe.
func TestAnUnreadableMembershipSetIsNotAnAnswer(t *testing.T) {
	super, err := IsSuperAdmin(context.Background(), closedDB(t), "hanzo", "z")
	if err == nil {
		t.Fatal("a degraded store answered 'not a SuperAdmin' — every caller that refuses on that answer would proceed")
	}
	if super {
		t.Fatal("a degraded store must not answer true either")
	}
}

// The reserved org is answerable without reading anything, so it still answers
// when the store is down — the refusal never depends on a read that can fail.
func TestTheReservedOrgAnswersWithoutTheStore(t *testing.T) {
	super, err := IsSuperAdmin(context.Background(), closedDB(t), policy.AdminOrg, "root")
	if err != nil || !super {
		t.Fatalf("admin/root should answer from its name alone (super=%v err=%v)", super, err)
	}
}

// THE CASE THE HOME ORG CANNOT ANSWER. An operator is someone an existing
// SuperAdmin put IN the reserved org, and most are anchored in a brand org
// because they also do ordinary work there. So the identity is the input, and
// membership is the answer — the same question policy.Claims.Sudo asks of a
// signed token, which is what makes one person an operator everywhere or nowhere.
func TestAnOperatorAnchoredInABrandOrg(t *testing.T) {
	ctx := context.Background()
	db := memDB(t)
	if _, err := EnsureMembership(ctx, db, "hanzo/op", policy.AdminOrg, RoleAdmin); err != nil {
		t.Fatalf("grant: %v", err)
	}

	super, err := IsSuperAdmin(ctx, db, "hanzo", "op")
	if err != nil || !super {
		t.Fatalf("an operator holding a membership in the reserved org is a SuperAdmin (super=%v err=%v)", super, err)
	}

	// The grant is the whole of it: the same org, a different person.
	if super, err := IsSuperAdmin(ctx, db, "hanzo", "coworker"); err != nil || super {
		t.Fatalf("a colleague in the same org inherited the grant (super=%v err=%v)", super, err)
	}

	// And membership of some OTHER org is not membership of the reserved one.
	if _, err := EnsureMembership(ctx, db, "hanzo/sideways", "built-in", RoleAdmin); err != nil {
		t.Fatalf("grant: %v", err)
	}
	if super, err := IsSuperAdmin(ctx, db, "hanzo", "sideways"); err != nil || super {
		t.Fatalf("a membership in built-in answered the reserved-org question (super=%v err=%v)", super, err)
	}
}
