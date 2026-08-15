// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"path/filepath"
	"testing"

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
	super, err := IsSuperAdmin(context.Background(), closedDB(t), AdminOrg, "root")
	if err != nil || !super {
		t.Fatalf("admin/root should answer from its name alone (super=%v err=%v)", super, err)
	}
}
