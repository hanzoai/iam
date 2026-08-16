// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

func signinDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "signin.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func signinUser(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// The column had no writer, so every row read "never signed in" — which is not
// absent, it is WRONG, and a dormant-account sweep run on it would have retired
// accounts in daily use.
func TestRecordSignin_stampsTheRow(t *testing.T) {
	db := signinDB(t)
	ctx := context.Background()
	signinUser(t, db, "hanzo", "alice")

	before, _ := GetUserByName(ctx, db, "hanzo", "alice")
	if before.LastSigninTime != "" {
		t.Fatalf("a fresh account already carries %q", before.LastSigninTime)
	}

	RecordSignin(ctx, db, "hanzo", "alice")

	after, _ := GetUserByName(ctx, db, "hanzo", "alice")
	if after.LastSigninTime == "" {
		t.Fatal("signing in recorded nothing")
	}
	when, err := time.Parse(time.RFC3339, after.LastSigninTime)
	if err != nil {
		t.Fatalf("recorded %q, which is not a time: %v", after.LastSigninTime, err)
	}
	if d := time.Since(when); d < 0 || d > time.Minute {
		t.Fatalf("recorded %v ago, want now", d)
	}
}

// It MOVES: the value is the last sign-in, not the first.
func TestRecordSignin_moves(t *testing.T) {
	db := signinDB(t)
	ctx := context.Background()
	signinUser(t, db, "hanzo", "alice")

	RecordSignin(ctx, db, "hanzo", "alice")
	first, _ := GetUserByName(ctx, db, "hanzo", "alice")

	// The stamp is second-resolution, so move the stored value back to prove the
	// second write replaces it rather than leaving the first in place.
	back := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
	u, _ := GetUserByName(ctx, db, "hanzo", "alice")
	u.LastSigninTime = back
	if err := u.UpdateCtx(ctx); err != nil {
		t.Fatalf("rewind: %v", err)
	}

	RecordSignin(ctx, db, "hanzo", "alice")
	second, _ := GetUserByName(ctx, db, "hanzo", "alice")
	if second.LastSigninTime == back {
		t.Fatal("the second sign-in did not move the stamp")
	}
	if second.LastSigninTime != first.LastSigninTime {
		// Both writes happen within the same second in a fast test; what matters is
		// that the rewound value was replaced, which the check above proves.
		_ = second
	}
}

// It touches ONLY that column. A sign-in is not an edit of the account.
func TestRecordSignin_touchesNothingElse(t *testing.T) {
	db := signinDB(t)
	ctx := context.Background()
	signinUser(t, db, "hanzo", "alice")

	u, _ := GetUserByName(ctx, db, "hanzo", "alice")
	u.DisplayName, u.Email, u.IsAdmin = "Alice", "alice@example.com", true
	if err := u.UpdateCtx(ctx); err != nil {
		t.Fatalf("seed profile: %v", err)
	}

	RecordSignin(ctx, db, "hanzo", "alice")

	after, _ := GetUserByName(ctx, db, "hanzo", "alice")
	if after.DisplayName != "Alice" || after.Email != "alice@example.com" || !after.IsAdmin {
		t.Fatalf("a sign-in edited the account: %+v", after)
	}
}

// An account that is not there is not an error to the caller — the person has
// signed in either way, and a bookkeeping field must never fail a login.
func TestRecordSignin_isBestEffort(t *testing.T) {
	db := signinDB(t)
	ctx := context.Background()
	RecordSignin(ctx, db, "hanzo", "ghost")
	RecordSignin(ctx, db, "", "")
}
