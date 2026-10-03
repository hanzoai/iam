// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

func fileDB(t *testing.T) (orm.DB, string) {
	t.Helper()
	_ = schema.Kinds()
	path := filepath.Join(t.TempDir(), "iam.db")
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   path,
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func putUser(t *testing.T, db orm.DB, owner, name, email string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = owner, name, email
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("create %s/%s: %v", owner, name, err)
	}
}

// stripNameKeys makes the stored rows look as they did before NameKey existed.
func stripNameKeys(t *testing.T, path string) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE _entities SET data = json_remove(data, '$.nameKey') WHERE kind IN ('users', 'memberships')`); err != nil {
		t.Fatalf("strip: %v", err)
	}
}

// A name is found whatever its case, by the indexed key, and a fold that names
// two accounts names neither.
func TestUserByNameFoldsThroughTheIndex(t *testing.T) {
	db, _ := fileDB(t)
	ctx := context.Background()
	putUser(t, db, "acme", "Alice", "")
	putUser(t, db, "acme", "Carol", "")
	putUser(t, db, "acme", "CAROL", "")
	putUser(t, db, "other", "alice2", "")

	if u, err := GetUserByName(ctx, db, "acme", "ALICE"); err != nil || u == nil || u.Name != "Alice" {
		t.Fatalf("ALICE: %v, %v; want Alice", u, err)
	}
	if u, err := GetUserByName(ctx, db, "acme", "nobody@example.com"); err != nil || u != nil {
		t.Fatalf("unknown: %v, %v; want nothing", u, err)
	}
	if u, err := GetUserByName(ctx, db, "acme", "Carol"); err != nil || u == nil || u.Name != "Carol" {
		t.Fatalf("exact Carol: %v, %v", u, err)
	}
	if _, err := GetUserByName(ctx, db, "acme", "cArOl"); err == nil {
		t.Fatal("cArOl folds to two accounts and was answered")
	}
}

// Rows stored before the key existed are found once the backfill has run, the
// backfill runs once per store, and a row saved afterwards needs no backfill.
func TestBackfillKeysOldRowsOnce(t *testing.T) {
	db, path := fileDB(t)
	ctx := context.Background()
	putUser(t, db, "acme", "Erin", "")
	putUser(t, db, "home", "Finn", "finn@example.com")
	if _, err := EnsureMembership(ctx, db, "home/Finn", "shared", "member"); err != nil {
		t.Fatal(err)
	}
	stripNameKeys(t, path)

	if u, _ := GetUserByName(ctx, db, "acme", "ERIN"); u != nil {
		t.Fatal("an old row was found by its key before the backfill: the strip did not take")
	}
	n, err := BackfillNameKeys(ctx, db)
	if err != nil || n < 3 {
		t.Fatalf("backfill wrote %d rows, %v; want users and memberships", n, err)
	}
	if u, err := GetUserByName(ctx, db, "acme", "ERIN"); err != nil || u == nil {
		t.Fatalf("ERIN after backfill: %v, %v", u, err)
	}
	if u, err := MemberByIdentifier(ctx, db, "shared", "FINN"); err != nil || u == nil || u.Name != "Finn" {
		t.Fatalf("FINN on shared's roster after backfill: %v, %v", u, err)
	}
	if n, err := BackfillNameKeys(ctx, db); err != nil || n != 0 {
		t.Fatalf("second backfill wrote %d, %v; want nothing", n, err)
	}
	putUser(t, db, "acme", "Gail", "")
	if u, err := GetUserByName(ctx, db, "acme", "GAIL"); err != nil || u == nil {
		t.Fatalf("a row saved after the backfill is not keyed: %v, %v", u, err)
	}
}

// The indexed member lookup keeps the roster's rules: org-wide rows only, a
// home of the member's own, and two members folding to one name name neither.
func TestMemberByIdentifierKeepsTheRoster(t *testing.T) {
	db, _ := fileDB(t)
	ctx := context.Background()
	putUser(t, db, "home", "Hana", "hana@example.com")
	putUser(t, db, "elsewhere", "Hana", "")
	putUser(t, db, "home", "Ivo", "ivo@example.com")
	putUser(t, db, "two", "Jo", "")
	putUser(t, db, "three", "JO", "")
	for _, m := range [][2]string{{"home/Hana", "shared"}, {"two/Jo", "shared"}, {"three/JO", "shared"}} {
		if _, err := EnsureMembership(ctx, db, m[0], m[1], "member"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := EnsureMembershipIn(ctx, db, "home/Ivo", "shared", "ws1", "", "member"); err != nil {
		t.Fatal(err)
	}

	if u, err := MemberByIdentifier(ctx, db, "shared", "hana"); err != nil || u == nil || u.Owner != "home" {
		t.Fatalf("hana: %v, %v; want home/Hana (elsewhere/Hana is not on the roster)", u, err)
	}
	if u, err := MemberByIdentifier(ctx, db, "shared", "hana@example.com"); err != nil || u == nil || u.Owner != "home" {
		t.Fatalf("by address: %v, %v", u, err)
	}
	if u, err := MemberByIdentifier(ctx, db, "shared", "ivo"); err != nil || u != nil {
		t.Fatalf("a workspace-only member was reached org-wide: %v, %v", u, err)
	}
	if u, err := MemberByIdentifier(ctx, db, "shared", "ivo@example.com"); err != nil || u != nil {
		t.Fatalf("a workspace-only member was reached by address: %v, %v", u, err)
	}
	if _, err := MemberByIdentifier(ctx, db, "shared", "jo"); !errors.Is(err, ErrMemberAmbiguous) {
		t.Fatalf("jo names two members: %v, want ErrMemberAmbiguous", err)
	}
}
