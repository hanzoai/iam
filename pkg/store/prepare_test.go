// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
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

// unkey makes rows look as an older binary leaves them: no nameKey field at all.
// where narrows which rows, as SQL over _entities.
func unkey(t *testing.T, path, where string) {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`UPDATE _entities SET data = json_remove(data, '$.nameKey') WHERE kind IN ('users', 'memberships') AND (` + where + `)`); err != nil {
		t.Fatalf("unkey: %v", err)
	}
}

func member(t *testing.T, db orm.DB, user, org string) {
	t.Helper()
	if _, err := EnsureMembership(context.Background(), db, user, org, "member"); err != nil {
		t.Fatal(err)
	}
}

// The half-keyed store a deploy meets: a legacy Alice with no key beside keyed
// CAROL and Carol; two/jo on shared's roster with no key, three/jo with one.
// Before Prepare the lookups see only the keyed half, which is the bug: a second
// "alice" could register, and "jo" would name three/jo alone. After it, they see
// every row.
func TestPrepareMakesAHalfKeyedStoreWhole(t *testing.T) {
	db, path := fileDB(t)
	ctx := context.Background()
	putUser(t, db, "acme", "Alice", "")
	putUser(t, db, "acme", "CAROL", "")
	putUser(t, db, "acme", "Carol", "")
	putUser(t, db, "two", "jo", "")
	putUser(t, db, "three", "jo", "")
	member(t, db, "two/jo", "shared")
	member(t, db, "three/jo", "shared")
	unkey(t, path, `id = 'acme/Alice' OR json_extract(data, '$.user') = 'two/jo'`)

	if u, _ := GetUserByName(ctx, db, "acme", "ALICE"); u != nil {
		t.Fatal("the unkeyed Alice was found before Prepare: the store is not half keyed")
	}
	if u, err := MemberByIdentifier(ctx, db, "shared", "jo"); err != nil || u == nil || u.Owner != "three" {
		t.Fatalf("before Prepare, jo: %v, %v; want three/jo alone (the bug)", u, err)
	}

	n, err := Prepare(ctx, db)
	if err != nil || n != 2 {
		t.Fatalf("Prepare wrote %d, %v; want Alice and two/jo's membership", n, err)
	}
	if u, err := GetUserByName(ctx, db, "acme", "ALICE"); err != nil || u == nil || u.Name != "Alice" {
		t.Fatalf("ALICE after Prepare: %v, %v", u, err)
	}
	if _, err := GetUserByName(ctx, db, "acme", "cArOl"); err == nil {
		t.Fatal("cArOl folds to two accounts and was answered")
	}
	if _, err := MemberByIdentifier(ctx, db, "shared", "jo"); !errors.Is(err, ErrMemberAmbiguous) {
		t.Fatalf("jo after Prepare: %v; want ErrMemberAmbiguous", err)
	}
	if n, err := Prepare(ctx, db); err != nil || n != 0 {
		t.Fatalf("a second Prepare wrote %d, %v; want nothing", n, err)
	}
}

// More rows than a page: every one is keyed, through several reads.
func TestPrepareKeysPastOnePage(t *testing.T) {
	db, path := fileDB(t)
	ctx := context.Background()
	const users = 3*preparePage + 17
	for i := 0; i < users; i++ {
		putUser(t, db, "acme", fmt.Sprintf("User%04d", i), "")
	}
	for i := 0; i < preparePage+3; i++ {
		member(t, db, fmt.Sprintf("acme/User%04d", i), "shared")
	}
	unkey(t, path, `1 = 1`)

	n, err := Prepare(ctx, db)
	if want := users + preparePage + 3; err != nil || n != want {
		t.Fatalf("Prepare wrote %d, %v; want every user and membership, %d", n, err, want)
	}
	for _, i := range []int{0, preparePage, 2*preparePage + 1, users - 1} {
		name := fmt.Sprintf("USER%04d", i)
		if u, err := GetUserByName(ctx, db, "acme", name); err != nil || u == nil {
			t.Fatalf("%s after Prepare: %v, %v", name, u, err)
		}
	}
	if u, err := MemberByIdentifier(ctx, db, "shared", fmt.Sprintf("user%04d", preparePage+2)); err != nil || u == nil {
		t.Fatalf("a member past the first page: %v, %v", u, err)
	}
}

// A rollback to a binary that does not know the key unkeys what it saves, and the
// roll forward keys it again: Prepare keeps no mark that would skip it.
func TestPrepareKeysAgainAfterARollback(t *testing.T) {
	db, path := fileDB(t)
	ctx := context.Background()
	putUser(t, db, "acme", "Dana", "")
	if _, err := Prepare(ctx, db); err != nil {
		t.Fatal(err)
	}
	unkey(t, path, `id = 'acme/Dana'`) // the rolled-back binary saved Dana
	putUser(t, db, "acme", "Erin", "")
	unkey(t, path, `id = 'acme/Erin'`) // and created Erin
	if n, err := Prepare(ctx, db); err != nil || n != 2 {
		t.Fatalf("Prepare after the roll forward wrote %d, %v; want Dana and Erin", n, err)
	}
	for _, name := range []string{"DANA", "ERIN"} {
		if u, err := GetUserByName(ctx, db, "acme", name); err != nil || u == nil {
			t.Fatalf("%s: %v, %v", name, u, err)
		}
	}
}

// A write that races Prepare is kept: each row is keyed from a fresh read in its
// own transaction, so a field changed in between is not written back.
func TestPrepareKeepsAConcurrentWrite(t *testing.T) {
	db, path := fileDB(t)
	ctx := context.Background()
	const n = 2 * preparePage
	for i := 0; i < n; i++ {
		putUser(t, db, "acme", fmt.Sprintf("u%04d", i), "")
	}
	unkey(t, path, `1 = 1`)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			u, err := GetUserByName(ctx, db, "acme", fmt.Sprintf("u%04d", i))
			if err != nil || u == nil {
				t.Errorf("u%04d: %v, %v", i, u, err)
				return
			}
			u.Bio = "edited"
			if err := u.UpdateCtx(ctx); err != nil {
				t.Errorf("update u%04d: %v", i, err)
				return
			}
		}
	}()
	if _, err := Prepare(ctx, db); err != nil {
		t.Fatal(err)
	}
	wg.Wait()

	for i := 0; i < n; i++ {
		u, err := GetUserByName(ctx, db, "acme", fmt.Sprintf("U%04d", i))
		if err != nil || u == nil {
			t.Fatalf("U%04d not found by its key: %v, %v", i, u, err)
		}
		if u.Bio != "edited" {
			t.Fatalf("u%04d lost the write that raced Prepare", i)
		}
	}
}

// Opening a store prepares it.
func TestOpenPreparesTheStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "iam.db")
	db, err := Open("sqlite", path, "")
	if err != nil {
		t.Fatal(err)
	}
	putUser(t, db, "acme", "Gail", "")
	_ = db.Close()
	unkey(t, path, `1 = 1`)

	db, err = Open("sqlite", path, "")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if u, err := GetUserByName(context.Background(), db, "acme", "GAIL"); err != nil || u == nil {
		t.Fatalf("GAIL after Open: %v, %v", u, err)
	}
}
