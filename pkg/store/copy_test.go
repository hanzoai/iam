// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/orm"
)

func copySeedUser(t *testing.T, db orm.DB, owner, name, email string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = owner, name, email
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %s/%s: %v", owner, name, err)
	}
}

func copySeedToken(t *testing.T, db orm.DB, owner, name, user, hash string) {
	t.Helper()
	tk := orm.New[schema.Token](db)
	tk.Owner, tk.Name, tk.User, tk.AccessTokenHash = owner, name, user, hash
	tk.SetId(owner + "/" + name)
	if err := tk.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed token %s/%s: %v", owner, name, err)
	}
}

func total(rs []CopyReport, f func(CopyReport) int) int {
	n := 0
	for _, r := range rs {
		n += f(r)
	}
	return n
}

// copyRoundTrip copies src to dst three times, changing src between the passes,
// and checks what each pass did and that the stores end the same.
func copyRoundTrip(t *testing.T, src, dst orm.DB) {
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		copySeedUser(t, src, "acme", fmt.Sprintf("u%d", i), fmt.Sprintf("u%d@acme.test", i))
		copySeedToken(t, src, "acme", fmt.Sprintf("t%d", i), fmt.Sprintf("u%d", i), fmt.Sprintf("hash-%d", i))
	}

	rs, err := Copy(ctx, src, dst, false)
	if err != nil {
		t.Fatalf("first copy: %v", err)
	}
	if got := total(rs, func(r CopyReport) int { return r.Written }); got != 6 {
		t.Fatalf("first copy wrote %d records, want 6", got)
	}
	if d, err := Verify(ctx, src, dst); err != nil || len(d) != 0 {
		t.Fatalf("after the first copy: %v %v", err, d)
	}

	// The source changes while it still serves: one record edited, one added,
	// one removed.
	u, err := GetUserByEmail(ctx, src, "acme", "u0@acme.test")
	if err != nil || u == nil {
		t.Fatalf("read u0: %v", err)
	}
	u.DisplayName = "Zero"
	if err := u.UpdateCtx(ctx); err != nil {
		t.Fatalf("edit u0: %v", err)
	}
	copySeedUser(t, src, "acme", "u9", "u9@acme.test")
	gone, err := orm.Get[schema.Token](src, "acme/t2")
	if err != nil {
		t.Fatalf("read t2: %v", err)
	}
	if err := gone.DeleteCtx(ctx); err != nil {
		t.Fatalf("remove t2: %v", err)
	}

	rs, err = Copy(ctx, src, dst, true)
	if err != nil {
		t.Fatalf("second copy: %v", err)
	}
	written := total(rs, func(r CopyReport) int { return r.Written })
	removed := total(rs, func(r CopyReport) int { return r.Removed })
	if written != 2 || removed != 1 {
		t.Fatalf("second copy wrote %d and removed %d, want 2 and 1: %+v", written, removed, rs)
	}
	if d, err := Verify(ctx, src, dst); err != nil || len(d) != 0 {
		t.Fatalf("after the second copy: %v %v", err, d)
	}

	rs, err = Copy(ctx, src, dst, true)
	if err != nil {
		t.Fatalf("third copy: %v", err)
	}
	if w := total(rs, func(r CopyReport) int { return r.Written }); w != 0 {
		t.Fatalf("a copy of an unchanged store wrote %d records", w)
	}

	// The target answers the lookups sign-in makes.
	if u, err := GetUserByEmail(ctx, dst, "acme", "u0@acme.test"); err != nil || u == nil || u.DisplayName != "Zero" {
		t.Fatalf("target email lookup: %v %+v", err, u)
	}
	if tk, err := GetTokenByAccessTokenHash(ctx, dst, "hash-1"); err != nil || tk == nil || tk.User != "u1" {
		t.Fatalf("target token lookup: %v %+v", err, tk)
	}
	if tk, err := GetTokenByAccessTokenHash(ctx, dst, "hash-2"); err != nil || tk != nil {
		t.Fatalf("a token removed at the source is still found at the target: %v %+v", err, tk)
	}
}

func TestCopyMovesAndProvesTheStore(t *testing.T) {
	copyRoundTrip(t, memDB(t), memDB(t))
}

// TestCopyToSQL runs the same round trip into a live hanzoai/sql when
// IAM_SQL_ADDR names one (sql://host:port or host:port). It runs only
// against a server that holds no identity records, and leaves it holding none:
// pointed at a real store by mistake, it refuses rather than copying over it.
func TestCopyToSQL(t *testing.T) {
	addr := os.Getenv("IAM_SQL_ADDR")
	if addr == "" {
		t.Skip("IAM_SQL_ADDR is not set")
	}
	dst, err := Open("sql", "", addr)
	if err != nil {
		t.Fatalf("open sql: %v", err)
	}
	t.Cleanup(func() { _ = dst.Close() })
	ctx := context.Background()
	empty := memDB(t)
	if d, err := Verify(ctx, empty, dst); err != nil || len(d) != 0 {
		t.Fatalf("%s holds %d identity records (%v): point IAM_SQL_ADDR at an empty scratch server", addr, len(d), err)
	}
	t.Cleanup(func() {
		if _, err := Copy(ctx, empty, dst, true); err != nil {
			t.Errorf("leave the server empty: %v", err)
		}
	})
	copyRoundTrip(t, memDB(t), dst)
}

// More users than one page, half carrying a UUID id of their own and half carrying
// none: the walk is by storage key, so every one is copied and the two stores
// verify the same. The id a user's document carries is not its key, so a walk that
// sorted by it and resumed from the key lost its place at the first page.
func TestCopyPastOnePageWithAndWithoutUUIDs(t *testing.T) {
	src, dst := memDB(t), memDB(t)
	ctx := context.Background()
	const n = copyPage + 7
	for i := 0; i < n; i++ {
		u := orm.New[schema.User](src)
		u.Owner, u.Name = "acme", fmt.Sprintf("u%05d", i)
		if i%2 == 0 {
			// A UUID-shaped id that sorts against the storage key in no useful way.
			u.Id = fmt.Sprintf("%08x-0000-4000-8000-%012d", (n-i)*7919, i)
		}
		u.SetId("acme/" + u.Name)
		if err := u.CreateCtx(ctx); err != nil {
			t.Fatal(err)
		}
	}
	reports, err := Copy(ctx, src, dst, false)
	if err != nil {
		t.Fatalf("copy: %v", err)
	}
	for _, r := range reports {
		if r.Kind == "users" && (r.Source != n || r.Written != n) {
			t.Fatalf("users: %+v; want %d read and written", r, n)
		}
	}
	diffs, err := Verify(ctx, src, dst)
	if err != nil || len(diffs) != 0 {
		t.Fatalf("verify: %d diffs (%v), %v", len(diffs), firstDiffs(diffs), err)
	}
	if again, err := Copy(ctx, src, dst, false); err != nil || total(again, func(r CopyReport) int { return r.Written }) != 0 {
		t.Fatalf("a second copy wrote %d, %v", total(again, func(r CopyReport) int { return r.Written }), err)
	}
}

// A record keyed in one store and not yet in the other is the same record.
func TestVerifyIgnoresTheDerivedNameKey(t *testing.T) {
	src, dst := memDB(t), memDB(t)
	ctx := context.Background()
	copySeedUser(t, src, "acme", "Ivy", "")
	if _, err := Copy(ctx, src, dst, false); err != nil {
		t.Fatal(err)
	}
	if _, err := dst.Put(ctx, dst.NewKey("users", "acme/Ivy", 0, nil), json.RawMessage(`{"owner":"acme","name":"Ivy","email":""}`)); err != nil {
		t.Fatal(err)
	}
	var raw json.RawMessage
	_ = src.Get(ctx, src.NewKey("users", "acme/Ivy", 0, nil), &raw)
	var m map[string]any
	_ = json.Unmarshal(raw, &m)
	delete(m, "nameKey")
	plain, _ := json.Marshal(m)
	if _, err := dst.Put(ctx, dst.NewKey("users", "acme/Ivy", 0, nil), json.RawMessage(plain)); err != nil {
		t.Fatal(err)
	}
	if diffs, err := Verify(ctx, src, dst); err != nil || len(diffs) != 0 {
		t.Fatalf("an unkeyed copy of a keyed record differs: %v, %v", diffs, err)
	}
}

func firstDiffs(d []Diff) []Diff {
	if len(d) > 3 {
		return d[:3]
	}
	return d
}
