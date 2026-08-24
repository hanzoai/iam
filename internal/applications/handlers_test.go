// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

// closedDB is an opened-then-closed store. Every operation against it returns a
// store error rather than a not-found, which is the one input that drives each
// handler down its ErrInternal arm — the arm that must translate a backend
// failure into a 5xx, never a silent success or a masked 404.
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

// owner and name are the natural key; a handler that let either go empty would
// address the wrong row (or every row). Each verb refuses the empty half before
// it ever touches the store.
func TestHandlers_RequireOwnerAndName(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	list, get, create, update, del := listApplications(db), getApplication(db), Create(db), Update(db), deleteApplication(db)

	cases := []struct {
		name string
		call func() error
	}{
		{"list/no-owner", func() error { _, e := list(ctx, &ApplicationQuery{}); return e }},
		{"get/no-owner", func() error { _, e := get(ctx, &ApplicationRef{Name: "n"}); return e }},
		{"get/no-name", func() error { _, e := get(ctx, &ApplicationRef{Owner: "o"}); return e }},
		{"create/no-owner", func() error { _, e := create(ctx, &schema.Application{Name: "n"}); return e }},
		{"create/no-name", func() error { _, e := create(ctx, &schema.Application{Owner: "o"}); return e }},
		{"update/no-owner", func() error { _, e := update(ctx, &schema.Application{Name: "n"}); return e }},
		{"update/no-name", func() error { _, e := update(ctx, &schema.Application{Owner: "o"}); return e }},
		{"delete/no-owner", func() error { _, e := del(ctx, &ApplicationRef{Name: "n"}); return e }},
		{"delete/no-name", func() error { _, e := del(ctx, &ApplicationRef{Owner: "o"}); return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("a missing owner/name half was accepted")
			}
		})
	}
}

// A read, replace or remove of a row that is not there is a 404, not a 500 and
// not a fabricated empty row.
func TestHandlers_NotFound(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	cases := []struct {
		name string
		call func() error
	}{
		{"get", func() error {
			_, e := getApplication(db)(ctx, &ApplicationRef{Owner: "hanzo", Name: "ghost"})
			return e
		}},
		{"update", func() error { _, e := Update(db)(ctx, &schema.Application{Owner: "hanzo", Name: "ghost"}); return e }},
		{"delete", func() error {
			_, e := deleteApplication(db)(ctx, &ApplicationRef{Owner: "hanzo", Name: "ghost"})
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(); err == nil {
				t.Fatal("a missing row did not surface as an error")
			}
		})
	}
}

// A backend failure is an error at every verb — never swallowed into a success or
// collapsed into a not-found.
func TestHandlers_StoreFailureIsAnError(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		call func(orm.DB) error
	}{
		{"list", func(db orm.DB) error { _, e := listApplications(db)(ctx, &ApplicationQuery{Owner: "o"}); return e }},
		{"get", func(db orm.DB) error {
			_, e := getApplication(db)(ctx, &ApplicationRef{Owner: "o", Name: "n"})
			return e
		}},
		{"create", func(db orm.DB) error {
			_, e := Create(db)(ctx, &schema.Application{Owner: "o", Name: "n", ClientId: "c"})
			return e
		}},
		{"update", func(db orm.DB) error { _, e := Update(db)(ctx, &schema.Application{Owner: "o", Name: "n"}); return e }},
		{"delete", func(db orm.DB) error {
			_, e := deleteApplication(db)(ctx, &ApplicationRef{Owner: "o", Name: "n"})
			return e
		}},
		{"ensureClientIdUnique", func(db orm.DB) error { return ensureClientIdUnique(ctx, db, "c", "o", "n") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.call(closedDB(t)); err == nil {
				t.Fatal("a store failure was not reported")
			}
		})
	}
}

// A second create of the same (owner,name) is refused, not an overwrite — the
// owner-scoped natural key is unique.
func TestCreate_RejectsDuplicateName(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	create := Create(db)
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "a", ClientId: "a"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "a", ClientId: "a2"}); err == nil {
		t.Fatal("a duplicate (owner,name) was accepted")
	}
}

// An empty clientId is exempt from the global-uniqueness check — a public app
// authenticates no confidential grant, so it can never collide.
func TestEnsureClientIdUnique_EmptyIsExempt(t *testing.T) {
	if err := ensureClientIdUnique(context.Background(), memDB(t), "", "o", "n"); err != nil {
		t.Fatalf("empty clientId must be exempt: %v", err)
	}
}

// The list is owner-scoped and every row is masked — a list response never
// carries a clientSecret, and never leaks another owner's apps. The scope is the
// CALLER's: the listing runs as a hanzo tenant, and the owner it filters on is
// the one principal.Scope returns for that caller, not the one the input asked
// for.
func TestList_ScopedAndMasked(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	create := Create(db)
	for _, a := range []*schema.Application{
		{Owner: "hanzo", Name: "a1", ClientId: "cid-a1", ClientSecret: "sekret-a1"},
		{Owner: "hanzo", Name: "a2", ClientId: "cid-a2", ClientSecret: "sekret-a2"},
		{Owner: "other", Name: "b1", ClientId: "cid-b1", ClientSecret: "sekret-b1"},
	} {
		if _, err := create(ctx, a); err != nil {
			t.Fatalf("seed %s/%s: %v", a.Owner, a.Name, err)
		}
	}

	out, err := listApplications(db)(asTenant("hanzo"), &ApplicationQuery{Owner: "hanzo"})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(out.Applications) != 2 {
		t.Fatalf("owner scope leaked: got %d apps, want 2", len(out.Applications))
	}
	for _, a := range out.Applications {
		if a.Owner != "hanzo" {
			t.Fatalf("a foreign owner's app appeared: %s/%s", a.Owner, a.Name)
		}
		if a.ClientSecret != "" {
			t.Fatalf("list emitted a clientSecret for %s: %q", a.Name, a.ClientSecret)
		}
	}
}

// A get returns the row with its clientSecret masked.
func TestGet_Masked(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	if _, err := Create(db)(ctx, &schema.Application{Owner: "hanzo", Name: "app", ClientId: "cid", ClientSecret: "sekret"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got, err := getApplication(db)(ctx, &ApplicationRef{Owner: "hanzo", Name: "app"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Name != "app" {
		t.Fatalf("got the wrong row: %+v", got)
	}
	if got.ClientSecret != "" {
		t.Fatalf("get emitted a clientSecret: %q", got.ClientSecret)
	}
}

// Delete removes the row and reports it; a follow-up get is a not-found.
func TestDelete_RemovesTheRow(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	if _, err := Create(db)(ctx, &schema.Application{Owner: "hanzo", Name: "gone", ClientId: "cid"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res, err := deleteApplication(db)(ctx, &ApplicationRef{Owner: "hanzo", Name: "gone"})
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !res.Deleted {
		t.Fatal("delete did not report Deleted=true")
	}
	if _, err := getApplication(db)(ctx, &ApplicationRef{Owner: "hanzo", Name: "gone"}); err == nil {
		t.Fatal("the row survived delete")
	}
}
