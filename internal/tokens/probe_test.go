// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package tokens

// The item handlers (get/add/update/delete) do not self-authorize — the Guard
// and the op-invoke seam do — so they are driven here directly, the way
// organizations/probe_test.go drives its item API. orm.Get takes no context, so
// a CLOSED db is what turns a read into a 500; CreateCtx/UpdateCtx/DeleteCtx do
// take one, so a CANCELLED context is what turns a write into a 500 while the
// preceding read still finds the seeded row. listTokens is the one auth-coupled
// handler: its authorized listing is proved in authz's scope suite, and the
// refusal it answers when the context carries no principal is the branch that
// belongs to this package.

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func openDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "x.db"), "")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seed(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	tok := orm.New[schema.Token](db)
	tok.Owner, tok.Name = owner, name
	tok.SetId(tokenId(owner, name))
	if err := tok.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

func cancelledCtx() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// A write's key must be present, a read of a row that is not there is not an
// error, and a list with no principal is refused — the arms the addressing test
// never reaches because it only ever drives the happy path.
func TestArms(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name string
		run  func(t *testing.T, db orm.DB)
	}{
		{"add refuses a missing name", func(t *testing.T, db orm.DB) {
			if _, err := addToken(db)(ctx, &schema.Token{Owner: "acme"}); err == nil {
				t.Fatal("want an error for an empty name")
			}
		}},
		{"add refuses a missing owner", func(t *testing.T, db orm.DB) {
			if _, err := addToken(db)(ctx, &schema.Token{Name: "nightly"}); err == nil {
				t.Fatal("want an error for an empty owner")
			}
		}},
		{"update refuses a missing key", func(t *testing.T, db orm.DB) {
			if _, err := updateToken(db)(ctx, &schema.Token{}); err == nil {
				t.Fatal("want an error for an empty owner/name")
			}
		}},
		{"update of a missing row changes nothing", func(t *testing.T, db orm.DB) {
			out, err := updateToken(db)(ctx, &schema.Token{Owner: "acme", Name: "ghost"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out.Affected {
				t.Fatal("a missing row must report affected=false")
			}
		}},
		{"delete of a missing row changes nothing", func(t *testing.T, db orm.DB) {
			out, err := deleteToken(db)(ctx, &tokenKey{Owner: "acme", Name: "ghost"})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if out.Affected {
				t.Fatal("a missing row must report affected=false")
			}
		}},
		{"list refuses a request carrying no principal", func(t *testing.T, db orm.DB) {
			if _, err := listTokens(db)(ctx, &listTokensIn{}); err == nil {
				t.Fatal("want a refusal when the context carries no principal")
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) { c.run(t, openDB(t)) })
	}
}

// A read reaches its 500 arm on a closed db, because orm.Get takes no context
// and so cannot be failed any other way.
func TestReadFailsClosed(t *testing.T) {
	ctx := context.Background()
	db := openDB(t)
	seed(t, db, "acme", "nightly")
	_ = db.Close()

	cases := []struct {
		name string
		err  func() error
	}{
		{"get", func() error { _, err := getToken(db)(ctx, &tokenKey{Owner: "acme", Name: "nightly"}); return err }},
		{"update", func() error {
			_, err := updateToken(db)(ctx, &schema.Token{Owner: "acme", Name: "nightly"})
			return err
		}},
		{"delete", func() error { _, err := deleteToken(db)(ctx, &tokenKey{Owner: "acme", Name: "nightly"}); return err }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.err() == nil {
				t.Fatal("want a 500 when the read runs on a closed db")
			}
		})
	}
}

// A write reaches its 500 arm on a cancelled context, while the preceding
// orm.Get (which takes none) still finds the seeded row.
func TestWriteFailsOnCancelledCtx(t *testing.T) {
	cctx := cancelledCtx()

	t.Run("add", func(t *testing.T) {
		db := openDB(t)
		if _, err := addToken(db)(cctx, &schema.Token{Owner: "acme", Name: "nightly"}); err == nil {
			t.Fatal("want a 500 when the create context is cancelled")
		}
	})
	t.Run("update", func(t *testing.T) {
		db := openDB(t)
		seed(t, db, "acme", "nightly")
		if _, err := updateToken(db)(cctx, &schema.Token{Owner: "acme", Name: "nightly"}); err == nil {
			t.Fatal("want a 500 when the update context is cancelled")
		}
	})
	t.Run("delete", func(t *testing.T) {
		db := openDB(t)
		seed(t, db, "acme", "nightly")
		if _, err := deleteToken(db)(cctx, &tokenKey{Owner: "acme", Name: "nightly"}); err == nil {
			t.Fatal("want a 500 when the delete context is cancelled")
		}
	})
}
