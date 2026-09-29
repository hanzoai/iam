// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package superadmin

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The router refuses a non-SuperAdmin before either handler runs, so these
// layers are held to their rule on their own: the handler admits a SuperAdmin
// person and nobody else, the write re-reads the actor's row and admits a live,
// classed SuperAdmin and nobody else, and a store without transactions is
// refused before anything is read.

func status(err error) int {
	var he *zip.HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

func TestPresent_admitsASuperAdminPersonAlone(t *testing.T) {
	for _, c := range []struct {
		name string
		p    *principal.Principal
		want int
	}{
		{"a SuperAdmin with no sign-in", &principal.Principal{Org: "admin", User: "root", Sudo: true}, 401},
		{"an org admin", &principal.Principal{Org: "hanzo", User: "boss", Admin: true}, 403},
		{"a member of the admin org", &principal.Principal{Org: "hanzo", User: "alice", Orgs: map[string]policy.Role{"admin": "admin"}}, 403},
		{"an application", &principal.Principal{Org: "admin", User: "console", Sudo: true, App: &policy.App{Name: "console"}}, 403},
		{"no one", nil, 403},
	} {
		ctx := context.Background()
		if c.p != nil {
			ctx = principal.Bind(ctx, c.p)
		}
		_, _, err := present(ctx, loose(t), "")
		if status(err) != c.want {
			t.Errorf("%s: present = %v, want %d", c.name, err, c.want)
		}
	}
}

func TestStanding_readsTheActorsRow(t *testing.T) {
	db := loose(t)
	ctx := context.Background()
	for _, u := range []struct {
		owner, name, kind string
		forbidden         bool
	}{
		{"admin", "root", "normal-user", false},
		{"admin", "typeless", "", false},
		{"admin", "provisioner", schema.ServiceAccount, false},
		{"admin", "gone", "normal-user", true},
		{"hanzo", "boss", "normal-user", false},
	} {
		row := orm.New[schema.User](db)
		row.Owner, row.Name, row.Type, row.IsForbidden = u.owner, u.name, u.kind, u.forbidden
		row.IsAdmin = u.owner == "hanzo"
		row.SetId(u.owner + "/" + u.name)
		if err := row.CreateCtx(ctx); err != nil {
			t.Fatal(err)
		}
	}
	for actor, ok := range map[string]bool{
		"admin/root": true, "genesis": false, "admin/typeless": false, "admin/provisioner": false,
		"admin/gone": false, "hanzo/boss": false, "admin/nobody": false, "admin": false, "": false,
	} {
		err := standing(ctx, db, actor)
		if (err == nil) != ok || (err != nil && status(err) != 403) {
			t.Errorf("standing(%q) = %v", actor, err)
		}
	}
}

func TestWrites_refusedWithoutTransactions(t *testing.T) {
	db := loose(t)
	if _, _, err := appoint(context.Background(), db, "admin/root", "", Target{Owner: "acme", Name: "carol"}, ""); status(err) != 503 {
		t.Errorf("appoint on a store without transactions = %v, want 503", err)
	}
	if err := dismiss(context.Background(), db, "admin/root", "", "zed"); status(err) != 503 {
		t.Errorf("dismiss on a store without transactions = %v, want 503", err)
	}
}

// A store failure is logged and answered as server_error, never echoed.
func TestAnswer_hidesAStoreFailure(t *testing.T) {
	err := answer(errors.New("sqlite: disk I/O error at /var/lib/iam/iam.db"))
	var he *zip.HTTPError
	if !errors.As(err, &he) || he.Status != 500 || he.Error() == "" || containsAny(he.Error(), "sqlite", "/var/lib") {
		t.Fatalf("answer = %v", err)
	}
	if refusal := zip.ErrConflict("admin/x exists"); answer(refusal) != refusal {
		t.Fatal("a refusal was rewritten")
	}
}

func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
	}
	return false
}

// loose is a SQLite store Open did not make, so store.Atomic reads it as having
// no transactions.
func loose(t *testing.T) orm.DB {
	t.Helper()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "loose.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if store.Atomic(db) {
		t.Fatal("a store Open did not make reads as transactional")
	}
	return db
}
