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
)

// The router refuses a non-SuperAdmin before either handler runs, so these two
// layers are held to their rule on their own: the handler admits a SuperAdmin
// person and nobody else, and the write re-reads the actor's row and admits a
// live SuperAdmin or Genesis on an empty directory and nobody else.

func forbidden(err error) bool {
	var he *zip.HTTPError
	return errors.As(err, &he) && he.Status == 403
}

func TestSudo_admitsASuperAdminPersonAlone(t *testing.T) {
	for _, c := range []struct {
		name string
		p    *principal.Principal
		ok   bool
	}{
		{"a SuperAdmin", &principal.Principal{Org: "admin", User: "root", Sudo: true}, true},
		{"an org admin", &principal.Principal{Org: "hanzo", User: "boss", Admin: true}, false},
		{"a member of the admin org", &principal.Principal{Org: "hanzo", User: "alice", Orgs: map[string]policy.Role{"admin": "admin"}}, false},
		{"an application", &principal.Principal{Org: "admin", User: "console", Sudo: true, App: &policy.App{Name: "console"}}, false},
		{"no one", nil, false},
	} {
		ctx := context.Background()
		if c.p != nil {
			ctx = principal.Bind(ctx, c.p)
		}
		_, err := sudo(ctx)
		if (err == nil) != c.ok || (err != nil && !forbidden(err)) {
			t.Errorf("%s: sudo = %v", c.name, err)
		}
	}
}

func TestStanding_readsTheActorsRow(t *testing.T) {
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "standing.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	if err := standing(ctx, db, "genesis"); err != nil {
		t.Errorf("genesis on an empty directory: %v", err)
	}
	for _, u := range []struct {
		owner, name, kind string
		forbidden         bool
	}{
		{"admin", "root", "", false},
		{"admin", "provisioner", schema.ServiceAccount, false},
		{"admin", "gone", "", true},
		{"hanzo", "boss", "", false},
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
		"admin/root": true, "genesis": false, "admin/provisioner": false, "admin/gone": false,
		"hanzo/boss": false, "admin/nobody": false, "admin": false, "": false,
	} {
		err := standing(ctx, db, actor)
		if (err == nil) != ok || (err != nil && !forbidden(err)) {
			t.Errorf("standing(%q) = %v", actor, err)
		}
	}
}
