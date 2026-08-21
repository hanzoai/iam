// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package mint

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

func mintDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "mint.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func seedUser(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// This package signs for the user it is NAMED, so every name it cannot resolve
// has to be a refusal. A mint that fell back to "whoever the store returned
// first" would hand one tenant a token for another's user, and the caller — which
// has already authorized a DIFFERENT principal — would have no way to notice.
//
// The signing path itself is pinned in internal/oidc, where the mint lives and
// where the cert harness is; what is proved here is the resolution in front of it.
func TestForRefusesEveryNameItCannotResolve(t *testing.T) {
	db := mintDB(t)
	seedUser(t, db, "acme", "ada")

	for _, tc := range []struct{ what, owner, user, app string }{
		{"no owner", "", "ada", "console"},
		{"no user", "acme", "", "console"},
		{"no application", "acme", "ada", ""},
		{"unknown user", "acme", "nobody", "console"},
		{"unknown application", "acme", "ada", "nosuchapp"},
		// ada is acme's. Asking for globex's ada must not reach acme's row.
		{"another org's user", "globex", "ada", "console"},
	} {
		access, _, err := For(context.Background(), db, tc.owner, tc.user, tc.app, "", "https://hanzo.id", "/v1/sessions")
		if err == nil {
			t.Errorf("%s: minted a token", tc.what)
		}
		if access != "" {
			t.Errorf("%s: refused and still returned a token", tc.what)
		}
	}
}
