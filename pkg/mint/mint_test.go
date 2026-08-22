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

// seedUser files a user under a subject — the stable opaque Id an OIDC `sub`
// carries, which is a different field from the row key.
func seedUser(t *testing.T, db orm.DB, owner, name, subject string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Id = owner, name, subject
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// This package signs for the user a SUBJECT names, so every subject it cannot
// resolve has to be a refusal. A mint that fell back to a name, or to whichever
// row the storage engine returned first, would hand a caller a token addressing
// a principal it never authorized.
//
// The signing path itself is pinned in internal/oidc, where the mint lives and
// where the cert harness is; what is proved here is the resolution in front of it.
func TestForRefusesEverySubjectItCannotResolve(t *testing.T) {
	db := mintDB(t)
	seedUser(t, db, "acme", "ada", "sub-ada")

	for _, tc := range []struct{ what, subject, app string }{
		{"no subject", "", "console"},
		{"no application", "sub-ada", ""},
		{"unknown subject", "sub-nobody", "console"},
		{"unknown application", "sub-ada", "nosuchapp"},
		// The username is an attribution key, not an identity key. Handing it
		// here must not resolve the row that carries it.
		{"a username in the subject's place", "ada", "console"},
		{"a row key in the subject's place", "acme/ada", "console"},
	} {
		access, _, err := For(context.Background(), db, tc.subject, tc.app, "", "hanzo.id", "/v1/session")
		if err == nil {
			t.Errorf("%s: minted a token", tc.what)
		}
		if access != "" {
			t.Errorf("%s: refused and still returned a token", tc.what)
		}
	}
}

// Two rows sharing one subject name neither in particular. Answering with the
// first would let whoever registered the second be minted as the first.
func TestForFailsClosedOnADuplicatedSubject(t *testing.T) {
	db := mintDB(t)
	seedUser(t, db, "acme", "ada", "sub-shared")
	seedUser(t, db, "globex", "bob", "sub-shared")

	if _, _, err := For(context.Background(), db, "sub-shared", "console", "", "hanzo.id", "/v1/session"); err == nil {
		t.Error("an ambiguous subject minted a token")
	}
}
