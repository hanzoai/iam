// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/model"
	"github.com/hanzoai/iam/pkg/store"
	"github.com/hanzoai/iam/server"
)

// addUser writes a user row directly through orm — the store surface is
// deliberately read-only, so a fixture is seeded the way the migrator does
// (orm.New + the "owner/name" id).
func addUser(t *testing.T, db orm.DB, u *model.User) {
	t.Helper()
	row := orm.New[model.User](db)
	model := row.Model
	*row = *u
	row.Model = model
	row.SetId(u.Owner + "/" + u.Name)
	if err := row.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %s/%s: %v", u.Owner, u.Name, err)
	}
}

func emails(us []*model.User) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Email)
	}
	return out
}

// TestGetMailableUsers is the roster contract: an org sees exactly its own
// reachable customers, every unreachable row is excluded, and no credential
// material rides along.
func TestGetMailableUsers(t *testing.T) {
	sdb, err := server.OpenSQLite(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = sdb.Close() }()

	for _, u := range []*model.User{
		{Owner: "hanzo", Name: "ada", Email: "ada@hanzo.ai", DisplayName: "Ada",
			PasswordHash: "$argon2id$v=19$secret", TotpSecret: "SEED", AccessSecretHash: "hk-hash"},
		{Owner: "hanzo", Name: "bob", Email: "bob@hanzo.ai", EmailVerified: true},
		{Owner: "hanzo", Name: "gone", Email: "gone@hanzo.ai", IsDeleted: true},
		{Owner: "hanzo", Name: "banned", Email: "banned@hanzo.ai", IsForbidden: true},
		{Owner: "hanzo", Name: "noaddr", Email: ""},
		{Owner: "acme", Name: "eve", Email: "eve@acme.com"},
	} {
		addUser(t, sdb, u)
	}

	got, err := store.GetMailableUsers(sdb, "hanzo")
	if err != nil {
		t.Fatalf("GetMailableUsers: %v", err)
	}
	// Deleted, forbidden and address-less rows are excluded; acme's user is not visible.
	want := []string{"ada@hanzo.ai", "bob@hanzo.ai"}
	if len(got) != len(want) {
		t.Fatalf("want %v, got %v", want, emails(got))
	}
	for i, w := range want {
		if got[i].Email != w {
			t.Fatalf("want %v, got %v", want, emails(got))
		}
	}

	// TENANT ISOLATION: hanzo's roster can never carry another org's user.
	for _, u := range got {
		if u.Owner != "hanzo" {
			t.Fatalf("tenant leak: roster carried a user owned by %q", u.Owner)
		}
	}

	// REDACTION: credential material must not cross the embed seam.
	ada := got[0]
	if ada.PasswordHash != "" || ada.TotpSecret != "" || ada.AccessSecretHash != "" {
		t.Fatalf("credential material leaked: hash=%q totp=%q accessSecretHash=%q",
			ada.PasswordHash, ada.TotpSecret, ada.AccessSecretHash)
	}
	// The mask returns a COPY: the stored row still authenticates.
	stored, err := store.GetMailableUsers(sdb, "hanzo")
	if err != nil || len(stored) == 0 {
		t.Fatalf("re-read: %v", err)
	}
	if raw, err := orm.Get[model.User](sdb, "hanzo/ada"); err != nil {
		t.Fatalf("raw read: %v", err)
	} else if raw.PasswordHash == "" {
		t.Fatalf("Mask must not blank the STORED digest — login would break")
	}

	// The other org sees only its own.
	acme, err := store.GetMailableUsers(sdb, "acme")
	if err != nil {
		t.Fatalf("GetMailableUsers(acme): %v", err)
	}
	if len(acme) != 1 || acme[0].Email != "eve@acme.com" {
		t.Fatalf("acme roster want [eve@acme.com], got %v", emails(acme))
	}

	// An empty org is REFUSED, never the all-orgs view — that would be a
	// cross-tenant mailing.
	if all, err := store.GetMailableUsers(sdb, ""); err == nil {
		t.Fatalf("empty org must fail closed, got %v", emails(all))
	}
}
