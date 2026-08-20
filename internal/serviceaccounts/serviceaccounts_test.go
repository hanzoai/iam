// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package serviceaccounts

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// mint is the security core, and its whole job is that the credential it hands
// out can actually be USED. It writes a schema.Key row — the one place the
// resolver looks — holding the secret's DIGEST and never the secret.
//
// It used to write AccessKey/AccessSecretHash onto the User row instead, and
// nothing reads either: store.UserByAccessKey resolves an sk- through
// schema.Key, and cred.Verify is never called against AccessSecretHash. So every
// service-account key ever minted answered "not recognized" — which reads as
// revoked and was in fact unresolvable from the moment it was issued. This test
// exists to keep that from being true again, so it asserts the RESOLUTION and
// not merely the storage.
func TestMint_IssuesAResolvableCredentialAndStoresNoPlaintext(t *testing.T) {
	ctx, db := context.Background(), memDB(t)
	sa := orm.New[schema.User](db)
	sa.Owner, sa.Name, sa.Type = "hanzo", "hanzo-bot", "service-account"
	sa.SetId("hanzo/hanzo-bot")
	if err := sa.CreateCtx(ctx); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	key, secret, err := mint(ctx, db, sa)
	if err != nil {
		t.Fatal(err)
	}
	if key == "" || secret == "" {
		t.Fatal("mint returned an empty credential")
	}

	// THE POINT: the secret resolves to its own service account.
	u, err := store.UserByAccessKey(ctx, db, secret)
	if err != nil {
		t.Fatalf("the minted secret does not resolve: %v", err)
	}
	if u.Owner != "hanzo" || u.Name != "hanzo-bot" {
		t.Fatalf("resolved %s/%s, want hanzo/hanzo-bot", u.Owner, u.Name)
	}

	// The row holds a digest and no plaintext; the User row holds nothing at all.
	k, err := orm.TypedQuery[schema.Key](db).Filter("AccessSecretDigest=", schema.DigestSecret(secret)).First()
	if err != nil || k == nil {
		t.Fatalf("no key row answers the secret's digest: %v", err)
	}
	if k.AccessSecret != "" {
		t.Fatalf("the key row stored the plaintext secret: %q", k.AccessSecret)
	}
	if sa.AccessSecret != "" || sa.AccessSecretHash != "" || sa.AccessKey != "" {
		t.Fatal("the User row must carry no credential material — nothing resolves it")
	}

	// Rotation replaces: the prior secret stops resolving, the new one starts.
	_, secret2, err := mint(ctx, db, sa)
	if err != nil {
		t.Fatal(err)
	}
	if secret2 == secret {
		t.Fatal("rotation must mint a fresh secret")
	}
	if _, err := store.UserByAccessKey(ctx, db, secret); err == nil {
		t.Fatal("the superseded secret still resolves — a rotated key would stay live")
	}
	if _, err := store.UserByAccessKey(ctx, db, secret2); err != nil {
		t.Fatalf("the rotated secret does not resolve: %v", err)
	}
}

// memDB is a real SQLite the ORM can index, because this test asserts on an
// indexed lookup and a fake would prove nothing about it.
func memDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "sa.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// admin gates every credential MUTATION: a mint-capable app, a SuperAdmin, or an
// admin of the target org itself — never a foreign-org admin, never a read-only
// app, never a regular user.
func TestAdminGate(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-team")
	t.Setenv("IAM_SA_LIST_ALLOWED_APPS", "hanzo-reader")
	for _, c := range []struct {
		name string
		p    *authz.Principal
		org  string
		want bool
	}{
		{"mint-cap app (admin-owned)", &authz.Principal{App: "hanzo-team", AppOwner: "admin"}, "hanzo", true},
		{"tenant-owned mint-named app denied", &authz.Principal{App: "hanzo-team", AppOwner: "evil"}, "hanzo", false},
		{"non-cap app", &authz.Principal{App: "rogue", AppOwner: "admin"}, "hanzo", false},
		{"read-only app cannot mint", &authz.Principal{App: "hanzo-reader", AppOwner: "admin"}, "hanzo", false},
		{"super human", &authz.Principal{Org: "admin", Super: true}, "orgb", true},
		{"org admin own org", &authz.Principal{Org: "hanzo", Admin: true}, "hanzo", true},
		{"org admin foreign org", &authz.Principal{Org: "hanzo", Admin: true}, "orgb", false},
		{"regular human", &authz.Principal{Org: "hanzo"}, "hanzo", false},
		{"nil principal", nil, "hanzo", false},
	} {
		if got := admin(c.p, c.org); got != c.want {
			t.Fatalf("%s: admin(%v,%q) = %v, want %v", c.name, c.p, c.org, got, c.want)
		}
	}
}

// read gates the LIST surface: the mint cap is a superset (any org); the read-only
// cap suffices but ONLY within the org the app's <org>-<app> name binds it to, so
// a leaked reader credential enumerates one tenant and never another.
func TestReadGate_TenantBound(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-team")
	t.Setenv("IAM_SA_LIST_ALLOWED_APPS", "hanzo-reader")
	if !read(&authz.Principal{App: "hanzo-team", AppOwner: "admin"}, "lux") {
		t.Fatal("a mint-cap app may enumerate any org")
	}
	if !read(&authz.Principal{App: "hanzo-reader", AppOwner: "admin"}, "hanzo") {
		t.Fatal("hanzo-reader may list its own tenant")
	}
	if read(&authz.Principal{App: "hanzo-reader", AppOwner: "admin"}, "lux") {
		t.Fatal("hanzo-reader must NOT list lux — a cross-tenant roster leak")
	}
	if read(&authz.Principal{App: "rogue", AppOwner: "admin"}, "hanzo") {
		t.Fatal("an uncapable app must list nothing")
	}
	// A tenant-owned app spoofing an allow-listed NAME reads nothing — the owner-pin
	// denies the capability before the tenant-binding is even consulted.
	if read(&authz.Principal{App: "hanzo-reader", AppOwner: "evil"}, "hanzo") {
		t.Fatal("a tenant-owned app named like the reader must NOT enumerate any org")
	}
	if read(&authz.Principal{App: "hanzo-team", AppOwner: "evil"}, "lux") {
		t.Fatal("a tenant-owned app named like the minter must NOT enumerate any org")
	}
}

// canonical maps a request pair to the <org>-<agent> handle and refuses a
// malformed one at the boundary rather than persisting it.
func TestCanonicalAndValid(t *testing.T) {
	if got := canonical("hanzo", "bot"); got != "hanzo-bot" {
		t.Fatalf("a bare agent must be prefixed, got %q", got)
	}
	if got := canonical("hanzo", "hanzo-bot"); got != "hanzo-bot" {
		t.Fatalf("an already-canonical name is kept, got %q", got)
	}
	for _, bad := range []string{"", "bad--name", "-bad", "bad-", "a b"} {
		if canonical("hanzo", bad) != "" {
			t.Fatalf("malformed name %q must be refused", bad)
		}
	}
}
