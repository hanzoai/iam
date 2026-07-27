// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package keys

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/schema"
)

func memDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "keys.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// F1 write-side gate: keys.create and keys.update must REJECT a Key whose User field
// names a different owner than the key — the row that would let get-user?accessKey
// forge a cross-tenant / SuperAdmin identity can never be persisted. A same-owner or
// bare User is accepted.
func TestKeys_RejectCrossTenantUserOnWrite(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	c := create(db)

	// Cross-tenant qualified User → rejected (attacker in "a" pointing at admin/z).
	if _, err := c(ctx, &schema.Key{Owner: "a", Name: "forge", User: "admin/z"}); err == nil {
		t.Fatal("create accepted a cross-tenant User reference (forgery row)")
	}

	// Same-owner qualified User → accepted.
	ok, err := c(ctx, &schema.Key{Owner: "a", Name: "own", User: "a/alice"})
	if err != nil || ok == nil {
		t.Fatalf("create rejected a same-owner User: %v", err)
	}
	// Bare username → accepted (resolves within the key's own owner).
	if _, err := c(ctx, &schema.Key{Owner: "a", Name: "bare", User: "bob"}); err != nil {
		t.Fatalf("create rejected a bare username: %v", err)
	}

	// update must enforce it too: flipping an existing key's User cross-tenant fails.
	u := update(db)
	if _, err := u(ctx, &schema.Key{Owner: "a", Name: "own", User: "victimorg/ceo"}); err == nil {
		t.Fatal("update accepted a cross-tenant User reference (forgery row)")
	}
	// A same-owner update still works.
	if _, err := u(ctx, &schema.Key{Owner: "a", Name: "own", User: "a/carol"}); err != nil {
		t.Fatalf("update rejected a same-owner User: %v", err)
	}
}

// A publishable key (Scope=publish) mints a pk- publishable half ONLY — never a
// confidential sk- secret — so it can carry no full-access material. A default key
// still mints BOTH halves (its sk- is the reader-authenticating credential).
func TestKeys_PublishableMintsNoSecret(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	c := create(db)

	pub, err := c(ctx, &schema.Key{Owner: "hanzo", Name: "site", Scope: schema.KeyScopePublish})
	if err != nil {
		t.Fatalf("create publish key: %v", err)
	}
	if !strings.HasPrefix(pub.AccessKey, "pk-") {
		t.Fatalf("publish key AccessKey = %q, want a pk-", pub.AccessKey)
	}
	if pub.AccessSecret != "" {
		t.Fatalf("publish key minted a secret %q, want none (write-only)", pub.AccessSecret)
	}

	def, err := c(ctx, &schema.Key{Owner: "hanzo", Name: "server"})
	if err != nil {
		t.Fatalf("create default key: %v", err)
	}
	if !strings.HasPrefix(def.AccessKey, "pk-") || !strings.HasPrefix(def.AccessSecret, "sk-") {
		t.Fatalf("default key halves = %q/%q, want pk-/sk-", def.AccessKey, def.AccessSecret)
	}
}

// A publishable key is write-only even if the caller SUPPLIES a secret: create and
// update both force AccessSecret empty, so a browser key can never carry a confidential
// half for its whole lifecycle.
func TestKeys_PublishableForcesSecretEmpty(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	// Caller tries to smuggle a secret onto a publish key at create.
	pub, err := create(db)(ctx, &schema.Key{
		Owner: "hanzo", Name: "site", Scope: schema.KeyScopePublish,
		AccessKey: "pk-live-CHOSEN", AccessSecret: "sk-live-SMUGGLED",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if pub.AccessSecret != "" {
		t.Fatalf("create let a publish key keep a supplied secret %q", pub.AccessSecret)
	}

	// And again at update — the invariant holds across the key's lifecycle.
	upd, err := update(db)(ctx, &schema.Key{
		Owner: "hanzo", Name: "site", Scope: schema.KeyScopePublish,
		AccessSecret: "sk-live-SMUGGLED2",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if upd.AccessSecret != "" {
		t.Fatalf("update let a publish key gain a secret %q", upd.AccessSecret)
	}
}

// The round-trip that did not exist, and whose absence let a dead credential ship:
// a key minted by mint-user-keys MUST resolve back to the user it was minted for.
//
// It did not. mintUserKeysHandler stamped the sk- onto schema.User.AccessKey, while
// store.UserByAccessKey's sk- branch reads schema.Key.AccessSecret — the write and
// the read never met, so every minted key authenticated nobody. Worse, the write
// landed in the same field as the user's working legacy hk-, so regenerating a key
// locked the holder out with no way back through the UI.
func TestMintUserKey_ResolvesBackToItsUser(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	secret, err := MintUserKey(ctx, db, "acme", "ada")
	if err != nil {
		t.Fatalf("MintUserKey: %v", err)
	}
	if !strings.HasPrefix(secret, "sk-") {
		t.Fatalf("minted secret = %q, want an sk- confidential half", secret[:3])
	}

	// The row the resolver reads must exist, name its user, and hold the secret.
	k, err := orm.TypedQuery[schema.Key](db).Filter("AccessSecret=", secret).First()
	if err != nil || k == nil {
		t.Fatalf("no schema.Key row resolves the minted secret (err=%v) — this is the bug", err)
	}
	if k.User != "ada" || k.Owner != "acme" {
		t.Fatalf("key resolves to %s/%s, want acme/ada", k.Owner, k.User)
	}
	if !strings.HasPrefix(k.AccessKey, "pk-") {
		t.Fatalf("publishable half = %q, want pk-", k.AccessKey)
	}
	if k.Scope == schema.KeyScopePublish {
		t.Fatal("a user's authenticating key must NOT be publish-scoped")
	}
}

// Re-minting REPLACES the credential rather than leaving a second live secret: a
// user holds one key, so revoking it revokes them.
func TestMintUserKey_RemintReplacesRatherThanAccumulates(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	first, err := MintUserKey(ctx, db, "acme", "ada")
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	second, err := MintUserKey(ctx, db, "acme", "ada")
	if err != nil {
		t.Fatalf("re-mint: %v", err)
	}
	if first == second {
		t.Fatal("re-mint returned the same secret; it must rotate")
	}
	if old, _ := orm.TypedQuery[schema.Key](db).Filter("AccessSecret=", first).First(); old != nil {
		t.Fatal("the superseded secret still resolves — a revoked key would stay live")
	}
	if cur, err := orm.TypedQuery[schema.Key](db).Filter("AccessSecret=", second).First(); err != nil || cur == nil {
		t.Fatalf("the current secret does not resolve: %v", err)
	}
}

// Revoke is a statement about the END state: after it, the user holds nothing, and
// revoking again is still success (a caller may always assert "holds no credential").
func TestRevokeUserKey_EndStateAndIdempotent(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	secret, err := MintUserKey(ctx, db, "acme", "ada")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := RevokeUserKey(ctx, db, "acme"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if k, _ := orm.TypedQuery[schema.Key](db).Filter("AccessSecret=", secret).First(); k != nil {
		t.Fatal("secret still resolves after revoke")
	}
	if err := RevokeUserKey(ctx, db, "acme"); err != nil {
		t.Fatalf("revoke on an already-revoked user must succeed, got %v", err)
	}
}
