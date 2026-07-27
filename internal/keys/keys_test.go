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
