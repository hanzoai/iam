// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keys

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
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
// the read never met, so every minted key authenticated nobody.
func TestMintUserKey_ResolvesBackToItsUser(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	secret, err := MintUserKey(ctx, db, "acme", "ada", "")
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

	first, err := MintUserKey(ctx, db, "acme", "ada", "")
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	second, err := MintUserKey(ctx, db, "acme", "ada", "")
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

	secret, err := MintUserKey(ctx, db, "acme", "ada", "")
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if err := RevokeUserKey(ctx, db, "acme", ""); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if k, _ := orm.TypedQuery[schema.Key](db).Filter("AccessSecret=", secret).First(); k != nil {
		t.Fatal("secret still resolves after revoke")
	}
	if err := RevokeUserKey(ctx, db, "acme", ""); err != nil {
		t.Fatalf("revoke on an already-revoked user must succeed, got %v", err)
	}
}

// A caller must not be able to CHOOSE a key's credential. The sk- half resolves its
// owning user by exact match (store.userOwningKey), so a body that carries one lets
// the sender pick a secret it already knows and then present it as that principal.
// This is a forgery primitive the moment the secret is stored as a digest.
func TestKeys_CallerCannotChooseTheCredential(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	k, err := create(db)(ctx, &schema.Key{
		Owner: "acme", Name: "planted",
		AccessKey:    "pk-live-chosen-by-caller",
		AccessSecret: "sk-live-chosen-by-caller",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if k.AccessSecret == "sk-live-chosen-by-caller" {
		t.Fatal("caller-supplied AccessSecret was persisted — a chosen credential is a forgery")
	}
	if k.AccessKey == "pk-live-chosen-by-caller" {
		t.Fatal("caller-supplied AccessKey was persisted")
	}
	if !strings.HasPrefix(k.AccessSecret, "sk-") || !strings.HasPrefix(k.AccessKey, "pk-") {
		t.Fatalf("both halves must be minted; got key=%q secret-prefix=%q", k.AccessKey, k.AccessSecret[:3])
	}
}

// Scope is the ACCESS CLASS and is fixed at mint. An update that could flip a secret
// key to publish scope would blank its secret and make its pk- half org-resolvable at
// the ingest door — a privilege change wearing the clothes of a profile edit.
func TestKeys_UpdateCannotReScopeOrRotate(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	made, err := create(db)(ctx, &schema.Key{Owner: "acme", Name: "svc"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	secret, access := made.AccessSecret, made.AccessKey

	got, err := update(db)(ctx, &schema.Key{
		Owner: "acme", Name: "svc",
		DisplayName:  "renamed",
		Scope:        schema.KeyScopePublish,
		AccessSecret: "sk-live-attacker",
		AccessKey:    "pk-live-attacker",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.Scope == schema.KeyScopePublish {
		t.Fatal("update re-scoped a secret key to publish — that blanks the secret and opens the ingest door")
	}
	// Assert on the STORED row, not the response: the response is masked (an edit is
	// not a mint), so reading the secret back out of it would only ever prove the mask.
	stored, err := orm.Get[schema.Key](db, "acme/svc")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.AccessSecret != secret || stored.AccessKey != access {
		t.Fatal("update rotated the credential to caller-supplied values")
	}
	if got.AccessSecret != "" {
		t.Fatalf("update echoed the confidential secret %q — the secret is revealed once, by create", got.AccessSecret)
	}
	if got.DisplayName != "renamed" {
		t.Fatalf("update failed to apply a legitimately mutable field: %q", got.DisplayName)
	}
}

// The gap that made a publishable key unmintable: there was NO path anywhere that
// produced one for a user. IAM owned the model (schema.KeyScopePublish), the resolver
// (store.PublishableKeyByAccessKey) and the ingest door (compat resolve-key), and
// nothing minted the credential they were written for — so every surface configured
// its own thing. Type is a field on the ONE mint, and this is the proof it works.
func TestMintUserKey_PublishableTypeMintsAPublicKeyAndNoSecret(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	got, err := MintUserKey(ctx, db, "acme", "ada", schema.KeyScopePublish)
	if err != nil {
		t.Fatalf("MintUserKey(publish): %v", err)
	}
	if !strings.HasPrefix(got, "pk-") {
		t.Fatalf("publishable mint returned %q, want the pk- half — a browser key is the value you ship", got)
	}
	k, err := orm.Get[schema.Key](db, "acme/"+PublishKeyName)
	if err != nil {
		t.Fatalf("no publishable key row: %v", err)
	}
	if k.Scope != schema.KeyScopePublish {
		t.Fatalf("row scope = %q, want %q — the resolver refuses anything else", k.Scope, schema.KeyScopePublish)
	}
	if k.AccessSecret != "" {
		t.Fatalf("a publishable key stored a confidential secret %q — it must have no secret half at all", k.AccessSecret)
	}
	if k.AccessKey != got {
		t.Fatalf("returned %q but stored %q; the value handed out must be the value that resolves", got, k.AccessKey)
	}
	if k.User != "ada" || k.Owner != "acme" {
		t.Fatalf("publishable key filed under %s/%s, want acme/ada", k.Owner, k.User)
	}
}

// The two scopes are two rows, so a user holds both at once and rotating one does not
// touch the other. One row would make "rotate the key in my browser bundle" also sign
// the holder out of their own API.
func TestMintUserKey_ScopesAreIndependentCredentials(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	secret, err := MintUserKey(ctx, db, "acme", "ada", "")
	if err != nil {
		t.Fatalf("mint secret: %v", err)
	}
	pub, err := MintUserKey(ctx, db, "acme", "ada", schema.KeyScopePublish)
	if err != nil {
		t.Fatalf("mint publishable: %v", err)
	}
	if k, _ := orm.TypedQuery[schema.Key](db).Filter("AccessSecret=", secret).First(); k == nil {
		t.Fatal("minting the publishable key destroyed the secret key")
	}

	// Rotating the publishable key leaves the secret key alone…
	pub2, err := MintUserKey(ctx, db, "acme", "ada", schema.KeyScopePublish)
	if err != nil {
		t.Fatalf("re-mint publishable: %v", err)
	}
	if pub2 == pub {
		t.Fatal("re-minting the publishable key did not rotate it")
	}
	if k, _ := orm.TypedQuery[schema.Key](db).Filter("AccessSecret=", secret).First(); k == nil {
		t.Fatal("rotating the publishable key revoked the secret key")
	}
	// …and revoking it likewise.
	if err := RevokeUserKey(ctx, db, "acme", schema.KeyScopePublish); err != nil {
		t.Fatalf("revoke publishable: %v", err)
	}
	if _, err := orm.Get[schema.Key](db, "acme/"+PublishKeyName); err == nil {
		t.Fatal("publishable key survived its own revoke")
	}
	if k, _ := orm.TypedQuery[schema.Key](db).Filter("AccessSecret=", secret).First(); k == nil {
		t.Fatal("revoking the publishable key revoked the secret key — the whole reason they are separate rows")
	}
}

// A key LIST must never carry a confidential secret. Before schema.Key.Mask the list
// handed every reader every sk- in the org verbatim, which meant read AUTHORIZATION
// was standing in for redaction — and so widening who may see their own keys could
// not be done safely. The publishable half survives the mask on purpose: it is the
// value the holder needs, and it authenticates nobody.
func TestKeys_ReadsMaskTheSecretAndKeepThePublishableHalf(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	made, err := create(db)(ctx, &schema.Key{Owner: "acme", Name: "svc", User: "ada"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if made.AccessSecret == "" {
		t.Fatal("create must reveal the secret ONCE, or a minted key is unusable")
	}

	listed, err := list(db)(ctx, &ListRequest{Owner: "acme"})
	if err != nil || len(listed.Keys) != 1 {
		t.Fatalf("list: %v (%d keys)", err, len(listed.Keys))
	}
	if listed.Keys[0].AccessSecret != "" {
		t.Fatalf("list disclosed the confidential secret %q", listed.Keys[0].AccessSecret)
	}
	if listed.Keys[0].AccessKey != made.AccessKey {
		t.Fatalf("list blanked the publishable half (%q); the holder needs it", listed.Keys[0].AccessKey)
	}

	one, err := get(db)(ctx, &Ref{Owner: "acme", Name: "svc"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if one.AccessSecret != "" {
		t.Fatalf("get disclosed the confidential secret %q", one.AccessSecret)
	}
	// And the STORED secret is untouched — the mask is a projection, not a deletion.
	stored, err := orm.Get[schema.Key](db, "acme/svc")
	if err != nil || stored.AccessSecret != made.AccessSecret {
		t.Fatal("masking a read mutated the stored credential")
	}
}
