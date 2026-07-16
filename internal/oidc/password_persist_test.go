// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/password"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
	"github.com/hanzoai/iam2/internal/users"
)

// TestPasswordHashPersists is the regression for the json:"-"-drops-from-storage
// bug: orm serializes an entity to its JSON data column, so a credential field
// tagged json:"-" was never stored → every retrieved user had an empty hash →
// login could never succeed. This proves the hash survives a store round-trip
// and verifies, and that the same holds for AccessSecretHash.
func TestPasswordHashPersists(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret-pw"), bcrypt.MinCost)
	u := orm.New[schema.User](db)
	u.Owner = "hanzo"
	u.Name = "persisttest"
	u.Email = "persist@hanzo.ai"
	u.PasswordHash = string(hash)
	u.PasswordType = "bcrypt"
	u.AccessSecretHash = "access-hash-value"
	if err := u.Create(); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetUserByEmail(ctx, db, "hanzo", "persist@hanzo.ai")
	if err != nil || got == nil {
		t.Fatalf("lookup: %v", err)
	}
	if got.PasswordHash == "" {
		t.Fatal("PasswordHash did not persist — the json:\"-\" storage bug is back")
	}
	if got.AccessSecretHash == "" {
		t.Fatal("AccessSecretHash did not persist")
	}
	// The retrieved hash actually verifies the password.
	if !users.VerifyPassword(ctx, db, got, "s3cret-pw") {
		t.Fatal("persisted hash does not verify the password")
	}
	if users.VerifyPassword(ctx, db, got, "wrong-pw") {
		t.Fatal("wrong password verified — verification broken")
	}
}

// TestLegacyBcryptRowUpgradesOnLogin proves the transparent migration against a
// REAL store: a bcrypt row (40 of these are live today) verifies, is re-minted
// as argon2id in place, and the NEXT login verifies against the new digest.
// Without this, a bcrypt row stays bcrypt forever — nothing else in the system
// ever holds the plaintext to re-hash from.
func TestLegacyBcryptRowUpgradesOnLogin(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	const pw = "legacy-password"
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	u := orm.New[schema.User](db)
	u.Owner = "hanzo"
	u.Name = "legacyuser"
	u.Email = "legacy@hanzo.ai"
	u.PasswordHash = string(hash)
	u.PasswordType = "bcrypt"
	u.PasswordSalt = "a-legacy-v1-salt"
	if err := u.Create(); err != nil {
		t.Fatal(err)
	}

	// First login: verifies under bcrypt, and re-mints.
	got, err := store.GetUserByEmail(ctx, db, "hanzo", "legacy@hanzo.ai")
	if err != nil || got == nil {
		t.Fatalf("lookup: %v", err)
	}
	if !users.VerifyPassword(ctx, db, got, pw) {
		t.Fatal("a live-shaped bcrypt row failed to log in")
	}

	// Re-read from the store: the upgrade must have been PERSISTED, not just
	// applied to the in-memory copy.
	after, err := store.GetUserByEmail(ctx, db, "hanzo", "legacy@hanzo.ai")
	if err != nil || after == nil {
		t.Fatalf("re-read: %v", err)
	}
	if password.Scheme(after.PasswordHash) != password.SchemeArgon2id {
		t.Fatalf("digest not re-minted as argon2id; scheme is %q", password.Scheme(after.PasswordHash))
	}
	if after.PasswordType != password.SchemeArgon2id {
		t.Fatalf("passwordType = %q, want argon2id — the column now contradicts the digest", after.PasswordType)
	}
	if after.PasswordSalt != "" {
		t.Fatal("legacy passwordSalt survived the upgrade — it describes nothing under argon2id")
	}

	// The re-minted digest still authenticates the SAME password — the upgrade
	// must be invisible to the user.
	if !users.VerifyPassword(ctx, db, after, pw) {
		t.Fatal("re-minted digest does not verify the original password — the upgrade locked the user out")
	}
	if users.VerifyPassword(ctx, db, after, "wrong-pw") {
		t.Fatal("wrong password verified after upgrade")
	}
}

// TestArgon2idRowIsNotRewrittenOnLogin: the 85 live argon2id rows are stronger
// than our mint policy, so a login must leave them exactly as they are.
func TestArgon2idRowIsNotRewrittenOnLogin(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// A live-shaped v1 digest (m=65536,t=1,p=2), minted by alexedwards/argon2id
	// v0.0.0-20211130144151 — see internal/password/password_test.go.
	const (
		liveDigest = "$argon2id$v=19$m=65536,t=1,p=2$pp/ox8H4VMz2MEVeKoOuxg$Vqb3kOJtdw9vdDMTvJG/yn8U81IwcuidSJFXMUaI+u0"
		livePw     = "correct horse battery staple"
	)
	u := orm.New[schema.User](db)
	u.Owner = "hanzo"
	u.Name = "argonuser"
	u.Email = "argon@hanzo.ai"
	u.PasswordHash = liveDigest
	u.PasswordType = "argon2id"
	if err := u.Create(); err != nil {
		t.Fatal(err)
	}

	got, err := store.GetUserByEmail(ctx, db, "hanzo", "argon@hanzo.ai")
	if err != nil || got == nil {
		t.Fatalf("lookup: %v", err)
	}
	if !users.VerifyPassword(ctx, db, got, livePw) {
		t.Fatal("a live-shaped argon2id row failed to log in — this is the blocker")
	}

	after, err := store.GetUserByEmail(ctx, db, "hanzo", "argon@hanzo.ai")
	if err != nil || after == nil {
		t.Fatalf("re-read: %v", err)
	}
	if after.PasswordHash != liveDigest {
		t.Fatal("a stronger-than-policy argon2id digest was rewritten on login — that weakens the account")
	}
}
