// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/pkg/store"
	"github.com/hanzoai/iam/internal/users"
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
	if !users.VerifyPassword(got, "s3cret-pw", "") {
		t.Fatal("persisted hash does not verify the password")
	}
	if users.VerifyPassword(got, "wrong-pw", "") {
		t.Fatal("wrong password verified — bcrypt broken")
	}
}
