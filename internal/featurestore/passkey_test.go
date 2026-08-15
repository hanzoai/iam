// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package featurestore

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/feature"
	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// openStoreAndDB is openFeatureStore plus the handle, so a test can seed rows the
// seam has no verb for — a membership in the reserved org.
func openStoreAndDB(t *testing.T) (feature.Store, orm.DB) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db), db
}

func seedCredentialedUser(t *testing.T, db orm.DB, org, name, password string) {
	t.Helper()
	hash, err := cred.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u := orm.New[schema.User](db)
	u.Owner = org
	u.Name = name
	u.PasswordHash = hash
	u.PasswordType = cred.TypeArgon2id
	u.SetId(org + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func seedMembershipInAdmin(t *testing.T, db orm.DB, org, name string) {
	t.Helper()
	m := orm.New[schema.Membership](db)
	m.Owner = "admin"
	m.Name = "m-" + org + "-" + name
	m.User = org + "/" + name
	m.Org = "admin"
	m.Role = "admin"
	m.SetId("admin/m-" + org + "-" + name)
	if err := m.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

// An LDAP bind is a password on the wire, and it does not carry an operator.
//
// This seam is how a directory module authenticates, which means it is a door into
// the same accounts with none of the login form's ceremony around it. It answers
// one bit, so the refusal is indistinguishable from a wrong password.
func TestBindRefusesAnOperator(t *testing.T) {
	ctx := context.Background()
	s, db := openStoreAndDB(t)
	seedCredentialedUser(t, db, "hanzo", "z", "correct-horse")
	seedMembershipInAdmin(t, db, "hanzo", "z")

	ok, err := s.VerifyPassword(ctx, "hanzo", "z", "correct-horse")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("an operator's correct password completed an LDAP bind")
	}
}

// The control: the same seam still binds an ordinary account.
func TestBindStillAcceptsAnOrdinaryAccount(t *testing.T) {
	ctx := context.Background()
	s, db := openStoreAndDB(t)
	seedCredentialedUser(t, db, "hanzo", "dana", "correct-horse")

	ok, err := s.VerifyPassword(ctx, "hanzo", "dana", "correct-horse")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("an ordinary account's correct password failed to bind")
	}
}
