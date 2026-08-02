// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// seedUser creates a user with a bcrypt password in org "hanzo".
func seedUser(t *testing.T, db orm.DB, name, email, password string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost) // MinCost = fast tests
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Owner = "hanzo"
	u.Name = name
	u.Email = email
	u.PasswordHash = string(hash)
	u.PasswordType = "bcrypt"
	u.SetId("hanzo/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// TestLoginToTokenFlow is the full interactive round-trip: a password login
// (verified with bcrypt) mints a PKCE-bound code, which the token endpoint
// redeems into a signed JWT. Proves login→code→token end to end.
func TestLoginToTokenFlow(t *testing.T) {
	db := openTestDB(t)
	key := mustGenRSA(t)
	app := seedAppWithCert(t, db, key)
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse battery staple")
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)

	verifier := "login-verifier-000000000000000000000000000000000"
	challenge := pkce.Challenge(verifier)

	// --- login side: resolve app+user, verify password, mint the code ---
	user, err := resolveLoginUser(ctx, db, "hanzo", "alice@hanzo.ai") // login by EMAIL
	if err != nil || user == nil {
		t.Fatalf("resolve user by email: %v (nil=%v)", err, user == nil)
	}
	code, err := MintCode(app, user.Owner+"/"+user.Name, "openid profile", challenge, "S256", "", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PersistToken(ctx, db, code); err != nil {
		t.Fatal(err)
	}

	// --- token side: redeem the code with the verifier ---
	tok, _ := store.GetTokenByCode(ctx, db, code.Code)
	if err := RedeemCode(tok, app.Name, verifier, now.Add(time.Second)); err != nil {
		t.Fatalf("redeem: %v", err)
	}
	if tok.User != "hanzo/alice" {
		t.Fatalf("code bound to wrong user: %q", tok.User)
	}
}

func TestResolveLoginUser_ByUsernameAndEmail(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedUser(t, db, "bob", "bob@hanzo.ai", "pw")

	byName, _ := resolveLoginUser(ctx, db, "hanzo", "bob")
	if byName == nil || byName.Name != "bob" {
		t.Fatal("login by username failed")
	}
	byEmail, _ := resolveLoginUser(ctx, db, "hanzo", "bob@hanzo.ai")
	if byEmail == nil || byEmail.Name != "bob" {
		t.Fatal("login by email failed")
	}
	// Wrong org → not found (tenant isolation).
	other, _ := resolveLoginUser(ctx, db, "lux", "bob")
	if other != nil {
		t.Fatal("user resolved in the wrong org — tenant isolation broken")
	}
}
