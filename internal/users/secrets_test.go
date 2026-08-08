// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A full-row update is fed by a masked read: every client that edits a user GETs the
// account, changes a field, and POSTs the whole row back. Mask blanks the secrets on
// the way out, so each one arrives back EMPTY — and a write that takes the body at
// its word erases it. These tests pin the inverse rule (schema.User.CarrySecretsFrom):
// what a reader cannot see, a writer cannot state.

// The authenticator seed and its recovery codes are the case that bit a real account.
// hanzo.id's onboarding read its own account and posted it back to bind a wallet; the
// seed and every recovery code went to zero while preferredMfaType stayed "app" — so
// sign-in still demanded a code, nothing could produce one, and the recovery codes
// that exist for exactly that moment were gone too. Enrolment lives in internal/mfa;
// this write never had standing to touch it.
//
// FAILS before the fix (seed and codes empty), PASSES after.
func TestUpdate_keepsAuthenticatorSeed(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "mfa-update.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	const org, name = "hanzo", "alice"
	const seed = "JBSWY3DPEHPK3PXP"
	codes := []string{"aaaa-bbbb", "cccc-dddd"}

	if _, err := New(db).Create(ctx, &CreateInput{
		User:     schema.User{Owner: org, Name: name, Email: "alice@hanzo.ai"},
		Password: "correct horse battery staple",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Enrol an authenticator, the way internal/mfa does: load the stored row, set the
	// multi-factor columns, write it back.
	enrolled, _ := store.GetUserByName(ctx, db, org, name)
	enrolled.TotpSecret = seed
	enrolled.RecoveryCodes = codes
	enrolled.PreferredMfaType = "app"
	if err := enrolled.UpdateCtx(ctx); err != nil {
		t.Fatalf("enrol: %v", err)
	}

	// The shipped read-merge-write: read the account (masked), merge a field, post the
	// whole row back. Mask is what the client actually receives, so deriving the body
	// from it is the faithful reproduction. The field that client merged in was
	// `web3onboard`, which schema.User does not have — so the decoder drops it and the
	// body below is what actually reached this write: a row asking for NO change,
	// which nonetheless erased the seed.
	stored, _ := store.GetUserByName(ctx, db, org, name)
	body := *stored.Mask()
	if body.TotpSecret != "" || len(body.RecoveryCodes) != 0 {
		t.Fatalf("premise broken: Mask no longer blanks the seed (%q/%v) — this test would prove nothing",
			body.TotpSecret, body.RecoveryCodes)
	}
	if _, err := New(db).Update(ctx, &UpdateInput{User: body}); err != nil {
		t.Fatalf("update: %v", err)
	}

	after, _ := store.GetUserByName(ctx, db, org, name)
	if after.TotpSecret != seed {
		t.Fatalf("totpSecret = %q, want %q — a profile edit erased the authenticator seed while preferredMfaType stayed %q: the account is locked out",
			after.TotpSecret, seed, after.PreferredMfaType)
	}
	if len(after.RecoveryCodes) != len(codes) {
		t.Fatalf("recoveryCodes = %v, want %v — the escape hatch for a lost seed was erased by the same write",
			after.RecoveryCodes, codes)
	}
	if after.PreferredMfaType != "app" {
		t.Fatalf("preferredMfaType = %q, want \"app\"", after.PreferredMfaType)
	}
}

// The same rule, stated over Mask's whole set rather than one field, so a secret added
// to Mask without its sibling carry line fails here. A password digest that survives a
// profile edit is long-standing behaviour; a bearer token and a live one-time code are
// the same kind of thing and were not carried.
func TestUpdate_keepsEverySecretMaskHides(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "secrets-update.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	const org, name, pw = "hanzo", "bob", "correct horse battery staple"
	if _, err := New(db).Create(ctx, &CreateInput{
		User:     schema.User{Owner: org, Name: name, Email: "bob@hanzo.ai"},
		Password: pw,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Put a distinct value in every field Mask blanks, so an erasure of any one of
	// them is visible by name below.
	seeded, _ := store.GetUserByName(ctx, db, org, name)
	// argon2id carries its parameters inside the digest, so a freshly created account
	// has no separate salt. A migrated account does, and it is masked either way.
	seeded.PasswordSalt = "legacy-salt"
	seeded.AccessSecret = "sk-secret"
	seeded.AccessSecretHash = "sk-digest"
	seeded.AccessToken = "bearer-token"
	seeded.OriginalToken = "idp-token"
	seeded.OriginalRefreshToken = "idp-refresh"
	seeded.TotpSecret = "JBSWY3DPEHPK3PXP"
	seeded.RecoveryCodes = []string{"aaaa-bbbb"}
	seeded.VerificationCode = "123456"
	if err := seeded.UpdateCtx(ctx); err != nil {
		t.Fatalf("seed secrets: %v", err)
	}
	before, _ := store.GetUserByName(ctx, db, org, name)

	body := *before.Mask()
	body.DisplayName = "Bob B"
	if _, err := New(db).Update(ctx, &UpdateInput{User: body}); err != nil {
		t.Fatalf("update: %v", err)
	}
	after, _ := store.GetUserByName(ctx, db, org, name)

	for _, f := range []struct {
		name string
		want string
		got  string
	}{
		{"passwordHash", before.PasswordHash, after.PasswordHash},
		{"passwordSalt", before.PasswordSalt, after.PasswordSalt},
		{"accessSecret", before.AccessSecret, after.AccessSecret},
		{"accessSecretHash", before.AccessSecretHash, after.AccessSecretHash},
		{"accessToken", before.AccessToken, after.AccessToken},
		{"originalToken", before.OriginalToken, after.OriginalToken},
		{"originalRefreshToken", before.OriginalRefreshToken, after.OriginalRefreshToken},
		{"totpSecret", before.TotpSecret, after.TotpSecret},
		{"verificationCode", before.VerificationCode, after.VerificationCode},
	} {
		if f.want == "" {
			t.Fatalf("setup: %s was not seeded, so this row proves nothing", f.name)
		}
		if f.got != f.want {
			t.Fatalf("%s = %q, want %q — Mask hides this field, so the body arrived blank and the write erased it", f.name, f.got, f.want)
		}
	}
	if len(after.RecoveryCodes) != len(before.RecoveryCodes) {
		t.Fatalf("recoveryCodes = %v, want %v", after.RecoveryCodes, before.RecoveryCodes)
	}

	// The edit the caller actually asked for still lands, and a password reset — the
	// one secret a caller may state, through its own field — still takes effect.
	if after.DisplayName != "Bob B" {
		t.Fatalf("displayName = %q, want %q — the intended edit was lost", after.DisplayName, "Bob B")
	}
	if _, err := New(db).Update(ctx, &UpdateInput{User: body, Password: "a whole new password"}); err != nil {
		t.Fatalf("password reset: %v", err)
	}
	reset, _ := store.GetUserByName(ctx, db, org, name)
	if reset.PasswordHash == before.PasswordHash {
		t.Fatal("password reset did not change the digest — carrying secrets must not disable the reset seam")
	}
}
