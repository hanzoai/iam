// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package cred

import (
	"testing"

	"github.com/alexedwards/argon2id"
	"golang.org/x/crypto/bcrypt"
)

// TestVerify_Argon2id_RealV1FormatHash is the regression for the cutover
// blocker: every live v1 row is argon2id, and a bcrypt-only verifier fails all
// of them. This proves iam verifies a genuine argon2id PHC digest — the exact
// shape v1's Argon2idCredManager writes (github.com/alexedwards/argon2id,
// DefaultParams).
func TestVerify_Argon2id_RealV1FormatHash(t *testing.T) {
	pw := "correct horse battery staple"
	hash, err := argon2id.CreateHash(pw, argon2id.DefaultParams)
	if err != nil {
		t.Fatal(err)
	}
	// Sanity: it really is the PHC shape a live row carries.
	if len(hash) < 20 || hash[:9] != "$argon2id" {
		t.Fatalf("not an argon2id PHC digest: %q", hash)
	}
	if !Verify(TypeArgon2id, pw, hash) {
		t.Fatal("argon2id: correct password REJECTED — this is the cutover blocker")
	}
	if Verify(TypeArgon2id, "wrong password", hash) {
		t.Fatal("argon2id: wrong password ACCEPTED")
	}
}

// TestVerify_BcryptStillWorks — new iam-minted users are bcrypt; don't regress.
func TestVerify_Bcrypt(t *testing.T) {
	pw := "s3cret-pw"
	h, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)
	if !Verify(TypeBcrypt, pw, string(h)) {
		t.Fatal("bcrypt: correct password rejected")
	}
	if Verify(TypeBcrypt, "nope", string(h)) {
		t.Fatal("bcrypt: wrong password accepted")
	}
}

// TestVerify_CrossSchemeFailsClosed — the actual bug: an argon2id digest handed
// to the bcrypt path (or vice versa) must NOT pass, and must not panic.
func TestVerify_CrossSchemeFailsClosed(t *testing.T) {
	pw := "x"
	argon, _ := argon2id.CreateHash(pw, argon2id.DefaultParams)
	bc, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost)

	if Verify(TypeBcrypt, pw, argon) {
		t.Fatal("argon2id digest verified under bcrypt — auth bypass")
	}
	if Verify(TypeArgon2id, pw, string(bc)) {
		t.Fatal("bcrypt digest verified under argon2id — auth bypass")
	}
}

// TestVerify_FailsClosedOnGarbage — unknown type, empty hash, malformed digest.
func TestVerify_FailsClosedOnGarbage(t *testing.T) {
	cases := []struct{ typ, pw, hash string }{
		{"", "pw", "$argon2id$v=19$whatever"},    // no type
		{"sha256-salt", "pw", "deadbeef"},        // unsupported legacy type
		{"plain", "pw", "pw"},                    // plaintext scheme: refused
		{TypeArgon2id, "pw", ""},                 // empty hash
		{TypeArgon2id, "pw", "not-a-phc-string"}, // malformed
		{TypeBcrypt, "pw", "$2a$garbage"},        // malformed bcrypt
		{"ARGON2ID", "pw", "$argon2id$v=19$x"},   // case-sensitive: not supported
	}
	for _, c := range cases {
		if Verify(c.typ, c.pw, c.hash) {
			t.Fatalf("verify(%q, hash=%q) returned TRUE — must fail closed", c.typ, c.hash)
		}
	}
}

// TestResolve_PerRowThenOrgFallback — v1's contract: the user's own type wins;
// an empty user type falls back to the org's; never a hardcoded default.
func TestResolve(t *testing.T) {
	if got := Resolve("bcrypt", "argon2id"); got != "bcrypt" {
		t.Fatalf("user type must win: got %q", got)
	}
	if got := Resolve("", "argon2id"); got != "argon2id" {
		t.Fatalf("empty user type must fall back to org: got %q", got)
	}
	if got := Resolve("", ""); got != "" {
		t.Fatalf("both empty must stay empty (caller decides), got %q", got)
	}
}

func TestSupported(t *testing.T) {
	for _, ok := range []string{TypeArgon2id, TypeBcrypt} {
		if !Supported(ok) {
			t.Fatalf("%s must be supported", ok)
		}
	}
	for _, no := range []string{"", "plain", "salt", "sha512-salt", "md5-salt", "pbkdf2-salt"} {
		if Supported(no) {
			t.Fatalf("%q must NOT be supported (fail closed)", no)
		}
	}
}
