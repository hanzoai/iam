// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package cred_test

// The credential-digest contract. The load-bearing case is interop: iam2 must
// verify a digest LIVE v1 wrote, so the fixtures below are not iam2's own output
// — they were minted by the exact library and parameters v1 mints with
// (github.com/alexedwards/argon2id, DefaultParams; iam/object/service_account.go
// MintServiceAccountKey). A verifier tested only against its own encoder proves
// nothing about cutover.

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/iam2/internal/cred"
)

// v1Hash / v1Secret are a REAL argon2id PHC digest minted by v1's own library at
// v1's own DefaultParams (m=65536,t=1,p=2), frozen here as the cutover contract.
const (
	v1Secret = "hk-abc123secret"
	v1Hash   = "$argon2id$v=19$m=65536,t=1,p=2$lw7pOIR6REN0aO6PxubXHQ$Sh93/A7jca0IIF//9/DYGyEc/TgpObpZiy3xP1x3wlY"

	v1Secret2 = "correct horse battery staple"
	v1Hash2   = "$argon2id$v=19$m=65536,t=1,p=2$h0899dypBb7YDHPZFVWxVA$oS3XKYK+y+C6qG4dGc7T5CbtU1aMR6bsHlAcNSPJd88"
)

// TestVerifiesRealV1Argon2idHash is the cutover gate: every live service-account
// secret is an argon2id PHC string written by v1. If this fails, every imported
// credential stops authenticating the moment iam2 serves.
func TestVerifiesRealV1Argon2idHash(t *testing.T) {
	for _, tc := range []struct{ secret, hash string }{
		{v1Secret, v1Hash},
		{v1Secret2, v1Hash2},
	} {
		if !cred.Verify(cred.Argon2id, tc.hash, tc.secret) {
			t.Fatalf("v1-minted argon2id hash did not verify for %q", tc.secret)
		}
		if cred.Verify(cred.Argon2id, tc.hash, tc.secret+"x") {
			t.Fatalf("a wrong secret verified against the v1 hash for %q", tc.secret)
		}
	}
	// A digest never verifies a secret it was not minted from — the two fixtures
	// are independent, so a cross-match would mean the salt is being ignored.
	if cred.Verify(cred.Argon2id, v1Hash, v1Secret2) {
		t.Fatal("a v1 hash verified a foreign secret")
	}
}

// TestHashIsV1CompatiblePHC pins the format iam2 WRITES: the same variant,
// version, and parameters v1 reads, so a row iam2 mints stays verifiable by v1
// during a rollback.
func TestHashIsV1CompatiblePHC(t *testing.T) {
	h, err := cred.Hash("s3cret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	const want = "$argon2id$v=19$m=65536,t=1,p=2$"
	if !strings.HasPrefix(h, want) {
		t.Fatalf("digest %q does not carry v1's parameters (want prefix %q)", h, want)
	}
	if parts := strings.Split(h, "$"); len(parts) != 6 {
		t.Fatalf("digest %q is not a 6-part PHC string", h)
	}
	if !cred.Verify(cred.Argon2id, h, "s3cret") {
		t.Fatal("iam2's own digest did not verify")
	}
	if strings.Contains(h, "s3cret") {
		t.Fatal("the digest carries the plaintext")
	}
	// Fresh salt per call: the same secret never yields the same digest.
	h2, _ := cred.Hash("s3cret")
	if h == h2 {
		t.Fatal("two digests of the same secret are identical — the salt is not random")
	}
}

// TestVerifyDispatchesOnTheStoredScheme is the decomplected property: the
// algorithm is a property of the ROW, so a bcrypt row verifies under bcrypt and
// an argon2id row under argon2id, through ONE entry point. Verifying with the
// wrong scheme name never succeeds — which is exactly the bug a hard-coded
// algorithm has.
func TestVerifyDispatchesOnTheStoredScheme(t *testing.T) {
	b, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("bcrypt: %v", err)
	}
	bcryptHash := string(b)

	if !cred.Verify(cred.Bcrypt, bcryptHash, "pw") {
		t.Fatal("a bcrypt row did not verify under bcrypt")
	}
	if !cred.Verify(cred.Argon2id, v1Hash, v1Secret) {
		t.Fatal("an argon2id row did not verify under argon2id")
	}
	// Crossed schemes: this is precisely the live blocker — calling bcrypt on an
	// argon2id row (and vice versa) refuses a CORRECT secret.
	if cred.Verify(cred.Bcrypt, v1Hash, v1Secret) {
		t.Fatal("an argon2id row verified under bcrypt")
	}
	if cred.Verify(cred.Argon2id, bcryptHash, "pw") {
		t.Fatal("a bcrypt row verified under argon2id")
	}
}

// TestVerifyFailsClosed pins every refusal axis: an unknown or empty scheme, an
// absent digest, an empty presented secret, and a malformed stored digest.
func TestVerifyFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		name             string
		kind, stored, in string
	}{
		{"unknown scheme", "sha256-salt", v1Hash, v1Secret},
		{"empty scheme", "", v1Hash, v1Secret},
		{"no digest stored", cred.Argon2id, "", v1Secret},
		{"empty presented secret", cred.Argon2id, v1Hash, ""},
		{"not a PHC string", cred.Argon2id, "garbage", v1Secret},
		{"wrong variant", cred.Argon2id, strings.Replace(v1Hash, "argon2id", "argon2i", 1), v1Secret},
		{"wrong version", cred.Argon2id, strings.Replace(v1Hash, "v=19", "v=16", 1), v1Secret},
		{"truncated", cred.Argon2id, "$argon2id$v=19$m=65536,t=1,p=2$", v1Secret},
		{"empty key", cred.Argon2id, "$argon2id$v=19$m=65536,t=1,p=2$lw7pOIR6REN0aO6PxubXHQ$", v1Secret},
		{"non-base64 salt", cred.Argon2id, "$argon2id$v=19$m=65536,t=1,p=2$!!!$Sh93", v1Secret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if cred.Verify(tc.kind, tc.stored, tc.in) {
				t.Fatalf("verified: kind=%q stored=%q", tc.kind, tc.stored)
			}
		})
	}
}
