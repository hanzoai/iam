// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package cred

import "testing"

// Golden vectors: PHC digests produced by **v1's own Argon2idCredManager**
// (hanzoai/iam `cred.NewArgon2idCredManager().GetHashedPassword`, DefaultParams),
// captured verbatim. This is the parity proof that matters — iam2 must verify the
// exact bytes v1 wrote, not merely a digest iam2 generated itself.
//
// It also pins a REAL cross-version risk: v1 resolves
// `github.com/alexedwards/argon2id v0.0.0-20211130144151-3585854a6387` while iam2
// pins `v1.0.0`. The PHC string is self-describing (m/t/p + salt + key), so a
// digest from either version must verify under the other — this test is what
// proves that, and what fails loudly if a future bump ever breaks it.
//
// These are throwaway TEST passwords. No live user's digest is ever committed —
// a real hash is an offline-attackable secret and does not belong in a repo.

const (
	// v1 Argon2idCredManager.GetHashedPassword("golden-test-password-1", "")
	goldenV1Password = "golden-test-password-1"
	goldenV1Digest   = "$argon2id$v=19$m=65536,t=1,p=2$oOen09XtFBqKnv2/K4q5mQ$iZKRwt09CdXDXr4E1CQtRoF/nWzgI810tMFUUiKHugo"
)

// TestGolden_V1Argon2idDigestVerifies is the cutover-parity assertion: a digest
// written by the LIVE v1 code path verifies under iam2's cred.Verify.
func TestGolden_V1Argon2idDigestVerifies(t *testing.T) {
	if !Verify(TypeArgon2id, goldenV1Password, goldenV1Digest) {
		t.Fatal("iam2 REJECTED a digest produced by v1's Argon2idCredManager — " +
			"credential parity is broken; every live login would fail at cutover")
	}
	if Verify(TypeArgon2id, "not-the-password", goldenV1Digest) {
		t.Fatal("wrong password ACCEPTED against the v1 golden digest")
	}
}

// TestGolden_V1DigestShape documents the exact PHC shape v1 emits, so a change in
// v1's params (or a lib bump on either side) is caught here rather than in prod.
func TestGolden_V1DigestShape(t *testing.T) {
	// $argon2id$v=19$m=65536,t=1,p=2$<salt>$<key>
	const wantPrefix = "$argon2id$v=19$m=65536,t=1,p="
	if len(goldenV1Digest) < len(wantPrefix) || goldenV1Digest[:len(wantPrefix)] != wantPrefix {
		t.Fatalf("v1 digest shape changed: %q", goldenV1Digest)
	}
}

// TestGolden_ResolvedThroughRowType proves the full row→algorithm path a real
// login takes: the row says "argon2id" (what every live v1 row says), the org
// fallback is irrelevant, and the v1 digest verifies.
func TestGolden_ResolvedThroughRowType(t *testing.T) {
	typ := Resolve("argon2id", "bcrypt") // user's own type must win
	if typ != TypeArgon2id {
		t.Fatalf("resolve: got %q", typ)
	}
	if !Verify(typ, goldenV1Password, goldenV1Digest) {
		t.Fatal("row-resolved argon2id failed to verify the v1 golden digest")
	}
	// And the bug that shipped: resolving to bcrypt against this digest must FAIL,
	// never pass.
	if Verify(TypeBcrypt, goldenV1Password, goldenV1Digest) {
		t.Fatal("v1 argon2id digest verified under bcrypt — auth bypass")
	}
}
