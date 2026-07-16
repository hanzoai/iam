// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package password

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

// Golden digests minted by the EXACT code path that produced the live v1 rows:
//
//	iam/cred/argon2id.go -> argon2id.CreateHash(pw, argon2id.DefaultParams)
//	with github.com/alexedwards/argon2id v0.0.0-20211130144151-3585854a6387
//	(that version's DefaultParams: m=64*1024, t=1, p=2, salt 16, key 32)
//
// They are byte-shaped exactly like the 85 argon2id rows measured in the live
// prod store on 2026-07-16 ($argon2id$v=19$m=65536,t=1,p=2$...) — verified by
// reading the parameter segment of the real rows.
//
// These are synthetic digests of known throwaway passwords, minted here for the
// test. No live credential material is reproduced, and none should ever be.
//
// This is the test that matters: iam2 must verify a digest MINTED BY SOMETHING
// ELSE. A round-trip of our own hasher passes happily while every real login is
// broken — which is exactly the state this package was written to fix.
const (
	liveArgon2idDigest   = "$argon2id$v=19$m=65536,t=1,p=2$pp/ox8H4VMz2MEVeKoOuxg$Vqb3kOJtdw9vdDMTvJG/yn8U81IwcuidSJFXMUaI+u0"
	liveArgon2idPassword = "correct horse battery staple"

	// A second vector, distinct password + salt, guarding against a fluke.
	liveArgon2idDigest2   = "$argon2id$v=19$m=65536,t=1,p=2$6bXpDr3wTXMi+qXh4GNlRg$BmOi5GhRqpP0RT2cGZ3LHbfcXs37/jT8xP0rxhdmop4"
	liveArgon2idPassword2 = "hunter2"

	// bcrypt at the costs actually observed live ($2a$10 x24, $2b$10 x15,
	// $2b$12 x1). $2b$ is the same digest with the minor version bumped: the
	// $2a$/$2b$ difference is a wraparound fix that cannot affect a <=72-byte
	// password, and x/crypto accepts any minor version.
	liveBcrypt10Digest = "$2a$10$TD8./C3ff5vaeBHgUEfAW.55wo2O7e0RGGoXBOP1fv6mkQtUpVrv6"
	liveBcrypt12Digest = "$2a$12$KovJZc28AmrlLpI5H.yuF.htTbrskZWpaNvBodi1eDUT6u1g1ylpa"
	liveBcryptPassword = "hunter2"
)

// TestVerifiesLiveShapedArgon2idDigest is THE regression test for the blocker:
// bcrypt-only verify handed an argon2id PHC string returns ErrHashTooShort, so
// every argon2id account failed login. Against the pre-fix code this fails.
func TestVerifiesLiveShapedArgon2idDigest(t *testing.T) {
	for _, tc := range []struct{ name, digest, password string }{
		{"vector 1", liveArgon2idDigest, liveArgon2idPassword},
		{"vector 2", liveArgon2idDigest2, liveArgon2idPassword2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, stale := Verify(ctx(), tc.digest, tc.password)
			if !ok {
				t.Fatal("a live-shaped v1 argon2id digest did not verify — every argon2id login is broken")
			}
			// m=65536,t=1 -> 65536 KiB-passes, above the 19456*2=38912 policy.
			// Re-hashing these to policy would WEAKEN them; must not be stale.
			if stale {
				t.Fatal("live argon2id (m=65536,t=1,p=2) marked stale — re-hashing it to policy would weaken the account")
			}
		})
	}
}

func TestRejectsWrongPasswordAgainstLiveDigest(t *testing.T) {
	for _, wrong := range []string{"", "wrong", liveArgon2idPassword + "x", strings.ToUpper(liveArgon2idPassword)} {
		if ok, _ := Verify(ctx(), liveArgon2idDigest, wrong); ok {
			t.Fatalf("wrong password %q verified against a live argon2id digest", wrong)
		}
	}
}

// TestVerifiesLiveBcryptDigest proves the 40 live bcrypt rows still log in —
// deleting the bcrypt path would have broken every one of them.
func TestVerifiesLiveBcryptDigest(t *testing.T) {
	for _, tc := range []struct{ name, digest string }{
		{"$2a$10 (24 live rows)", liveBcrypt10Digest},
		{"$2a$12 (1 live row)", liveBcrypt12Digest},
		// The 15 live $2b$10 rows: same digest, minor version bumped.
		{"$2b$10 (15 live rows)", "$2b$" + strings.TrimPrefix(liveBcrypt10Digest, "$2a$")},
		// Not observed live, but a bcrypt dialect we must not silently reject.
		{"$2y$10", "$2y$" + strings.TrimPrefix(liveBcrypt10Digest, "$2a$")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, stale := Verify(ctx(), tc.digest, liveBcryptPassword)
			if !ok {
				t.Fatal("a live-shaped bcrypt digest did not verify — these accounts would be locked out")
			}
			// bcrypt is not what we mint: a successful login is the one moment
			// we can retire it.
			if !stale {
				t.Fatal("bcrypt digest not marked stale — the 40 live bcrypt rows would never migrate")
			}
		})
	}
	if ok, _ := Verify(ctx(), liveBcrypt10Digest, "wrong"); ok {
		t.Fatal("wrong password verified against a live bcrypt digest")
	}
}

// TestNeverStaleOnFailure: a failed guess must never trigger a re-hash.
func TestNeverStaleOnFailure(t *testing.T) {
	for _, digest := range []string{liveArgon2idDigest, liveBcrypt10Digest} {
		ok, stale := Verify(ctx(), digest, "definitely-not-the-password")
		if ok {
			t.Fatal("wrong password verified")
		}
		if stale {
			t.Fatal("stale reported for a FAILED verify — would re-hash on an attacker's guess")
		}
	}
}

func TestHashVerifyRoundTrip(t *testing.T) {
	const pw = "a fresh password"
	digest, err := Hash(ctx(), pw)
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	ok, stale := Verify(ctx(), digest, pw)
	if !ok {
		t.Fatal("freshly minted digest did not verify")
	}
	if stale {
		t.Fatal("freshly minted digest reported stale — every login would re-hash forever")
	}
	if ok, _ := Verify(ctx(), digest, pw+"x"); ok {
		t.Fatal("wrong password verified against a fresh digest")
	}
}

// TestHashMintsCurrentPolicy pins the parameters we advertise. OWASP baseline:
// m=19456 (19 MiB), t=2, p=1.
func TestHashMintsCurrentPolicy(t *testing.T) {
	digest, err := Hash(ctx(), "x")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if !strings.HasPrefix(digest, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("Hash did not mint the OWASP baseline parameters: %s", paramsOf(digest))
	}
	memory, time, threads, salt, key, err := parse(digest)
	if err != nil {
		t.Fatalf("parse of our own digest: %v", err)
	}
	if memory != memoryKiB || time != timeCost || threads != lanes {
		t.Fatalf("got m=%d,t=%d,p=%d want m=%d,t=%d,p=%d", memory, time, threads, memoryKiB, timeCost, lanes)
	}
	if len(salt) != saltLen {
		t.Fatalf("salt length %d, want %d", len(salt), saltLen)
	}
	if len(key) != keyLen {
		t.Fatalf("key length %d, want %d", len(key), keyLen)
	}
}

// TestHashSaltIsRandom: two digests of the same password must differ.
func TestHashSaltIsRandom(t *testing.T) {
	a, err := Hash(ctx(), "same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	b, err := Hash(ctx(), "same password")
	if err != nil {
		t.Fatalf("Hash: %v", err)
	}
	if a == b {
		t.Fatal("two hashes of the same password are identical — the salt is not random")
	}
}

// TestStaleTracksMemoryTimeProduct: the axis Argon2 parameters trade along.
// Every OWASP-equivalent set must be accepted (not re-hashed); anything
// genuinely cheaper than policy must be re-hashed.
func TestStaleTracksMemoryTimeProduct(t *testing.T) {
	for _, tc := range []struct {
		name         string
		memory, time uint32
		wantStale    bool
	}{
		// OWASP's five "equivalent" sets — none should be re-hashed.
		{"OWASP m=47104,t=1", 47104, 1, false},
		{"OWASP m=19456,t=2 (our policy)", 19456, 2, false},
		{"OWASP m=12288,t=3", 12288, 3, false},
		{"OWASP m=9216,t=4", 9216, 4, false},
		{"OWASP m=7168,t=5", 7168, 5, false},
		// The live v1 rows — stronger than policy, must not be downgraded.
		{"live v1 m=65536,t=1", 65536, 1, false},
		// Genuinely weaker than policy.
		{"weak m=4096,t=1", 4096, 1, true},
		{"weak m=1024,t=2", 1024, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := weaker(tc.memory, tc.time); got != tc.wantStale {
				t.Fatalf("weaker(m=%d,t=%d) = %v, want %v", tc.memory, tc.time, got, tc.wantStale)
			}
		})
	}
}

// TestWeakArgon2idIsRehashed: an under-strength argon2id digest verifies AND is
// flagged for replacement.
func TestWeakArgon2idIsRehashed(t *testing.T) {
	// Minted at deliberately weak parameters (m=1024,t=1,p=1).
	const pw = "weakly hashed"
	weak := mintAt(t, pw, 1024, 1, 1)
	ok, stale := Verify(ctx(), weak, pw)
	if !ok {
		t.Fatal("weak argon2id digest did not verify")
	}
	if !stale {
		t.Fatal("weak argon2id digest not flagged for re-hash")
	}
}

// TestMalformedDigestFailsClosed: no panic, no match. argon2.IDKey panics on a
// zero time/threads value, so a corrupt or hostile digest must never reach it.
func TestMalformedDigestFailsClosed(t *testing.T) {
	for _, tc := range []struct{ name, digest string }{
		{"empty", ""},
		{"unknown scheme", "$scrypt$v=19$m=1,t=1,p=1$aaaa$bbbb"},
		{"plaintext (no scheme)", "hunter2"},
		{"bare marker", "$argon2id$"},
		{"too few fields", "$argon2id$v=19$m=65536,t=1,p=2$onlysalt"},
		{"too many fields", liveArgon2idDigest + "$extra"},
		{"zero memory", "$argon2id$v=19$m=0,t=1,p=1$cGFzc3dvcmQ$cGFzc3dvcmQ"},
		{"zero time", "$argon2id$v=19$m=65536,t=0,p=1$cGFzc3dvcmQ$cGFzc3dvcmQ"},
		{"zero lanes", "$argon2id$v=19$m=65536,t=1,p=0$cGFzc3dvcmQ$cGFzc3dvcmQ"},
		{"bad version", "$argon2id$v=16$m=65536,t=1,p=2$cGFzc3dvcmQ$cGFzc3dvcmQ"},
		{"nonnumeric version", "$argon2id$v=xx$m=65536,t=1,p=2$cGFzc3dvcmQ$cGFzc3dvcmQ"},
		{"missing params", "$argon2id$v=19$$cGFzc3dvcmQ$cGFzc3dvcmQ"},
		{"garbage params", "$argon2id$v=19$m=a,t=b,p=c$cGFzc3dvcmQ$cGFzc3dvcmQ"},
		{"bad salt base64", "$argon2id$v=19$m=65536,t=1,p=2$!!!!$cGFzc3dvcmQ"},
		{"bad key base64", "$argon2id$v=19$m=65536,t=1,p=2$cGFzc3dvcmQ$!!!!"},
		{"empty salt+key", "$argon2id$v=19$m=65536,t=1,p=2$$"},
		{"truncated bcrypt", "$2a$10$tooshort"},
		{"bcrypt garbage", "$2a$10$" + strings.Repeat("!", 53)},
		{"argon2i (not id)", "$argon2i$v=19$m=65536,t=1,p=2$cGFzc3dvcmQ$cGFzc3dvcmQ"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A panic here is a crash on the unauthenticated login path.
			ok, stale := Verify(ctx(), tc.digest, "anything")
			if ok {
				t.Fatal("malformed digest verified — must fail closed")
			}
			if stale {
				t.Fatal("malformed digest marked stale")
			}
		})
	}
}

// TestVerifyHasNoLengthCap: maxPasswordLen bounds what we MINT. Enforcing it on
// the verify path would lock out any account whose password predates the bound.
func TestVerifyHasNoLengthCap(t *testing.T) {
	long := strings.Repeat("x", maxPasswordLen*2)
	digest := mintAt(t, long, 1024, 1, 1) // weak params: keep the test fast
	if ok, _ := Verify(ctx(), digest, long); !ok {
		t.Fatal("an over-long password could not be verified — the cap must not reach the verify path")
	}
}

func TestHashRejectsOverlongPassword(t *testing.T) {
	if _, err := Hash(ctx(), strings.Repeat("x", maxPasswordLen+1)); err != ErrPasswordTooLong {
		t.Fatalf("Hash(ctx(), overlong) error = %v, want ErrPasswordTooLong", err)
	}
	if _, err := Hash(ctx(), strings.Repeat("x", maxPasswordLen)); err != nil {
		t.Fatalf("Hash at exactly maxPasswordLen: %v", err)
	}
}

// TestEmptyDigestNeverVerifies: the 63 live federated users hold an empty
// digest. An empty password must not authenticate them.
func TestEmptyDigestNeverVerifies(t *testing.T) {
	for _, pw := range []string{"", "anything"} {
		if ok, _ := Verify(ctx(), "", pw); ok {
			t.Fatalf("empty digest verified against %q — federated accounts would be open", pw)
		}
	}
}

// mintAt builds an argon2id PHC digest at arbitrary parameters, for test
// fixtures that must not depend on current policy.
func mintAt(t *testing.T, plaintext string, memory, time uint32, threads uint8) string {
	t.Helper()
	salt := []byte("0123456789abcdef")
	key, err := idKey(ctx(), []byte(plaintext), salt, time, memory, threads, keyLen)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
}

// paramsOf returns just the scheme+parameter prefix of a digest — never the
// salt or key — so a failure message can name what went wrong without printing
// credential material.
func paramsOf(digest string) string {
	parts := strings.Split(digest, "$")
	if len(parts) < 4 {
		return "<unparseable>"
	}
	return strings.Join(parts[:4], "$")
}

// ctx is the test context for the gate. Every hash runs under one, so the tests
// name it once here rather than at ~40 call sites.
func ctx() context.Context { return context.Background() }
