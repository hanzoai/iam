// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package password is the one place Hanzo IAM turns a plaintext password into a
// stored digest, and the one place it checks a plaintext against one. Nothing
// else in the tree imports a hash function; a second opinion about how a
// password is stored is the bug this package exists to make impossible.
//
// # The digest describes itself
//
// Verify dispatches on the stored bytes, never on a type column. Every digest
// we can encounter names its own algorithm and carries its own parameters:
//
//	$argon2id$v=19$m=65536,t=1,p=2$<salt>$<hash>   argon2id (PHC string)
//	$2a$10$<salt+hash>                             bcrypt (also $2b$, $2y$)
//
// A `passwordType` column alongside the digest is a second source of truth that
// can disagree with the bytes it describes — and the two are written by
// different code at different times, so eventually they do. The bytes win,
// because the bytes are what we must actually verify against.
//
// # Parameters are read, never assumed
//
// Argon2id parameters come out of the stored hash. They are policy only when
// MINTING a digest (Hash); on the verify path they are data. Pinning today's
// parameters into Verify would make every hash minted under yesterday's
// parameters unreadable the day we tune them — which is a self-inflicted
// outage that lands on the login path, where it is most expensive.
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// Argon2id parameters for every NEW digest, per the OWASP Password Storage
// Cheat Sheet ("Password Storage Cheat Sheet", Argon2id section): "Use Argon2id
// with a minimum configuration of 19 MiB of memory, an iteration count of 2,
// and 1 degree of parallelism."
//
// OWASP offers five sets it calls equivalent — m=47104,t=1 / m=19456,t=2 /
// m=12288,t=3 / m=9216,t=4 / m=7168,t=5 (all p=1). We take m=19456,t=2,p=1, the
// stated baseline, because of what this binary actually runs on: the iam pod is
// limited to 2 CPUs and 2 GiB (GOMEMLIMIT=1750MiB). Memory is the scarce,
// attacker-controlled axis there — every in-flight hash holds `memoryKiB` live
// and login is unauthenticated — so of the equivalent sets we prefer the cheap
// end of the memory range over m=47104 (46 MiB), which is 2.4x the footprint
// for the same work. Going further down the ladder (m=7168,t=5) would trade
// that memory for 2.5x the CPU time on a 2-core box, where CPU is what bounds
// login throughput. m=19456,t=2,p=1 is the balance point for this pod.
//
// p=1 (not the p=2 that the live v1 rows carry) because parallelism inside one
// hash cannot help a 2-CPU pod that is already serving concurrent logins: the
// lanes just contend for the same cores. One lane per hash keeps per-login cost
// predictable and lets `gate` do the scheduling.
const (
	memoryKiB = 19456 // 19 MiB
	timeCost  = 2
	lanes     = 1
	saltLen   = 16 // 128-bit random salt, per PHC/RFC 9106
	keyLen    = 32 // 256-bit derived key
)

// minCost is the ACCEPTANCE floor: an argon2id digest at or above it is
// current enough to keep, and only one below it is re-minted on login. It is a
// separate question from what we mint, and conflating the two is a bug in each
// direction — mint policy that doubles as an acceptance test re-hashes accounts
// that are already fine (and, when a live row is stronger than policy, actively
// weakens them).
//
// The unit is the memory-time product (KiB-passes) — Argon2's area-time cost,
// the axis its parameters trade along. The floor is the weakest of the five
// configurations OWASP itself calls equivalent (m=7168, t=5 -> 35840), so every
// OWASP-current digest is accepted, including the three that sit just below our
// own mint cost of 19456*2=38912.
const minCost = 7168 * 5 // 35840 KiB-passes

// maxPasswordLen bounds what we will MINT a digest for. OWASP: "you should
// enforce a maximum password length". It is deliberately not enforced on the
// verify path — a bound introduced today must never lock out an account whose
// password was accepted yesterday.
const maxPasswordLen = 4096

// gate bounds how many argon2id computations run at once. Each one holds
// memoryKiB (19 MiB) of live memory for its duration, so without a bound an
// unauthenticated login endpoint is a memory-exhaustion lever: ~90 concurrent
// requests reach this pod's 1750MiB GOMEMLIMIT and the process is killed —
// which is the one failure that logs everybody out at once.
//
// GOMAXPROCS is the right bound and costs nothing: with p=1 only GOMAXPROCS
// hashes can make real progress anyway, so admitting more buys queueing and a
// larger peak, not throughput. Excess logins wait here (cheap — a parked
// goroutine) instead of allocating (expensive). On the iam pod this caps
// argon2id's footprint at 2 x 19 MiB.
var gate = make(chan struct{}, max(1, runtime.GOMAXPROCS(0)))

// ErrPasswordTooLong is returned by Hash for an input over maxPasswordLen.
var ErrPasswordTooLong = errors.New("password: too long")

// Hash derives a new digest from plaintext. It is always argon2id at the
// current parameters — the ONE way a password becomes storable. The returned
// PHC string carries its own salt and parameters, so it stays verifiable after
// those parameters change.
func Hash(plaintext string) (string, error) {
	if len(plaintext) > maxPasswordLen {
		return "", ErrPasswordTooLong
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password: read salt: %w", err)
	}
	key := idKey([]byte(plaintext), salt, timeCost, memoryKiB, lanes, keyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, timeCost, lanes,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify reports whether plaintext matches digest, and whether digest should be
// replaced by a freshly minted one (stale).
//
// stale is only meaningful when ok is true — never re-hash on a failed guess.
// It is true when the digest is not argon2id (bcrypt, which we are retiring),
// or when it is argon2id weaker than current policy. It is deliberately NOT
// "the parameters differ from policy": the live v1 rows are m=65536,t=1,p=2
// (64 MiB), which is *stronger* than our m=19456,t=2,p=1 baseline, and
// re-hashing those to policy would weaken 85 accounts in the name of an
// upgrade. See stale() for the comparison.
func Verify(digest, plaintext string) (ok, stale bool) {
	switch Scheme(digest) {
	case SchemeArgon2id:
		return verifyArgon2id(digest, plaintext)
	case SchemeBcrypt:
		// bcrypt: correct today, but not the algorithm we mint. A successful
		// verify is the only moment we hold the plaintext, so it is the only
		// moment we can replace the digest.
		err := bcrypt.CompareHashAndPassword([]byte(digest), []byte(plaintext))
		return err == nil, err == nil
	default:
		// Unknown, empty or corrupt digest: fail closed. Never treat an
		// unparseable digest as a match.
		return false, false
	}
}

// The schemes a stored digest can be under. SchemeArgon2id is the only one we
// mint; SchemeBcrypt is verify-and-retire.
const (
	SchemeArgon2id = "argon2id"
	SchemeBcrypt   = "bcrypt"
)

// Scheme names the algorithm a digest is stored under, read from the digest
// itself, or "" if it is under none we know.
//
// It exists so that the stored `passwordType` is DERIVED from the bytes it
// describes instead of being chosen alongside them. Those are the two writes
// that drift apart: v1 sets the organization's type in one place and the user's
// digest in another, so a row can claim argon2id while holding bcrypt bytes.
// Nothing here reads the column to decide how to verify — Verify asks the
// digest — but as long as the column exists it must not be able to lie.
func Scheme(digest string) string {
	switch {
	case strings.HasPrefix(digest, "$argon2id$"):
		return SchemeArgon2id
	case strings.HasPrefix(digest, "$2a$"),
		strings.HasPrefix(digest, "$2b$"),
		strings.HasPrefix(digest, "$2y$"):
		return SchemeBcrypt
	default:
		return ""
	}
}

// verifyArgon2id checks plaintext against a PHC argon2id digest, using the
// parameters the digest itself carries.
func verifyArgon2id(digest, plaintext string) (ok, stale bool) {
	memory, time, threads, salt, want, err := parse(digest)
	if err != nil {
		return false, false
	}
	got := idKey([]byte(plaintext), salt, time, memory, threads, uint32(len(want)))
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return false, false
	}
	return true, weaker(memory, time)
}

// weaker reports whether an argon2id digest at these parameters is below the
// acceptance floor, and so should be re-minted on the next successful login.
//
// It compares against minCost, NOT against our mint parameters. Testing against
// what we mint would flag three of OWASP's five equivalent sets (12288x3 and
// 9216x4 = 36864, 7168x5 = 35840 all sit under our 38912) as stale, and would
// flag the live v1 rows for a "upgrade" that halves their memory hardness.
// What we mint and what we accept are different questions.
func weaker(memory, time uint32) bool {
	return uint64(memory)*uint64(time) < minCost
}

// parse pulls the parameters, salt and key out of a PHC argon2id string:
//
//	$argon2id$v=19$m=65536,t=1,p=2$<b64 salt>$<b64 key>
func parse(digest string) (memory, time uint32, threads uint8, salt, key []byte, err error) {
	// A leading "$" makes the first field empty, hence 6.
	parts := strings.Split(digest, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return 0, 0, 0, nil, nil, errors.New("password: not an argon2id digest")
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return 0, 0, 0, nil, nil, errors.New("password: bad version field")
	}
	if version != argon2.Version {
		return 0, 0, 0, nil, nil, fmt.Errorf("password: unsupported argon2 version %d", version)
	}

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil {
		return 0, 0, 0, nil, nil, errors.New("password: bad parameter field")
	}
	// argon2.IDKey panics on a zero time or thread count; a hostile or corrupt
	// digest must not be able to reach that.
	if memory == 0 || time == 0 || threads == 0 {
		return 0, 0, 0, nil, nil, errors.New("password: zero parameter")
	}

	if salt, err = base64.RawStdEncoding.DecodeString(parts[4]); err != nil {
		return 0, 0, 0, nil, nil, errors.New("password: bad salt encoding")
	}
	if key, err = base64.RawStdEncoding.DecodeString(parts[5]); err != nil {
		return 0, 0, 0, nil, nil, errors.New("password: bad key encoding")
	}
	if len(salt) == 0 || len(key) == 0 {
		return 0, 0, 0, nil, nil, errors.New("password: empty salt or key")
	}
	return memory, time, threads, salt, key, nil
}

// idKey is argon2.IDKey under `gate`, which is the only reason the bound holds:
// every argon2id computation in the process — mint and verify — goes through
// here.
func idKey(plaintext, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte {
	gate <- struct{}{}
	defer func() { <-gate }()
	return argon2.IDKey(plaintext, salt, time, memory, threads, keyLen)
}
