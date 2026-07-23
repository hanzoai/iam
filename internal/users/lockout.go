// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package users

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// Account lockout — casdoor's compensating control for a password endpoint, kept in
// the ONE credential package so every human-credential verify shares it: the
// interactive login form, the ROPC password grant, the registry Basic-auth token
// endpoint, and the LDAP-bind feature seam all call Authenticate, never the raw
// VerifyPassword digest check. Casdoor locked an account after a run of wrong
// passwords; the public ROPC endpoint (commit D) would otherwise be an
// unauthenticated online brute-force oracle. State lives on the user row
// (SigninWrongTimes / LastSigninWrongTime — already in schema.User), so it is
// per-account and survives restarts.
//
// The running count is a SHARED MUTABLE CELL, so the failed-attempt increment must
// be atomic against concurrent wrong attempts. A read-at-handler-entry, then
// in-memory bump, then full-row write loses updates: a generation of C parallel
// wrongs that each captured the same pre-increment snapshot all persist snapshot+1,
// so C concurrent guesses advance the persisted counter by only ONE — the account
// never locks and the brute-force oracle F-D1 exists to kill re-opens. The mutation
// therefore runs inside a ROW-LOCKED TRANSACTION (recordAttempt): every increment
// reads the FRESH persisted value under the lock and writes back from it, so C
// serialized wrongs advance the counter by exactly C. See recordAttempt for why
// this is correct under the production topology.

const (
	// LockThreshold is the consecutive-wrong-password count that locks an account
	// (casdoor's SigninWrongTimesLimit). Exported so a caller's tests can drive
	// exactly the boundary without re-declaring the policy.
	LockThreshold = 5
	// lockWindow is how long a lock — and the running count — persists since the last
	// wrong attempt (casdoor's LastSignWrongTimeDuration). Once it elapses the count
	// restarts, so an occasional typo never accumulates toward a lock.
	lockWindow = 15 * time.Minute
)

// Authenticate is the single human-credential check. It enforces lockout AROUND the
// raw VerifyPassword digest comparison:
//   - a locked account (count ≥ threshold within the window) is refused BEFORE the
//     password is honored — a correct password does not unlock it early;
//   - a wrong password increments the count (restarting it when the previous window
//     lapsed) and stamps the time;
//   - a correct, unlocked password resets the count to zero.
//
// Returns (ok, locked): ok is true ONLY for a correct password on an unlocked
// account; locked is true when the refusal is the lockout, so the caller can emit a
// distinct message that never reveals whether the password was in fact correct. A nil
// user (unknown login) is (false, false) — there is no row to lock, and the caller
// returns the same opaque error as a wrong password (no enumeration). Counter writes
// are best-effort: a persist fault must not convert a correct login into an error, so
// it is swallowed (the verify verdict holds).
//
// The digest comparison (argon2id/bcrypt) is deliberately slow and CPU-bound; it runs
// OUTSIDE the counter transaction so a login never holds the store's write lock across
// a password hash — that would serialize every concurrent login in the process behind
// one verify, a self-inflicted DoS. Only its boolean result crosses into the atomic
// counter update, which is the sole part that must be serialized.
func Authenticate(ctx context.Context, db orm.DB, user *schema.User, password, orgPasswordType string, now time.Time) (ok, locked bool) {
	if user == nil {
		return false, false
	}
	passwordOK := VerifyPassword(user, password, orgPasswordType)
	return recordAttempt(ctx, db, user.Owner, user.Name, passwordOK, now)
}

// recordAttempt applies the lockout decision atomically against the user's FRESH
// persisted counter and returns (ok, locked). passwordOK is the already-computed
// digest verdict (see Authenticate); this function performs NO password comparison,
// only the counter accounting.
//
// Atomicity mechanism and why it is correct under the production topology:
//
// The clean-room iam runs as an embedded subsystem of the ONE cloud binary, backed by
// hanzoai/orm over SQLite (store.Open("sqlite", …), WAL + busy_timeout) on a
// ReadWriteOnce volume — a single writer process. The SQLite backend opens its write
// handle with MaxOpenConns(1) and guards every write path (and every RunInTransaction)
// with one process-wide write mutex held for the FULL transaction, so a read→check→write
// inside RunInTransaction cannot interleave with any other writer in the process. The
// mechanism is NOT a process-local application mutex — which would not serialize across
// replicas — but the STORE's own transaction with a row lock: orm.GetForUpdate takes an
// exclusive lock on the row for the life of the transaction (a real SELECT … FOR UPDATE
// on the hanzoai/sql/Postgres backend; the write-mutex-serialized read under SQLite), so
// the same code is correct whether the store is single-writer SQLite today or a shared
// SQL backend under N replicas tomorrow. This mirrors the wallet challenge-burn CAS
// (internal/wallet/store.go), the established row-lock pattern in this repo.
//
// The row's storage key is resolved ONCE via the (owner,name) query path (which stamps
// the real orm key — an auto-int64 for a users.Create'd row, "owner/name" for a migrated
// casdoor row), then the lock is taken by that exact key. Reading the FRESH row and
// writing it back under the held lock keeps recordAttempt's OWN write free of lost
// updates. It does NOT, by itself, stop a DIFFERENT user-row writer from erasing this
// counter with a stale full-row write; that is prevented by routing every such writer
// through the SAME row lock (internal/oidc updateUser reads the row fresh under the lock
// and preserves the counter), so no snapshot can overwrite it (Red PoC4). Atomicity
// comes from the lock, not column scoping (a JSON-document store has no per-column write).
func recordAttempt(ctx context.Context, db orm.DB, owner, name string, passwordOK bool, now time.Time) (ok, locked bool) {
	keyed, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil || keyed == nil {
		// No row to lock (deleted under us, or a transient read fault). The counter is
		// best-effort — a persist fault must never turn a correct login into an error —
		// so fall back to the stateless verify verdict.
		return passwordOK, false
	}
	storageID := keyed.Key().Encode()

	var outOK, outLocked bool
	txErr := db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := orm.GetForUpdate[schema.User](tx, storageID)
		if err != nil {
			if errors.Is(err, orm.ErrNotFound) {
				outOK, outLocked = passwordOK, false
				return nil
			}
			return err
		}
		// Authoritative lock decision on the FRESH counter, under the row lock. A
		// correct password does NOT unlock a locked account early, and a wrong attempt
		// against an already-locked account neither increments nor extends it (no stamp
		// bump), so the lock expires the window after the LAST pre-lock wrong attempt.
		if fresh.SigninWrongTimes >= LockThreshold && withinLockWindow(fresh.LastSigninWrongTime, now) {
			outOK, outLocked = false, true
			return nil
		}
		if passwordOK {
			outOK = true
			// Reset a sub-threshold running count. Skip the write when already clear so a
			// clean login neither rewrites the row nor races a concurrent unrelated update.
			if fresh.SigninWrongTimes != 0 || fresh.LastSigninWrongTime != "" {
				fresh.SigninWrongTimes = 0
				fresh.LastSigninWrongTime = ""
				return fresh.UpdateCtx(ctx)
			}
			return nil
		}
		// Wrong password, not locked: restart the count if the previous window lapsed,
		// then bump FROM THE FRESH value. The row lock is held from the GetForUpdate read
		// through this write, so C concurrent wrongs serialize and advance by exactly C.
		if !withinLockWindow(fresh.LastSigninWrongTime, now) {
			fresh.SigninWrongTimes = 0
		}
		fresh.SigninWrongTimes++
		fresh.LastSigninWrongTime = now.UTC().Format(time.RFC3339)
		if err := fresh.UpdateCtx(ctx); err != nil {
			return err
		}
		outLocked = fresh.SigninWrongTimes >= LockThreshold
		return nil
	})
	if txErr != nil {
		// Persist fault: keep the best-effort contract — the correct/wrong verdict still
		// holds, we just could not record the attempt (never a spurious lock).
		return passwordOK, false
	}
	return outOK, outLocked
}

// withinLockWindow reports whether the last wrong attempt is recent enough that the
// running count still applies. An unparseable/empty stamp is treated as "not in a
// window" (fail toward restarting the count, never toward a spurious lock).
func withinLockWindow(lastWrong string, now time.Time) bool {
	if lastWrong == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, lastWrong)
	if err != nil {
		return false
	}
	return now.Sub(t) < lockWindow
}
