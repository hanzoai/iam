// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package users

import (
	"context"
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
//     password is checked — a correct password does not unlock it early;
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
// it is swallowed (the in-memory decision holds).
//
// The user MUST be a row loaded through the store (the (owner,name) query path stamps
// its real orm storage key); the counter save re-reads by that key, so it works for
// BOTH a users.Create'd account (auto-int64 key) and a migrated casdoor row
// (owner/name key). See saveLoginCounters.
func Authenticate(ctx context.Context, db orm.DB, user *schema.User, password, orgPasswordType string, now time.Time) (ok, locked bool) {
	if user == nil {
		return false, false
	}
	if user.SigninWrongTimes >= LockThreshold && withinLockWindow(user.LastSigninWrongTime, now) {
		return false, true
	}
	if VerifyPassword(user, password, orgPasswordType) {
		if user.SigninWrongTimes != 0 {
			user.SigninWrongTimes = 0
			user.LastSigninWrongTime = ""
			saveLoginCounters(ctx, db, user)
		}
		return true, false
	}
	// Wrong password: restart the count if the previous window lapsed, then bump.
	if !withinLockWindow(user.LastSigninWrongTime, now) {
		user.SigninWrongTimes = 0
	}
	user.SigninWrongTimes++
	user.LastSigninWrongTime = now.UTC().Format(time.RFC3339)
	saveLoginCounters(ctx, db, user)
	return false, user.SigninWrongTimes >= LockThreshold
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

// saveLoginCounters persists ONLY the lockout counters onto the stored row — a
// read-modify-write that leaves every other field (and the immutable Id) untouched.
// Best-effort by design (see Authenticate).
//
// It re-reads the row through the ONE (owner,name) query path — the same load the
// verify used — which stamps the row's REAL storage key (First → SetKey), then writes
// back by THAT key. This is load-bearing: schema.User is registered without
// WithStringKey, so a users.Create'd account is keyed by an auto-allocated int64
// (orm.Model.Id_), NOT by "owner/name"; only a migrated casdoor row is keyed by
// owner/name. A save keyed by owner/name matched a row ONLY for the migrated shape, so
// every post-cutover account's counter silently vanished and the account never
// locked — the online brute-force oracle F-D1 was meant to close. Re-reading fresh
// keeps the write counter-only for BOTH shapes: fresh mirrors the stored state, so
// only the two counters differ from what is persisted.
func saveLoginCounters(ctx context.Context, db orm.DB, u *schema.User) {
	fresh, err := store.GetUserByName(ctx, db, u.Owner, u.Name)
	if err != nil || fresh == nil {
		return
	}
	fresh.SigninWrongTimes = u.SigninWrongTimes
	fresh.LastSigninWrongTime = u.LastSigninWrongTime
	_ = fresh.UpdateCtx(ctx)
}
