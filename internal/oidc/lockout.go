// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/users"
)

// Account lockout — casdoor's compensating control for a password endpoint, ported
// to the ONE credential-verify choke point the interactive login form and the ROPC
// password grant share. Casdoor locked an account after a run of wrong passwords;
// commit D adopted casdoor's PUBLIC-ROPC endpoint, so without this it is an
// unauthenticated online brute-force oracle (F-D1). State lives on the user row
// (SigninWrongTimes / LastSigninWrongTime — already in schema.User), so it is
// per-account and survives restarts.

const (
	// signinWrongLimit is the consecutive-wrong-password count that locks an account
	// (casdoor's SigninWrongTimesLimit).
	signinWrongLimit = 5
	// lockoutWindow is how long a lock — and the running count — persists since the
	// last wrong attempt (casdoor's LastSignWrongTimeDuration). Once it elapses the
	// count restarts, so an occasional typo never accumulates toward a lock.
	lockoutWindow = 15 * time.Minute
)

// verifyLoginPassword is the single credential check for the login form and the ROPC
// password grant. It enforces lockout AROUND users.VerifyPassword:
//   - a locked account (count ≥ limit within the window) is refused BEFORE the
//     password is checked — a correct password does not unlock it early;
//   - a wrong password increments the count (restarting it when the previous window
//     lapsed) and stamps the time;
//   - a correct, unlocked password resets the count to zero.
//
// Returns (ok, locked): ok is true ONLY for a correct password on an unlocked
// account; locked is true when the refusal is the lockout, so the caller emits a
// distinct message that never reveals whether the password was in fact correct. A
// nil user (unknown login) is (false, false) — there is no row to lock, and the
// caller returns the same opaque error as a wrong password (no enumeration on the
// first attempt). Counter writes are best-effort: a persist fault must not convert a
// correct login into an error, so it is swallowed (the in-memory decision holds).
func verifyLoginPassword(ctx context.Context, db orm.DB, user *schema.User, password, orgPasswordType string, now time.Time) (ok, locked bool) {
	if user == nil {
		return false, false
	}
	if user.SigninWrongTimes >= signinWrongLimit && withinLockoutWindow(user.LastSigninWrongTime, now) {
		return false, true
	}
	if users.VerifyPassword(user, password, orgPasswordType) {
		if user.SigninWrongTimes != 0 {
			user.SigninWrongTimes = 0
			user.LastSigninWrongTime = ""
			saveLoginCounters(ctx, db, user)
		}
		return true, false
	}
	// Wrong password: restart the count if the previous window lapsed, then bump.
	if !withinLockoutWindow(user.LastSigninWrongTime, now) {
		user.SigninWrongTimes = 0
	}
	user.SigninWrongTimes++
	user.LastSigninWrongTime = now.UTC().Format(time.RFC3339)
	saveLoginCounters(ctx, db, user)
	return false, user.SigninWrongTimes >= signinWrongLimit
}

// withinLockoutWindow reports whether the last wrong attempt is recent enough that
// the running count still applies. An unparseable/empty stamp is treated as "not in
// a window" (fail toward restarting the count, never toward a spurious lock).
func withinLockoutWindow(lastWrong string, now time.Time) bool {
	if lastWrong == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, lastWrong)
	if err != nil {
		return false
	}
	return now.Sub(t) < lockoutWindow
}

// saveLoginCounters persists ONLY the lockout counters onto the stored row, by the
// (owner,name) key — a read-modify-write that leaves every other field (and the
// immutable Id) untouched. Best-effort by design (see verifyLoginPassword).
func saveLoginCounters(ctx context.Context, db orm.DB, u *schema.User) {
	existing, err := orm.Get[schema.User](db, u.Owner+"/"+u.Name)
	if err != nil {
		return
	}
	existing.SigninWrongTimes = u.SigninWrongTimes
	existing.LastSigninWrongTime = u.LastSigninWrongTime
	_ = existing.UpdateCtx(ctx)
}
