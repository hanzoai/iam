// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// TestAuthenticate_ConcurrentWrongPasswords_NoLostUpdates is the crisp atomicity
// proof: C concurrent wrong attempts BELOW the lock threshold must advance the
// persisted counter by EXACTLY C. Pre-fix, every goroutine bumps its own stale 0→1
// snapshot and the full-row save writes 1, so C parallel wrongs persist a counter of
// 1 — this test FAILS (want C, got 1). The fix reads-and-increments the FRESH row
// under a per-row lock, so the counter is exactly C.
func TestAuthenticate_ConcurrentWrongPasswords_NoLostUpdates(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "lockout-noloss.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	const org, name, pw = "hanzo", "victim", "correct horse battery staple"
	if _, err := New(db).Create(ctx, &CreateInput{
		User:     schema.User{Owner: org, Name: name, Email: "victim@hanzo.ai"},
		Password: pw,
	}); err != nil {
		t.Fatalf("create user through the canonical path: %v", err)
	}

	// Stay strictly below the threshold so the lock cap never truncates the count —
	// this isolates the increment atomicity: the answer must be exactly C.
	C := LockThreshold - 1
	if C < 2 {
		t.Fatalf("need at least 2 concurrent attempts to exercise the race")
	}

	snaps := make([]*schema.User, C)
	for i := range snaps {
		u, err := store.GetUserByName(ctx, db, org, name)
		if err != nil || u == nil {
			t.Fatalf("load snapshot %d: %v", i, err)
		}
		if u.SigninWrongTimes != 0 {
			t.Fatalf("snapshot %d loaded at count %d, want 0", i, u.SigninWrongTimes)
		}
		snaps[i] = u
	}

	now := time.Now()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < C; i++ {
		wg.Add(1)
		go func(u *schema.User) {
			defer wg.Done()
			<-start
			Authenticate(ctx, db, u, "WRONG", "", now)
		}(snaps[i])
	}
	close(start)
	wg.Wait()

	final, err := store.GetUserByName(ctx, db, org, name)
	if err != nil || final == nil {
		t.Fatalf("reload after flood: %v", err)
	}
	if final.SigninWrongTimes != C {
		t.Fatalf("persisted SigninWrongTimes = %d, want exactly %d — concurrent increments were lost (brute-force oracle re-opened)",
			final.SigninWrongTimes, C)
	}
}

// TestAuthenticate_ConcurrentFlood_Locks is the security outcome: a flood of C ≫
// threshold parallel wrong attempts (Red's PoC) must LOCK the account — the correct
// password is refused afterward. Pre-fix the flood persists a counter of 1 and the
// account never locks; the fix accumulates past the threshold and locks. The counter
// caps AT the threshold (a locked account stops counting — legacy semantics), so the
// assertion is "reached the lock", not "== C".
func TestAuthenticate_ConcurrentFlood_Locks(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "lockout-flood.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	const org, name, pw = "hanzo", "target", "s0verysecret correct pw"
	if _, err := New(db).Create(ctx, &CreateInput{
		User:     schema.User{Owner: org, Name: name},
		Password: pw,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	const C = 32 // ≫ LockThreshold, many generations of concurrent wrongs
	snaps := make([]*schema.User, C)
	for i := range snaps {
		u, err := store.GetUserByName(ctx, db, org, name)
		if err != nil || u == nil {
			t.Fatalf("load snapshot %d: %v", i, err)
		}
		snaps[i] = u
	}

	now := time.Now()
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < C; i++ {
		wg.Add(1)
		go func(u *schema.User) {
			defer wg.Done()
			<-start
			Authenticate(ctx, db, u, "WRONG", "", now)
		}(snaps[i])
	}
	close(start)
	wg.Wait()

	final, err := store.GetUserByName(ctx, db, org, name)
	if err != nil || final == nil {
		t.Fatalf("reload: %v", err)
	}
	if final.SigninWrongTimes < LockThreshold {
		t.Fatalf("persisted SigninWrongTimes = %d, want ≥ threshold %d — increments lost, account never locks",
			final.SigninWrongTimes, LockThreshold)
	}
	// The CORRECT password is refused: the account is locked, so the endpoint cannot
	// confirm (or brute-force) the password.
	ok, locked := Authenticate(ctx, db, final, pw, "", now)
	if ok || !locked {
		t.Fatalf("after %d parallel wrongs: ok=%v locked=%v — want refused and locked", C, ok, locked)
	}
}

// F-6: the canonical admin profile edit (POST /v1/iam/update-user -> API.Update) must
// NOT reset the lockout counter. Update is a full-row write; a body that omits
// signinWrongTimes (the common case) or sends 0 would overwrite a LOCKED account's
// counter to 0 — a routine profile edit silently unlocks the user mid-attack. Lockout
// state is server-owned, carried from the stored row like Id/CreatedTime. FAILS before
// the fix (counter 0), PASSES after (counter preserved at the lock threshold).
func TestUpdate_preservesLockoutCounter(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "f6-update.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	const org, name, pw = "hanzo", "victim", "correct horse battery staple"
	if _, err := New(db).Create(ctx, &CreateInput{
		User:     schema.User{Owner: org, Name: name, Email: "victim@hanzo.ai"},
		Password: pw,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Lock the account.
	now := time.Now()
	for i := 0; i < LockThreshold; i++ {
		u, _ := store.GetUserByName(ctx, db, org, name)
		Authenticate(ctx, db, u, "WRONG", "", now)
	}
	locked, _ := store.GetUserByName(ctx, db, org, name)
	if locked.SigninWrongTimes < LockThreshold {
		t.Fatalf("setup: counter=%d, want >= threshold %d", locked.SigninWrongTimes, LockThreshold)
	}

	// A routine admin profile edit — the body carries the ZERO-value counter (omitted in
	// JSON). It must change DisplayName WITHOUT touching the lockout state.
	if _, err := New(db).Update(ctx, &UpdateInput{
		User: schema.User{Owner: org, Name: name, Email: "victim@hanzo.ai", DisplayName: "Victim V"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	after, _ := store.GetUserByName(ctx, db, org, name)
	if after.SigninWrongTimes < LockThreshold {
		t.Fatalf("update-user reset the lockout counter to %d (want >= threshold %d) — a profile edit unlocked a locked account (F-6)", after.SigninWrongTimes, LockThreshold)
	}
	if after.DisplayName != "Victim V" {
		t.Fatalf("update did not apply the intended DisplayName change: %q", after.DisplayName)
	}
}

// TestAuthenticate_SequentialLockAndReset covers the single-threaded contract the
// atomic rewrite must preserve: a run of wrongs locks; a correct password on a
// sub-threshold count resets it; a correct password on a LOCKED account is still
// refused (no early unlock); and the counter persists across fresh reloads (the
// int64-key shape). It is the non-concurrent guard that the tx refactor did not
// regress plain lockout semantics.
func TestAuthenticate_SequentialLockAndReset(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "lockout-seq.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	const org, name, pw = "hanzo", "seq", "s3cret-pw correct"
	if _, err := New(db).Create(ctx, &CreateInput{
		User:     schema.User{Owner: org, Name: name},
		Password: pw,
	}); err != nil {
		t.Fatalf("create: %v", err)
	}
	now := time.Now()

	// Sub-threshold wrongs accumulate on the persisted row.
	for i := 1; i < LockThreshold; i++ {
		u, _ := store.GetUserByName(ctx, db, org, name)
		if ok, locked := Authenticate(ctx, db, u, "WRONG", "", now); ok || locked {
			t.Fatalf("wrong %d: ok=%v locked=%v, want refused, not yet locked", i, ok, locked)
		}
		got, _ := store.GetUserByName(ctx, db, org, name)
		if got.SigninWrongTimes != i {
			t.Fatalf("after %d wrongs, persisted count = %d, want %d", i, got.SigninWrongTimes, i)
		}
	}

	// A correct password below the threshold resets the count.
	u, _ := store.GetUserByName(ctx, db, org, name)
	if ok, locked := Authenticate(ctx, db, u, pw, "", now); !ok || locked {
		t.Fatalf("correct pw sub-threshold: ok=%v locked=%v, want accepted", ok, locked)
	}
	if got, _ := store.GetUserByName(ctx, db, org, name); got.SigninWrongTimes != 0 {
		t.Fatalf("correct pw did not reset the count: %d", got.SigninWrongTimes)
	}

	// Drive it to the lock.
	for i := 0; i < LockThreshold; i++ {
		u, _ := store.GetUserByName(ctx, db, org, name)
		Authenticate(ctx, db, u, "WRONG", "", now)
	}
	locked0, _ := store.GetUserByName(ctx, db, org, name)
	if locked0.SigninWrongTimes < LockThreshold {
		t.Fatalf("count = %d, want ≥ threshold %d", locked0.SigninWrongTimes, LockThreshold)
	}
	// Correct password on a LOCKED account is refused — no early unlock.
	if ok, locked := Authenticate(ctx, db, locked0, pw, "", now); ok || !locked {
		t.Fatalf("correct pw on locked account: ok=%v locked=%v, want refused+locked", ok, locked)
	}
}
