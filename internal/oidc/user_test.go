// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
)

// ITEM 2: a full-row user writer (onboard / preferences / the sk- key mint-revoke) must
// not erase the lockout counter a concurrent wrong-password attempt advanced. Every such
// writer now goes through updateUser, which reads the row FRESH under a GetForUpdate row
// lock and writes it back, so the counter (advanced atomically by users.recordAttempt on
// the same row lock) is carried forward, never overwritten by a stale snapshot.

// TestUpdateUser_preservesConcurrentLockoutCount is the crisp differential proof of the
// fix, deterministic (no goroutines). A CONTROL branch reproduces the pre-fix hazard: a
// stale full-row write (user.UpdateCtx on a snapshot loaded before the counter advanced —
// exactly what onboard/preferences/saveUser did) resets the persisted counter to the
// snapshot's stale 0. The FIX branch runs the same sequence through updateUser, which
// reads the row fresh under the lock and preserves the advanced counter.
func TestUpdateUser_preservesConcurrentLockoutCount(t *testing.T) {
	db := openTestDB(t)
	ctx := tctx()

	mk := func(name string) {
		if _, err := users.New(db).Create(ctx, &users.CreateInput{
			User:     schema.User{Owner: "hanzo", Name: name},
			Password: "pw",
		}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	advanceTo3 := func(name string) {
		for i := 0; i < 3; i++ { // three FRESH-loaded wrong attempts persist a count of 3
			fresh, err := store.GetUserByName(ctx, db, "hanzo", name)
			if err != nil || fresh == nil {
				t.Fatalf("reload %s: %v", name, err)
			}
			users.Authenticate(ctx, db, fresh, "WRONG", "", time.Now())
		}
		got, _ := store.GetUserByName(ctx, db, "hanzo", name)
		if got.SigninWrongTimes != 3 {
			t.Fatalf("setup: %s persisted count = %d, want 3", name, got.SigninWrongTimes)
		}
	}

	// --- CONTROL: the pre-fix stale full-row write erases the counter. ---
	mk("naive")
	stale, err := store.GetUserByName(ctx, db, "hanzo", "naive") // snapshot at count 0
	if err != nil || stale == nil {
		t.Fatalf("load stale snapshot: %v", err)
	}
	advanceTo3("naive")
	stale.DisplayName = "changed"
	if err := stale.UpdateCtx(ctx); err != nil { // the pre-fix writer: whole stale row written
		t.Fatalf("naive write: %v", err)
	}
	if got, _ := store.GetUserByName(ctx, db, "hanzo", "naive"); got.SigninWrongTimes != 0 {
		t.Fatalf("control: a stale full-row write was expected to RESET the counter (the bug), got %d — control invalid", got.SigninWrongTimes)
	}

	// --- FIX: updateUser reads fresh under the row lock and preserves the counter. ---
	mk("fixed")
	if _, err := store.GetUserByName(ctx, db, "hanzo", "fixed"); err != nil { // an equally-stale snapshot exists in the wild
		t.Fatalf("load: %v", err)
	}
	advanceTo3("fixed")
	if _, err := updateUser(ctx, db, "hanzo", "fixed", func(u *schema.User) error {
		u.DisplayName = "changed"
		return nil
	}); err != nil {
		t.Fatalf("updateUser: %v", err)
	}
	got, _ := store.GetUserByName(ctx, db, "hanzo", "fixed")
	if got.SigninWrongTimes != 3 {
		t.Fatalf("updateUser reset the lockout counter to %d, want 3 preserved (ITEM 2)", got.SigninWrongTimes)
	}
	if got.DisplayName != "changed" {
		t.Fatalf("updateUser did not apply the intended mutation: DisplayName=%q", got.DisplayName)
	}
}

// TestUpdateUser_concurrentWithLockIncrement_exactCount is the -race concurrency proof:
// N full-row updateUser writes (changing an unrelated field) racing N atomic wrong-
// password increments must leave the persisted counter at EXACTLY N. A single lost
// update — an updateUser write reverting a counted increment — would drop it below N and
// re-open the brute-force oracle. Because both take the same row lock, they serialize and
// none is lost.
func TestUpdateUser_concurrentWithLockIncrement_exactCount(t *testing.T) {
	db := openTestDB(t)
	ctx := tctx()

	if _, err := users.New(db).Create(ctx, &users.CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "race"},
		Password: "pw",
	}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Stay strictly below the lock threshold so the count is exact (a locked account
	// stops counting), isolating "no lost update" from the lock cap.
	N := users.LockThreshold - 1
	if N < 2 {
		t.Fatalf("need at least 2 to exercise the race")
	}

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			fresh, _ := store.GetUserByName(ctx, db, "hanzo", "race")
			users.Authenticate(ctx, db, fresh, "WRONG", "", time.Now())
		}()
	}
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			// The full-row writer under test; it must not clobber the counter.
			_, _ = updateUser(ctx, db, "hanzo", "race", func(u *schema.User) error {
				u.DisplayName = fmt.Sprintf("d%d", n)
				return nil
			})
		}(i)
	}
	close(start)
	wg.Wait()

	got, err := store.GetUserByName(ctx, db, "hanzo", "race")
	if err != nil || got == nil {
		t.Fatalf("reload: %v", err)
	}
	if got.SigninWrongTimes != N {
		t.Fatalf("persisted SigninWrongTimes = %d, want exactly %d — a full-row updateUser write erased a concurrent lock increment (ITEM 2)", got.SigninWrongTimes, N)
	}
}
