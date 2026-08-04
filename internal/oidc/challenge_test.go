// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// ITEM 4: TakeChallenge burns a login challenge exactly once. A captured MFA passcode
// rides on ONE challenge id; if two concurrent finishMfa calls both observe Used=false
// and both mark it used, the passcode is double-spent (the F-D1 lost-update/TOCTOU
// class). The burn runs inside a GetForUpdate transaction, so exactly one caller wins.

func TestTakeChallenge_concurrentBurn_exactlyOneWinner(t *testing.T) {
	db := openTestDB(t)
	ctx := tctx()
	now := time.Now()

	id, err := MintChallenge(ctx, db, KindMfa, "hanzo/alice", "", now)
	if err != nil {
		t.Fatalf("mint challenge: %v", err)
	}

	const N = 16
	var wins int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if ch, err := TakeChallenge(ctx, db, id, KindMfa, now); err == nil && ch != nil {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Fatalf("concurrent TakeChallenge on one id produced %d winners, want exactly 1 — a captured passcode can be double-spent (ITEM 4)", wins)
	}
}

// I1: BurnFederationState consumes an in-flight federation transaction exactly once —
// the OAuth-callback single-use guard, the exact twin of TakeChallenge. Two concurrent
// callbacks on one `state` must not both flip Used=false→true (double-completion of the
// same federated login). The burn runs inside a GetForUpdate transaction, so exactly one
// wins.
func TestBurnFederationState_concurrentBurn_exactlyOneWinner(t *testing.T) {
	db := openTestDB(t)
	ctx := tctx()
	now := time.Now()

	const state = "fedstate-0123456789abcdef0123456789abcdef" // opaque state token = row Name
	if err := store.PersistFederationState(ctx, db, &schema.FederationState{
		Owner:    "admin",
		Name:     state,
		ExpireIn: now.Add(5 * time.Minute).Unix(),
	}); err != nil {
		t.Fatalf("persist federation state: %v", err)
	}

	const N = 16
	var wins int64
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if st, err := store.BurnFederationState(ctx, db, state, now); err == nil && st != nil {
				atomic.AddInt64(&wins, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Fatalf("concurrent BurnFederationState on one state produced %d winners, want exactly 1 — a federation callback can be double-completed (I1)", wins)
	}
}
