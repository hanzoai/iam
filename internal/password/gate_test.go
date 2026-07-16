// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package password

import (
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The memory bound is only real if the argon2id paths actually consult the
// gate. These tests prove that by its observable effect — fill the gate, and
// the operation must not be able to proceed — rather than by asserting on the
// channel itself, which would pass even if nothing used it.

// fillGate takes every slot and returns a release func.
func fillGate(t *testing.T) func() {
	t.Helper()
	for i := 0; i < cap(gate); i++ {
		gate <- struct{}{}
	}
	released := false
	return func() {
		if released {
			return
		}
		released = true
		for i := 0; i < cap(gate); i++ {
			<-gate
		}
	}
}

// blocks reports whether fn is still running after a grace period.
func blocks(fn func()) bool {
	done := make(chan struct{})
	go func() { fn(); close(done) }()
	select {
	case <-done:
		return false
	case <-time.After(150 * time.Millisecond):
		return true
	}
}

// TestHashIsGated: minting holds 19 MiB, so it must wait for a slot.
func TestHashIsGated(t *testing.T) {
	release := fillGate(t)
	defer release()

	if !blocks(func() { _, _ = Hash(ctx(), "x") }) {
		t.Fatal("Hash ran with the gate full — it does not take a slot, so the memory bound is fiction")
	}
}

// TestVerifyArgon2idIsGated is the one that matters: verify is the
// UNAUTHENTICATED path, and a live v1 row holds 67 MB per in-flight call.
func TestVerifyArgon2idIsGated(t *testing.T) {
	release := fillGate(t)
	defer release()

	if !blocks(func() { _, _ = Verify(ctx(), liveArgon2idDigest, liveArgon2idPassword) }) {
		t.Fatal("argon2id verify ran with the gate full — an unauthenticated caller sets the memory peak")
	}
}

// TestGatedWorkCompletesOnceSlotsFree: the gate must bound concurrency, not
// deadlock it. A blocked hash proceeds the moment a slot is returned, and
// returns its own slot afterwards.
func TestGatedWorkCompletesOnceSlotsFree(t *testing.T) {
	release := fillGate(t)

	done := make(chan string, 1)
	go func() {
		d, err := Hash(ctx(), "eventually")
		if err != nil {
			done <- ""
			return
		}
		done <- d
	}()

	release() // hand the slots back
	select {
	case digest := <-done:
		if digest == "" {
			t.Fatal("Hash errored once unblocked")
		}
		if ok, _ := Verify(ctx(), digest, "eventually"); !ok {
			t.Fatal("digest minted through the gate does not verify")
		}
	case <-time.After(30 * time.Second):
		t.Fatal("Hash never completed after slots were freed — the gate deadlocks")
	}

	// Every slot must have been returned: the gate is reusable, not leaked.
	if len(gate) != 0 {
		t.Fatalf("%d gate slots leaked — a leak would eventually starve every login", len(gate))
	}
}

// TestBcryptVerifyIsNotGated: bcrypt holds ~5 KB, not 19-67 MB, so it has no
// business queueing behind memory-hungry argon2id work. Gating it would make
// the 40 legacy rows contend for a bound that exists for a cost they do not
// have.
//
// Deliberately uses a MinCost digest rather than the live cost-10 vector: at
// cost 10 bcrypt takes ~39ms, which inflates past any grace period under -race
// and would make this assert on the race detector's overhead instead of on the
// gate. The claim under test is "the bcrypt branch takes no slot", and cost is
// irrelevant to it.
func TestBcryptVerifyIsNotGated(t *testing.T) {
	cheap, err := bcrypt.GenerateFromPassword([]byte(liveBcryptPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	release := fillGate(t)
	defer release()

	if blocks(func() { _, _ = Verify(ctx(), string(cheap), liveBcryptPassword) }) {
		t.Fatal("bcrypt verify queued behind the argon2id gate — it holds ~5 KB and need not")
	}
}
