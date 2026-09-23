// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package otp

import (
	"context"
	"testing"
	"time"
)

// A code sent to an address nobody holds yet proves the address to whoever reads
// it — the signup gate — and nothing more. It is spent by the proof, and a wrong
// guess counts exactly as it does against a sign-in code, because the six digits
// are the whole of what stands between a stranger and somebody else's address.

func TestProveSpendsAnAddressCode(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	file(t, db, "hanzo", "new@example.com", "", "424242", now)

	if ok, err := Prove(context.Background(), db, "hanzo", "new@example.com", "424242", now); err != nil || !ok {
		t.Fatalf("the code sent to the address does not prove it: ok=%v err=%v", ok, err)
	}
	if ok, _ := Prove(context.Background(), db, "hanzo", "new@example.com", "424242", now); ok {
		t.Fatal("one code proved an address twice")
	}
}

func TestProveCountsWrongGuesses(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	file(t, db, "hanzo", "new@example.com", "", "424242", now)

	for i := 0; i < MaxAttempts; i++ {
		if ok, _ := Prove(context.Background(), db, "hanzo", "new@example.com", "000000", now); ok {
			t.Fatal("a wrong code proved the address")
		}
	}
	if ok, _ := Prove(context.Background(), db, "hanzo", "new@example.com", "424242", now); ok {
		t.Fatalf("the code survived %d wrong guesses", MaxAttempts)
	}
}

// A code minted for an ACCOUNT is that account's credential; it proves no address
// for anybody else, and another org's code proves nothing here.
func TestProveReadsOnlyAddressCodesInItsOrg(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	file(t, db, "hanzo", "held@example.com", "hanzo/held", "424242", now)
	file(t, db, "lux", "new@example.com", "", "515151", now)

	if ok, _ := Prove(context.Background(), db, "hanzo", "held@example.com", "424242", now); ok {
		t.Fatal("an account's sign-in code proved its address to somebody else")
	}
	if ok, _ := Prove(context.Background(), db, "hanzo", "new@example.com", "515151", now); ok {
		t.Fatal("another org's code proved an address here")
	}
}
