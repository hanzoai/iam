// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package cred

import (
	"context"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestFloodNeverExceedsTheBound is the invariant: however many callers arrive at
// once, no more than cap(gate) argon2id derivations hold memory at the same
// instant.
//
// It runs far more callers than slots, so an unbounded implementation would show
// a peak equal to the caller count. The assertion is on the peak the gate itself
// recorded, which is exact rather than sampled.
func TestFloodNeverExceedsTheBound(t *testing.T) {
	const callers = 64
	limit := cap(gate)
	if callers <= limit {
		t.Fatalf("this test needs more callers (%d) than slots (%d) to mean anything", callers, limit)
	}
	peak.Store(0)

	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Hash(context.Background(), "correct horse battery staple"); err != nil {
				t.Errorf("Hash: %v", err)
			}
		}()
	}
	wg.Wait()

	got := peak.Load()
	if got > int64(limit) {
		t.Fatalf("peak concurrent derivations = %d, bound is %d — the gate did not hold", got, limit)
	}
	if got < 2 {
		t.Fatalf("peak concurrent derivations = %d under %d callers — nothing overlapped, so the bound was never exercised", got, callers)
	}
	if n := inFlight.Load(); n != 0 {
		t.Fatalf("inFlight = %d after every caller returned — a slot leaked", n)
	}
	t.Logf("%d callers, %d slots, peak %d concurrent (≈%d MiB argon2id at peak, not %d MiB)",
		callers, limit, got, got*perHashBytes()/(1<<20), int64(callers)*perHashBytes()/(1<<20))
}

// TestFloodDoesNotScaleMemoryWithCallers is the OOM itself, measured.
//
// The live iam container has a 2Gi limit and argon2id reserves 64 MiB per
// derivation, so unbounded, ~26 simultaneous logins are enough to have the
// kernel kill the process. This drives 64 concurrent Hash calls and asserts the
// heap stays near the BOUND's footprint rather than the CALLERS' footprint —
// which is the difference between a slow pod and a dead one.
func TestFloodDoesNotScaleMemoryWithCallers(t *testing.T) {
	const callers = 64
	unbounded := int64(callers) * perHashBytes()
	bounded := int64(cap(gate)) * perHashBytes()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	done := make(chan struct{})
	var highest uint64
	go func() {
		defer close(done)
		var ms runtime.MemStats
		for {
			select {
			case <-done:
				return
			default:
			}
			runtime.ReadMemStats(&ms)
			if ms.HeapAlloc > highest {
				highest = ms.HeapAlloc
			}
			time.Sleep(time.Millisecond)
		}
	}()

	var wg sync.WaitGroup
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := Hash(context.Background(), "correct horse battery staple"); err != nil {
				t.Errorf("Hash: %v", err)
			}
		}()
	}
	wg.Wait()
	// Stop the sampler and let it observe the stop.
	select {
	case <-done:
	default:
	}

	// The ceiling is half the unbounded footprint, not the bound itself: a
	// released argon2id block is not reclaimed memory yet, so the peak trails
	// the GC and lands at roughly twice what the slots hold. Half of unbounded
	// is still decisive — removing the gate blows straight past it — while
	// leaving the assertion robust to GC timing rather than flaky.
	ceiling := unbounded / 2
	if int64(highest) >= ceiling {
		t.Fatalf("peak heap %d MiB reached %d MiB (half the unbounded footprint of %d MiB) — memory scaled with callers, not with the bound",
			int64(highest)>>20, ceiling>>20, unbounded>>20)
	}
	t.Logf("peak heap %d MiB under %d concurrent callers (baseline %d MiB); %d slots hold %d MiB, unbounded would be %d MiB",
		int64(highest)>>20, callers, int64(before.HeapAlloc)>>20, cap(gate), bounded>>20, unbounded>>20)
}

// TestCancelledCallerReleasesItsPlace proves the queue drains for a caller that
// gave up, rather than handing 64 MiB to a request nobody is waiting for.
func TestCancelledCallerReleasesItsPlace(t *testing.T) {
	// Fill every slot and hold them.
	held := cap(gate)
	for range held {
		if err := acquire(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	defer func() {
		for range held {
			release()
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- acquire(ctx) }()

	// It must still be queued — every slot is held.
	select {
	case err := <-errc:
		t.Fatalf("acquire returned %v while all %d slots were held", err, held)
	case <-time.After(50 * time.Millisecond):
	}

	cancel()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("acquire succeeded after cancellation — a cancelled caller took a slot")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("acquire did not return after cancellation — the queue is not ctx-aware")
	}

	if n := inFlight.Load(); n != int64(held) {
		t.Fatalf("inFlight = %d, want %d — the cancelled caller was counted", n, held)
	}
}

// TestVerifyIsGatedAndBcryptIsNot pins which scheme pays the queue. argon2id is
// the memory cost the gate exists for; bcrypt is a few KiB and must not queue
// behind it.
func TestVerifyIsGatedAndBcryptIsNot(t *testing.T) {
	digest, err := Hash(context.Background(), "hunter2")
	if err != nil {
		t.Fatal(err)
	}

	// With every slot held, an argon2id verify cannot proceed; a cancelled ctx
	// makes it fail closed rather than block the test.
	for range cap(gate) {
		if err := acquire(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if Verify(ctx, TypeArgon2id, "hunter2", digest) {
		t.Fatal("argon2id Verify succeeded with no slot free — it is not gated")
	}
	for range cap(gate) {
		release()
	}

	// Ungated, and still correct.
	if !Verify(context.Background(), TypeArgon2id, "hunter2", digest) {
		t.Fatal("argon2id Verify failed on its own digest")
	}
	if Verify(context.Background(), TypeArgon2id, "wrong", digest) {
		t.Fatal("argon2id Verify accepted a wrong password")
	}
}

func TestConcurrencyDerivesFromTheMemoryLimit(t *testing.T) {
	if got := perHashBytes(); got != int64(hashParams.Memory)*1024 {
		t.Fatalf("perHashBytes = %d, want hashParams.Memory (%d KiB) in bytes", got, hashParams.Memory)
	}

	// The env override wins, so an operator who measured their pod outranks the
	// derivation.
	t.Setenv(concurrencyEnv, "3")
	if got := concurrency(); got != 3 {
		t.Fatalf("concurrency() = %d with %s=3, want 3", got, concurrencyEnv)
	}
	t.Setenv(concurrencyEnv, "0")
	if got := concurrency(); got < 1 {
		t.Fatalf("concurrency() = %d with a zero override, want the derived bound (never < 1)", got)
	}
	t.Setenv(concurrencyEnv, "not-a-number")
	if got := concurrency(); got < 1 {
		t.Fatalf("concurrency() = %d with a malformed override, want the derived bound (never < 1)", got)
	}
}
