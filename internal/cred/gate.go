// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package cred

import (
	"context"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
)

// How many argon2id derivations may run at once.
//
// argon2id's cost IS memory: hashParams.Memory is 64 MiB, held for the whole
// derivation, per concurrent call. Nothing bounded how many ran at once, so N
// simultaneous logins reserved N × 64 MiB — at the live 2Gi container limit the
// pod dies somewhere around the 26th, and the kernel kills the PROCESS, not the
// request that caused it. Every session on that pod goes with it.
//
// That shape is wrong twice over:
//
//   - A password hash is DELIBERATELY expensive. Unbounded, it is a DoS
//     amplifier any unauthenticated client can pull with a few dozen wrong
//     passwords, because the cost lands before the password is known to be
//     wrong.
//   - It defeats the usual answer. Adding replicas does not help when each
//     replica dies the same way, and a rolling upgrade that shifts traffic onto
//     the pod still serving kills it FASTER — the moment you most need it alive.
//
// Bounded, the same flood queues. Latency rises, the pod survives, and the
// slowness shows up as slowness instead of as a restart.
//
// The bound is DERIVED from hashParams rather than written beside it, so
// re-tuning the cost re-sizes the gate and the two cannot drift.

// perHashBytes is what one derivation reserves: argon2id fills a Memory-KiB
// block, so this is the whole of its footprint and it does not depend on the
// password.
//
// It READS hashParams rather than restating 64 MiB. The bound and the cost are
// one fact, and a second copy of a number is a number that will disagree.
func perHashBytes() int64 { return int64(hashParams.Memory) * 1024 }

// hashMemoryShare is the fraction of the process memory limit argon2id may hold
// at peak. An eighth leaves the request path, the store, and the runtime the
// rest — hashing is a spike on top of a service, never the service.
//
// An eighth rather than a quarter because a released argon2id block is not
// reclaimed memory yet. Measured (TestFloodDoesNotScaleMemoryWithCallers): with
// 8 slots the peak heap under a flood was ~1 GiB, roughly TWICE the 512 MiB the
// slots themselves hold, because the GC trails the allocation rate. Budgeting
// the slots at an eighth puts the observed peak back at about a quarter, which
// is what "a spike on top of a service" is supposed to mean. At the live 2Gi
// container limit that is 4 concurrent derivations — ~40-80 logins/second at
// argon2id's ~50-100ms, far above what this identity plane serves.
const hashMemoryShare = 8

// defaultConcurrency is the bound when no memory limit is discoverable (a
// laptop, a test). Small enough to be safe anywhere, large enough that ordinary
// concurrent logins never queue.
const defaultConcurrency = 8

// concurrencyEnv overrides the derived bound. An operator who has measured
// their own pod outranks a derivation.
const concurrencyEnv = "IAM_HASH_CONCURRENCY"

// gate admits at most cap(gate) derivations. A buffered channel rather than a
// weighted semaphore because every derivation costs exactly the same: one slot
// IS 64 MiB, so counting slots and counting bytes are the same statement.
var gate = make(chan struct{}, concurrency())

// inFlight is the live count of derivations holding a slot. It exists so the
// bound can be ASSERTED (gate_test.go) rather than assumed — an invariant no
// test can observe is an invariant that quietly stops holding.
var inFlight atomic.Int64

// peak is the high-water mark of inFlight over the life of the process.
var peak atomic.Int64

// acquire blocks until a derivation slot is free, or until ctx is done.
//
// Blocking is the correct behaviour and not a fallback: the caller is asking for
// memory the process does not currently have, and the alternatives are worse.
// Returning a failure would be indistinguishable from a wrong password to
// everything downstream — it would count toward account lockout — so overload
// would lock out the very users retrying. Proceeding anyway is the OOM.
//
// ctx is what keeps the queue honest. A client that has already given up
// releases its place instead of being handed 64 MiB nobody is waiting for.
func acquire(ctx context.Context) error {
	select {
	case gate <- struct{}{}:
	case <-ctx.Done():
		return ctx.Err()
	}
	n := inFlight.Add(1)
	for {
		old := peak.Load()
		if n <= old || peak.CompareAndSwap(old, n) {
			break
		}
	}
	return nil
}

func release() {
	inFlight.Add(-1)
	<-gate
}

// concurrency is the derived bound: the share of the process memory limit
// argon2id may hold, divided by what one derivation costs.
func concurrency() int {
	if n, ok := envInt(concurrencyEnv); ok && n > 0 {
		return n
	}
	limit := memoryLimit()
	if limit <= 0 {
		return defaultConcurrency
	}
	n := int(limit / hashMemoryShare / perHashBytes())
	if n < 1 {
		// A limit too small for even one derivation still has to serve logins;
		// one at a time is the honest floor, and refusing to start would be a
		// worse answer than being slow.
		return 1
	}
	return n
}

// memoryLimit reports the bytes this process may use, or 0 when nothing says.
//
// It reads GOMEMLIMIT first because a deployment that sets it has already stated
// the answer (hanzoai/cloud does), then the cgroup the container actually runs
// under — which is the number the kernel enforces, and the only one available to
// a standalone pod that sets no GOMEMLIMIT.
func memoryLimit() int64 {
	limit := int64(0)
	// SetMemoryLimit(-1) reads the current limit without changing it. Unset is
	// math.MaxInt64, which is "no limit" rather than a very large one.
	if n := debug.SetMemoryLimit(-1); n > 0 && n < (int64(1)<<62) {
		limit = n
	}
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",                   // cgroup v2
		"/sys/fs/cgroup/memory/memory.limit_in_bytes", // cgroup v1
	} {
		n, ok := readInt(path)
		if !ok || n <= 0 || n >= (int64(1)<<62) {
			continue // "max", or v1's unlimited sentinel
		}
		if limit == 0 || n < limit {
			limit = n
		}
	}
	return limit
}

func readInt(path string) (int64, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

func envInt(key string) (int, bool) {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return 0, false
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, false
	}
	return n, true
}
