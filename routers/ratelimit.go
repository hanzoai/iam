// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Shared in-memory sliding-window rate-limit primitive for the IAM request
// filters (verification-code endpoints, device-approval endpoint). IAM runs
// single-replica per cluster, so a process-global map per concern is
// sufficient — no Redis dependency. One bucket implementation, used everywhere.

package routers

import (
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/beego/v2/server/web/context"
)

// slidingBucket holds the in-window request timestamps for one key. mu guards
// stamps: the same key can be hit concurrently by many request goroutines, so
// the read-modify-write of the window must be serialized per bucket.
type slidingBucket struct {
	mu     sync.Mutex
	stamps []time.Time
}

// rateLimitExceeded records "now" for key in buckets under a sliding window of
// the given size and capacity (burst). It returns true — recording nothing new
// — when the window is already full, i.e. the caller must reject the request.
func rateLimitExceeded(buckets *sync.Map, key string, burst int, window time.Duration) bool {
	now := time.Now()
	cutoff := now.Add(-window)

	val, _ := buckets.LoadOrStore(key, &slidingBucket{})
	b := val.(*slidingBucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	// Drop stamps outside the window.
	kept := b.stamps[:0]
	for _, t := range b.stamps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= burst {
		b.stamps = kept
		return true
	}
	b.stamps = append(kept, now)
	return false
}

// rateLimitSweep drops every bucket whose newest stamp predates cutoff, keeping
// the map bounded under sustained abuse.
func rateLimitSweep(buckets *sync.Map, cutoff time.Time) {
	buckets.Range(func(k, v interface{}) bool {
		b := v.(*slidingBucket)
		b.mu.Lock()
		fresh := false
		for _, t := range b.stamps {
			if t.After(cutoff) {
				fresh = true
				break
			}
		}
		b.mu.Unlock()
		if !fresh {
			buckets.Delete(k)
		}
		return true
	})
}

// scheduleSweep runs rateLimitSweep over the given buckets at most once per
// 5 minutes (guarded by mu/last), off the request path.
func scheduleSweep(mu *sync.Mutex, last *time.Time, window time.Duration, buckets ...*sync.Map) {
	now := time.Now()
	mu.Lock()
	if now.Sub(*last) > 5*time.Minute {
		*last = now
		mu.Unlock()
		cutoff := now.Add(-window)
		for _, b := range buckets {
			go rateLimitSweep(b, cutoff)
		}
	} else {
		mu.Unlock()
	}
}

// clientIPForRateLimit resolves the source IP for bucketing under a trusted-
// proxy model. Ingress assumption: exactly one trusted hop (hanzoai/ingress)
// fronts IAM; it OVERWRITES X-Real-IP with the peer it observed and APPENDS that
// peer as the rightmost X-Forwarded-For entry. A client cannot forge either:
//
//   - X-Real-IP is set (not appended) by the ingress, so any client-supplied
//     value is overwritten — trust it first.
//   - The LEFTMOST X-Forwarded-For entry is whatever the client injected and is
//     therefore attacker-controlled; the RIGHTMOST entry is the one our trusted
//     proxy appended (the real client as the proxy saw it). Take the rightmost,
//     never the leftmost, so the rate-limit key cannot be spoofed.
//   - Absent a proxy (direct connection / tests), fall back to RemoteAddr.
func clientIPForRateLimit(ctx *context.Context) string {
	if xrip := strings.TrimSpace(ctx.Input.Header("X-Real-IP")); xrip != "" {
		return xrip
	}
	if xff := ctx.Input.Header("X-Forwarded-For"); xff != "" {
		if comma := strings.LastIndexByte(xff, ','); comma >= 0 {
			return strings.TrimSpace(xff[comma+1:])
		}
		return strings.TrimSpace(xff)
	}
	host, _, err := net.SplitHostPort(ctx.Input.Context.Request.RemoteAddr)
	if err != nil {
		return ctx.Input.Context.Request.RemoteAddr
	}
	return host
}
