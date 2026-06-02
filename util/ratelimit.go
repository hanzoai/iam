// Copyright 2025 The Hanzo Authors. All Rights Reserved.
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

package util

import (
	"fmt"
	"os"
	"strconv"
	"sync"
	"time"
)

// SignupRateLimiter enforces per-key sliding-window rate limits for signups.
type SignupRateLimiter struct {
	mu      sync.Mutex
	entries map[string][]time.Time
	limit   int
	window  time.Duration
}

// NewSignupRateLimiter creates a rate limiter that allows at most limit
// events per window duration for each key.
func NewSignupRateLimiter(limit int, window time.Duration) *SignupRateLimiter {
	return &SignupRateLimiter{
		entries: make(map[string][]time.Time),
		limit:   limit,
		window:  window,
	}
}

// Allow checks whether the given key is within the rate limit.
// Returns nil if allowed, or an error describing the limit.
func (r *SignupRateLimiter) Allow(key string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-r.window)

	// Prune expired entries
	timestamps := r.entries[key]
	valid := timestamps[:0]
	for _, ts := range timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}

	if len(valid) >= r.limit {
		r.entries[key] = valid
		return fmt.Errorf("rate limit exceeded: max %d signups per %v", r.limit, r.window)
	}

	r.entries[key] = append(valid, now)
	return nil
}

// Cleanup removes stale entries older than the window. Call periodically
// to prevent memory growth in long-running processes.
func (r *SignupRateLimiter) Cleanup() {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := time.Now().Add(-r.window)
	for key, timestamps := range r.entries {
		valid := timestamps[:0]
		for _, ts := range timestamps {
			if ts.After(cutoff) {
				valid = append(valid, ts)
			}
		}
		if len(valid) == 0 {
			delete(r.entries, key)
		} else {
			r.entries[key] = valid
		}
	}
}

// Global signup rate limiters. Limits are env-configurable so each
// deployment can tune for its actual abuse profile without recompiling:
//
//	SIGNUP_IP_LIMIT_PER_HOUR     default 20  (was 3 — too aggressive,
//	                                         tripped on shared-NAT
//	                                         offices and Playwright runs)
//	SIGNUP_DOMAIN_LIMIT_PER_HOUR default 100 (was 10 — locked out any
//	                                         company onboarding a team
//	                                         from the same email domain)
//
// On sandbox envs (SANDBOX_GLOBAL_OTP set) the checks are skipped
// entirely by the caller; these limits only fire in production.
var (
	IPSignupLimiter     = NewSignupRateLimiter(intFromEnv("SIGNUP_IP_LIMIT_PER_HOUR", 20), 1*time.Hour)
	DomainSignupLimiter = NewSignupRateLimiter(intFromEnv("SIGNUP_DOMAIN_LIMIT_PER_HOUR", 100), 1*time.Hour)
)

// intFromEnv reads an integer env var with a default fallback.
func intFromEnv(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func init() {
	// Periodically clean up stale rate limit entries.
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		for range ticker.C {
			IPSignupLimiter.Cleanup()
			DomainSignupLimiter.Cleanup()
		}
	}()
}
