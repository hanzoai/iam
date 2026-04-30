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

// Per-IP token bucket for verification-code endpoints. In-memory only —
// IAM runs single-replica per cluster, so a global map is sufficient. No
// Redis dependency. Mitigates finding B from red review 2026-04-30:
// /v1/iam/send-* with auto-create can be abused to flood stub user rows.
//
// Limit: 10 requests / 60s / source IP, applied to:
//   - POST /v1/iam/send-verification-code
//   - POST /v1/iam/send-sms
//   - POST /v1/iam/send-email
//   - POST /v1/iam/send-otp (alias)
//
// On exceed: HTTP 429 with JSON {status:"error",msg:"..."}.

package routers

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/beego/beego/v2/server/web/context"
)

const (
	verifyRateBurst  = 10
	verifyRateWindow = 60 * time.Second
)

type verifyBucket struct {
	stamps []time.Time
}

var (
	verifyBuckets   sync.Map // map[string]*verifyBucket
	verifyJanitorMu sync.Mutex
	verifyLastSweep time.Time
)

// verifyRateLimitedPaths is the canonical set of paths that get IP-bucketed.
var verifyRateLimitedPaths = map[string]struct{}{
	"/v1/iam/send-verification-code": {},
	"/v1/iam/send-sms":               {},
	"/v1/iam/send-email":             {},
	"/v1/iam/send-otp":               {},
}

func clientIPForRateLimit(ctx *context.Context) string {
	// Trust X-Forwarded-For from gateway / ingress only when present;
	// take the leftmost (original client) entry.
	if xff := ctx.Input.Header("X-Forwarded-For"); xff != "" {
		if comma := strings.IndexByte(xff, ','); comma > 0 {
			return strings.TrimSpace(xff[:comma])
		}
		return strings.TrimSpace(xff)
	}
	if xrip := ctx.Input.Header("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	host, _, err := net.SplitHostPort(ctx.Input.Context.Request.RemoteAddr)
	if err != nil {
		return ctx.Input.Context.Request.RemoteAddr
	}
	return host
}

// VerificationRateLimitFilter is a beego BeforeRouter filter. It is a no-op
// for any path outside verifyRateLimitedPaths.
func VerificationRateLimitFilter(ctx *context.Context) {
	if ctx.Input.Method() != http.MethodPost {
		return
	}
	urlPath := ctx.Input.URL()
	if _, ok := verifyRateLimitedPaths[urlPath]; !ok {
		return
	}

	ip := clientIPForRateLimit(ctx)
	if ip == "" {
		return
	}

	now := time.Now()
	cutoff := now.Add(-verifyRateWindow)

	val, _ := verifyBuckets.LoadOrStore(ip, &verifyBucket{})
	bucket := val.(*verifyBucket)

	// Drop stamps outside the window.
	kept := bucket.stamps[:0]
	for _, t := range bucket.stamps {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= verifyRateBurst {
		bucket.stamps = kept
		ctx.Output.SetStatus(http.StatusTooManyRequests)
		_ = ctx.Output.JSON(map[string]string{
			"status": "error",
			"msg":    "Too many verification requests from your IP. Wait a minute and retry.",
		}, false, false)
		return
	}
	bucket.stamps = append(kept, now)

	// Cheap janitor: every 5 min, sweep buckets whose newest stamp is
	// older than the window. Keeps the map from growing unbounded under
	// abuse.
	verifyJanitorMu.Lock()
	if now.Sub(verifyLastSweep) > 5*time.Minute {
		verifyLastSweep = now
		verifyJanitorMu.Unlock()
		go verifySweep(cutoff)
	} else {
		verifyJanitorMu.Unlock()
	}
}

func verifySweep(cutoff time.Time) {
	verifyBuckets.Range(func(k, v interface{}) bool {
		bucket := v.(*verifyBucket)
		fresh := false
		for _, t := range bucket.stamps {
			if t.After(cutoff) {
				fresh = true
				break
			}
		}
		if !fresh {
			verifyBuckets.Delete(k)
		}
		return true
	})
}
