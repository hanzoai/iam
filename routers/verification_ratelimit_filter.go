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

// Per-IP rate limit for verification-code endpoints. Mitigates finding B from
// red review 2026-04-30: /v1/iam/send-* with auto-create can be abused to flood
// stub user rows. Built on the shared sliding-window primitive (ratelimit.go).
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
	"net/http"
	"sync"
	"time"

	"github.com/hanzoai/beego/v2/server/web/context"
)

const (
	verifyRateBurst  = 10
	verifyRateWindow = 60 * time.Second
)

var (
	verifyBuckets   sync.Map // map[string]*slidingBucket
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

// VerificationRateLimitFilter is a beego BeforeRouter filter. It is a no-op for
// any path outside verifyRateLimitedPaths.
func VerificationRateLimitFilter(ctx *context.Context) {
	if ctx.Input.Method() != http.MethodPost {
		return
	}
	if _, ok := verifyRateLimitedPaths[ctx.Input.URL()]; !ok {
		return
	}

	ip := clientIPForRateLimit(ctx)
	if ip == "" {
		return
	}

	if rateLimitExceeded(&verifyBuckets, ip, verifyRateBurst, verifyRateWindow) {
		ctx.Output.SetStatus(http.StatusTooManyRequests)
		_ = ctx.Output.JSON(map[string]string{
			"status": "error",
			"msg":    "Too many verification requests from your IP. Wait a minute and retry.",
		}, false, false)
		return
	}

	scheduleSweep(&verifyJanitorMu, &verifyLastSweep, verifyRateWindow, &verifyBuckets)
}
