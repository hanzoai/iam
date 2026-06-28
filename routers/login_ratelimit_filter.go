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

// Rate limit for the IAM login attack surface. ONE door per concern:
//
//   - POST /v1/iam/login is throttled UNCONDITIONALLY. The login decision (and
//     the RFC 8628 device-approval branch) is dispatched from form.Type in the
//     JSON BODY, not the query string, so keying on a query param leaves a
//     body-only bypass (POST {"type":"device",...} with no query ran
//     unthrottled). Guarding the endpoint itself — the actual door where the
//     decision is made — closes that hole and also bounds password brute-force.
//
//   - GET /v1/iam/get-app-login?type=device is throttled by IP. It is anonymous-
//     reachable and does DeviceAuthMap.Load(userCode); without a ceiling an
//     unauthenticated attacker can grind/oracle pending user_codes. type IS a
//     query param on this endpoint (the controller reads it from the query), so
//     keying on it here is correct, not a proxy of the decision.
//
// Both share the per-IP buckets — one IP ceiling across the whole login surface
// — plus a per-session ceiling on POST so a single session can't grind even
// while rotating IPs. The filter reads NOTHING from the request body, so the
// controller is still free to consume RequestBody. Built on the shared
// sliding-window primitive (ratelimit.go).
//
// Limit: 10 attempts / 60s. Reject (429) when ANY applicable ceiling is hit.

package routers

import (
	"net/http"
	"sync"
	"time"

	"github.com/hanzoai/beego/v2/server/web/context"
)

const (
	loginRateBurst  = 10
	loginRateWindow = 60 * time.Second
)

var (
	loginIPBuckets      sync.Map // map[ip]*slidingBucket — whole login surface
	loginSessionBuckets sync.Map // map[sessionID]*slidingBucket — POST /login only
	loginJanitorMu      sync.Mutex
	loginLastSweep      time.Time
)

// LoginRateLimitFilter is a beego BeforeRouter filter. It is a no-op for any
// request outside the login attack surface.
func LoginRateLimitFilter(ctx *context.Context) {
	method := ctx.Input.Method()
	url := ctx.Input.URL()

	switch {
	case method == http.MethodPost && url == "/v1/iam/login":
		limitLoginPost(ctx)
	case method == http.MethodGet && url == "/v1/iam/get-app-login" && ctx.Input.Query("type") == "device":
		limitDeviceLookupGet(ctx)
	}
}

// limitLoginPost throttles POST /v1/iam/login by source IP AND issuer session.
// Both are evaluated even when one already tripped so that an attacker rotating
// IPs still accrues against their session, and vice versa.
func limitLoginPost(ctx *context.Context) {
	limited := false
	if ip := clientIPForRateLimit(ctx); ip != "" {
		if rateLimitExceeded(&loginIPBuckets, ip, loginRateBurst, loginRateWindow) {
			limited = true
		}
	}
	if sid := ctx.Input.Cookie("iam_session_id"); sid != "" {
		if rateLimitExceeded(&loginSessionBuckets, sid, loginRateBurst, loginRateWindow) {
			limited = true
		}
	}

	if limited {
		rejectTooMany(ctx, "Too many login attempts. Wait a minute and retry.")
		return
	}
	loginScheduleSweep()
}

// limitDeviceLookupGet throttles the anonymous device user_code lookup by IP.
func limitDeviceLookupGet(ctx *context.Context) {
	ip := clientIPForRateLimit(ctx)
	if ip == "" {
		return
	}
	if rateLimitExceeded(&loginIPBuckets, ip, loginRateBurst, loginRateWindow) {
		rejectTooMany(ctx, "Too many device-lookup attempts. Wait a minute and retry.")
		return
	}
	loginScheduleSweep()
}

func rejectTooMany(ctx *context.Context, msg string) {
	ctx.Output.SetStatus(http.StatusTooManyRequests)
	_ = ctx.Output.JSON(map[string]string{"status": "error", "msg": msg}, false, false)
}

func loginScheduleSweep() {
	scheduleSweep(&loginJanitorMu, &loginLastSweep, loginRateWindow,
		&loginIPBuckets, &loginSessionBuckets)
}
