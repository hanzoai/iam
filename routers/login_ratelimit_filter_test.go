// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package routers

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/beego/v2/server/web/context"
)

// newLoginCtx builds a request context for the login surface.
//
//	method   — POST for /v1/iam/login, GET for /v1/iam/get-app-login.
//	url      — full path+query (the filter keys on Method/URL/Query only).
//	ip       — source IP placed in RemoteAddr (no proxy headers, so the
//	           trusted-proxy resolver falls through to RemoteAddr).
//	session  — iam_session_id cookie value, or "" for none.
//	body     — request body; the filter must NOT consume it.
func newLoginCtx(method, url, ip, session, body string) *context.Context {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.RemoteAddr = ip + ":12345"
	if session != "" {
		req.AddCookie(&http.Cookie{Name: "iam_session_id", Value: session})
	}
	rw := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(rw, req)
	return ctx
}

// resetLoginBuckets clears the shared buckets between tests. It must NOT
// reassign the sync.Map values (a background sweep goroutine may hold the
// package var by pointer and Range it concurrently — reassigning corrupts it);
// instead it walks and deletes, and pushes loginLastSweep forward so no
// per-test sweep fires under the test. Mirrors clearByAttrBuckets in controllers.
func resetLoginBuckets() {
	loginJanitorMu.Lock()
	loginLastSweep = time.Now()
	loginJanitorMu.Unlock()
	for _, m := range []*sync.Map{&loginIPBuckets, &loginSessionBuckets} {
		m.Range(func(k, _ interface{}) bool { m.Delete(k); return true })
	}
}

const (
	loginPath  = "/v1/iam/login"
	deviceLook = "/v1/iam/get-app-login?type=device&userCode=ABCD-EFGH"
)

func TestLogin_NoOpForUnrelatedRequest(t *testing.T) {
	resetLoginBuckets()
	for i := 0; i < loginRateBurst*3; i++ {
		ctx := newLoginCtx(http.MethodGet, "/v1/iam/get-account", "10.1.0.1", "sess-a", "")
		LoginRateLimitFilter(ctx)
		if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
			t.Fatal("an unrelated request must never be rate-limited here")
		}
	}
}

func TestLogin_POSTAllowsBurst(t *testing.T) {
	resetLoginBuckets()
	for i := 0; i < loginRateBurst; i++ {
		ctx := newLoginCtx(http.MethodPost, loginPath, "10.1.0.2", "", "")
		LoginRateLimitFilter(ctx)
		if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
			t.Fatalf("request %d/%d should be allowed", i+1, loginRateBurst)
		}
	}
}

// R1: a body-only {"type":"device"} POST with NO query string was the bypass —
// the old filter keyed on the query param. It must now be throttled.
func TestLogin_POSTBodyOnlyDeviceTypeIsThrottled(t *testing.T) {
	resetLoginBuckets()
	ip := "10.1.0.9"
	body := `{"type":"device","userCode":"ABCD-EFGH"}`
	for i := 0; i < loginRateBurst; i++ {
		ctx := newLoginCtx(http.MethodPost, loginPath, ip, "", body) // NO ?type=device
		LoginRateLimitFilter(ctx)
		if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
			t.Fatalf("request %d/%d should be allowed", i+1, loginRateBurst)
		}
	}
	ctx := newLoginCtx(http.MethodPost, loginPath, ip, "", body)
	LoginRateLimitFilter(ctx)
	if ctx.ResponseWriter.Status != http.StatusTooManyRequests {
		t.Fatalf("body-only type=device POST must be throttled, got %d", ctx.ResponseWriter.Status)
	}
}

// The filter must not drain the body — Login() reads form.Type from it.
func TestLogin_POSTDoesNotConsumeBody(t *testing.T) {
	resetLoginBuckets()
	body := `{"type":"device","userCode":"ABCD-EFGH"}`
	ctx := newLoginCtx(http.MethodPost, loginPath, "10.1.0.10", "", body)
	LoginRateLimitFilter(ctx)
	got, err := io.ReadAll(ctx.Request.Body)
	if err != nil {
		t.Fatalf("reading body after filter: %v", err)
	}
	if string(got) != body {
		t.Fatalf("filter consumed the request body: got %q want %q", got, body)
	}
}

func TestLogin_POSTBlocksOverBurstByIP(t *testing.T) {
	resetLoginBuckets()
	ip := "10.1.0.3"
	for i := 0; i < loginRateBurst; i++ {
		LoginRateLimitFilter(newLoginCtx(http.MethodPost, loginPath, ip, "", ""))
	}
	ctx := newLoginCtx(http.MethodPost, loginPath, ip, "", "")
	LoginRateLimitFilter(ctx)
	if ctx.ResponseWriter.Status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after IP burst, got %d", ctx.ResponseWriter.Status)
	}
}

func TestLogin_POSTBlocksOverBurstBySession(t *testing.T) {
	resetLoginBuckets()
	// Rotate the IP every request so only the SESSION bucket accumulates.
	for i := 0; i < loginRateBurst; i++ {
		ip := fmt.Sprintf("10.2.0.%d", i+1)
		LoginRateLimitFilter(newLoginCtx(http.MethodPost, loginPath, ip, "sess-grind", ""))
	}
	ctx := newLoginCtx(http.MethodPost, loginPath, "10.9.9.9", "sess-grind", "")
	LoginRateLimitFilter(ctx)
	if ctx.ResponseWriter.Status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after session burst across rotating IPs, got %d", ctx.ResponseWriter.Status)
	}
}

func TestLogin_POSTPerIPIsolation(t *testing.T) {
	resetLoginBuckets()
	for i := 0; i < loginRateBurst; i++ {
		LoginRateLimitFilter(newLoginCtx(http.MethodPost, loginPath, "10.3.0.1", "", ""))
	}
	ctx := newLoginCtx(http.MethodPost, loginPath, "10.3.0.2", "", "")
	LoginRateLimitFilter(ctx)
	if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
		t.Fatalf("a different IP must not be blocked, got %d", ctx.ResponseWriter.Status)
	}
}

// R2: the anonymous GET device user_code lookup must be throttled by IP.
func TestLogin_GETDeviceLookupIsThrottled(t *testing.T) {
	resetLoginBuckets()
	ip := "10.4.0.1"
	for i := 0; i < loginRateBurst; i++ {
		ctx := newLoginCtx(http.MethodGet, deviceLook, ip, "", "")
		LoginRateLimitFilter(ctx)
		if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
			t.Fatalf("lookup %d/%d should be allowed", i+1, loginRateBurst)
		}
	}
	ctx := newLoginCtx(http.MethodGet, deviceLook, ip, "", "")
	LoginRateLimitFilter(ctx)
	if ctx.ResponseWriter.Status != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after device-lookup burst, got %d", ctx.ResponseWriter.Status)
	}
}

// A non-device get-app-login (the common OAuth login-page render) is NOT
// throttled — only the device user_code oracle branch is.
func TestLogin_GETNonDeviceAppLoginIsNotThrottled(t *testing.T) {
	resetLoginBuckets()
	for i := 0; i < loginRateBurst*3; i++ {
		ctx := newLoginCtx(http.MethodGet, "/v1/iam/get-app-login?clientId=app_x", "10.4.0.2", "", "")
		LoginRateLimitFilter(ctx)
		if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
			t.Fatal("a non-device get-app-login must not be rate-limited")
		}
	}
}

// R3: the per-bucket sliding window is read-modify-written under load by many
// request goroutines hitting the same key. Hammer one key concurrently; with
// -race this fails if slidingBucket.stamps is touched without its mutex.
func TestLogin_ConcurrentSameKeyIsRaceClean(t *testing.T) {
	resetLoginBuckets()
	const goroutines = 64
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				rateLimitExceeded(&loginIPBuckets, "10.7.0.1", loginRateBurst, loginRateWindow)
			}
		}()
	}
	wg.Wait()
}

// XFF spoofing must not let a request mint a fresh rate-limit key per request.
// With one trusted proxy hop, the resolver keys on X-Real-IP (set by ingress),
// ignoring a client-injected leftmost X-Forwarded-For.
func TestLogin_XFFSpoofDoesNotEvadeThrottle(t *testing.T) {
	resetLoginBuckets()
	send := func(spoofLeft string) int {
		ctx := newLoginCtx(http.MethodPost, loginPath, "203.0.113.7", "", "")
		ctx.Request.Header.Set("X-Real-IP", "198.51.100.5") // ingress-set, trusted
		ctx.Request.Header.Set("X-Forwarded-For", spoofLeft+", 198.51.100.5")
		LoginRateLimitFilter(ctx)
		return ctx.ResponseWriter.Status
	}
	for i := 0; i < loginRateBurst; i++ {
		// Attacker rotates the spoofable leftmost XFF every request.
		if s := send(fmt.Sprintf("1.2.3.%d", i+1)); s == http.StatusTooManyRequests {
			t.Fatalf("request %d/%d should be allowed", i+1, loginRateBurst)
		}
	}
	if s := send("1.2.3.250"); s != http.StatusTooManyRequests {
		t.Fatalf("XFF rotation must not evade the throttle, got %d", s)
	}
}
