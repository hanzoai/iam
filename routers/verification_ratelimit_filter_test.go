// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package routers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

func newTestCtx(method, path, ip string) *context.Context {
	req := httptest.NewRequest(method, path, strings.NewReader(""))
	req.RemoteAddr = ip + ":12345"
	rw := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(rw, req)
	return ctx
}

func resetVerifyBuckets() {
	verifyBuckets = sync.Map{}
}

func TestVerificationRateLimit_NoOpForOtherPaths(t *testing.T) {
	resetVerifyBuckets()
	ctx := newTestCtx(http.MethodPost, "/v1/iam/login", "10.0.0.1")
	for i := 0; i < 100; i++ {
		VerificationRateLimitFilter(ctx)
	}
	if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
		t.Fatal("non-verification path should not be rate-limited")
	}
}

func TestVerificationRateLimit_AllowsBurst(t *testing.T) {
	resetVerifyBuckets()
	for i := 0; i < verifyRateBurst; i++ {
		ctx := newTestCtx(http.MethodPost, "/v1/iam/send-verification-code", "10.0.0.2")
		VerificationRateLimitFilter(ctx)
		if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
			t.Fatalf("request %d/%d should be allowed", i+1, verifyRateBurst)
		}
	}
}

func TestVerificationRateLimit_BlocksOverBurst(t *testing.T) {
	resetVerifyBuckets()
	ip := "10.0.0.3"
	for i := 0; i < verifyRateBurst; i++ {
		VerificationRateLimitFilter(newTestCtx(http.MethodPost, "/v1/iam/send-verification-code", ip))
	}
	ctx := newTestCtx(http.MethodPost, "/v1/iam/send-verification-code", ip)
	VerificationRateLimitFilter(ctx)
	if ctx.ResponseWriter.Status != http.StatusTooManyRequests {
		t.Fatalf("expected 429, got %d", ctx.ResponseWriter.Status)
	}
}

func TestVerificationRateLimit_PerIPIsolation(t *testing.T) {
	resetVerifyBuckets()
	for i := 0; i < verifyRateBurst; i++ {
		VerificationRateLimitFilter(newTestCtx(http.MethodPost, "/v1/iam/send-verification-code", "10.0.0.4"))
	}
	// Different IP must still be allowed.
	ctx := newTestCtx(http.MethodPost, "/v1/iam/send-verification-code", "10.0.0.5")
	VerificationRateLimitFilter(ctx)
	if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
		t.Fatalf("different IP should not be blocked, got %d", ctx.ResponseWriter.Status)
	}
}

func TestVerificationRateLimit_PrefersXForwardedFor(t *testing.T) {
	resetVerifyBuckets()
	// Burst with X-Forwarded-For = 1.2.3.4 from one RemoteAddr.
	for i := 0; i < verifyRateBurst; i++ {
		ctx := newTestCtx(http.MethodPost, "/v1/iam/send-verification-code", "10.0.0.6")
		ctx.Input.Context.Request.Header.Set("X-Forwarded-For", "1.2.3.4")
		VerificationRateLimitFilter(ctx)
	}
	// Another request with same XFF from a different RemoteAddr must still be blocked.
	ctx := newTestCtx(http.MethodPost, "/v1/iam/send-verification-code", "10.0.0.7")
	ctx.Input.Context.Request.Header.Set("X-Forwarded-For", "1.2.3.4")
	VerificationRateLimitFilter(ctx)
	if ctx.ResponseWriter.Status != http.StatusTooManyRequests {
		t.Fatalf("XFF-based bucketing should trigger 429, got %d", ctx.ResponseWriter.Status)
	}
}

func TestVerificationRateLimit_GETIsIgnored(t *testing.T) {
	resetVerifyBuckets()
	for i := 0; i < verifyRateBurst*2; i++ {
		ctx := newTestCtx(http.MethodGet, "/v1/iam/send-verification-code", "10.0.0.8")
		VerificationRateLimitFilter(ctx)
		if ctx.ResponseWriter.Status == http.StatusTooManyRequests {
			t.Fatal("GET should not be rate-limited")
		}
	}
}
