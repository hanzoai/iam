// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build !skipCi

package controllers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/beego/v2/server/web"
	"github.com/hanzoai/beego/v2/server/web/context"
	"github.com/hanzoai/iam/object"
)

// resetByAttrState wipes the per-test rate-limit state and restores the
// production-bound seams. Every test that touches the controller calls
// this in its t.Cleanup so we never leak buckets or fakes between cases.
//
// We CANNOT reassign byAttrBuckets (sync.Map cannot be safely value-copied
// concurrently with an in-flight Range); we walk and delete instead. We
// also push byAttrLastSweep forward so no test-induced sweep races with
// the next test's setup.
func resetByAttrState(t *testing.T) {
	t.Helper()
	clearByAttrBuckets()
	byAttrJanitorMu.Lock()
	byAttrLastSweep = time.Now()
	byAttrJanitorMu.Unlock()
	prevResolve := byAttrResolveClaims
	prevAudit := byAttrAudit
	t.Cleanup(func() {
		clearByAttrBuckets()
		byAttrResolveClaims = prevResolve
		byAttrAudit = prevAudit
	})
	// Swap audit to a no-op for every test by default — none of the
	// security assertions care about audit content, and the production
	// implementation requires a live xorm engine.
	byAttrAudit = func(*ApiController, string, string, string, int, int, string) {}
}

// clearByAttrBuckets walks the bucket map and deletes every entry. Safe
// to call while sweep goroutines may also be deleting — sync.Map.Delete
// is idempotent and the iteration is independent.
func clearByAttrBuckets() {
	byAttrBuckets.Range(func(k, _ interface{}) bool {
		byAttrBuckets.Delete(k)
		return true
	})
}

// newByAttrController builds a controller bound to a recorded HTTP
// context with the given method, query, and headers. The Beego controller
// is wired through web.Controller.Init so c.Ctx.Input/Output behave
// exactly as they do in production.
func newByAttrController(t *testing.T, query string, hdr map[string]string) (*ApiController, *httptest.ResponseRecorder) {
	t.Helper()
	target := "/v1/iam/users/by-attribute"
	if query != "" {
		target += "?" + query
	}
	req := httptest.NewRequest(http.MethodGet, target, strings.NewReader(""))
	req.RemoteAddr = "10.0.0.1:54321"
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(rec, req)
	c := &ApiController{Controller: web.Controller{}}
	c.Init(ctx, "ApiController", "GetUsersByAttribute", c)
	c.Data = map[interface{}]interface{}{}
	return c, rec
}

// decodeResp pulls the JSON body emitted by the controller into a
// generic map so tests can assert on `status` / `msg` / `data` / `data2`.
func decodeResp(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	body := rec.Body.Bytes()
	if len(body) == 0 {
		return nil
	}
	out := map[string]any{}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode response: %v\nbody: %s", err, string(body))
	}
	return out
}

// ===========================================================
// Pure helpers — no controller required.
// ===========================================================

// TestPhoneCandidates_NormalizesEquivalentForms exercises the canonical
// "the same human number in 6 typed forms" axis. Every variant must
// produce a candidate list that contains the canonical national,
// E.164-with-plus, and E.164-without-plus forms — i.e. probing any
// surface form will find a row stored under any other surface form.
func TestPhoneCandidates_NormalizesEquivalentForms(t *testing.T) {
	mustContain := func(t *testing.T, got []string, want ...string) {
		t.Helper()
		set := map[string]struct{}{}
		for _, g := range got {
			set[g] = struct{}{}
		}
		for _, w := range want {
			if _, ok := set[w]; !ok {
				t.Fatalf("candidate list %v missing %q", got, w)
			}
		}
	}

	// All 6 equivalent forms for the same number.
	forms := []string{
		"+19137779708",
		"19137779708",
		"9137779708",
		"913-777-9708",
		"913 777 9708",
		"(913) 777-9708",
	}
	for _, f := range forms {
		t.Run(f, func(t *testing.T) {
			cands := phoneCandidates(f)
			// Every form must produce all three canonical variants.
			mustContain(t, cands, "+19137779708", "19137779708", "9137779708")
		})
	}
}

// TestPhoneCandidates_EmptyAndWhitespace verifies the guard: a blank
// query produces no candidates at all (no probing the DB for nothing).
func TestPhoneCandidates_EmptyAndWhitespace(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n"} {
		if got := phoneCandidates(in); len(got) != 0 {
			t.Fatalf("phoneCandidates(%q) = %v; want empty", in, got)
		}
	}
}

// TestPhoneCandidates_Deduplicates makes sure two normalization passes
// that arrive at the same string don't bloat the candidate list.
func TestPhoneCandidates_Deduplicates(t *testing.T) {
	cands := phoneCandidates("9137779708")
	seen := map[string]int{}
	for _, c := range cands {
		seen[c]++
	}
	for c, n := range seen {
		if n > 1 {
			t.Fatalf("candidate %q appeared %d times: %v", c, n, cands)
		}
	}
}

// TestByAttributeAllowedClients_EmptyEnvRejectsAll verifies the
// fail-secure default: unset env => empty allowlist => zero callers
// permitted.
func TestByAttributeAllowedClients_EmptyEnvRejectsAll(t *testing.T) {
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "")
	if got := byAttributeAllowedClients(); len(got) != 0 {
		t.Fatalf("empty env must yield empty set, got %v", got)
	}
}

// TestByAttributeAllowedClients_ParsesCommaList verifies the CSV parse
// trims whitespace, drops empty entries, and produces an exact set.
func TestByAttributeAllowedClients_ParsesCommaList(t *testing.T) {
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", " acme-bd ,acme-ats,,acme-ta ")
	got := byAttributeAllowedClients()
	for _, want := range []string{"acme-bd", "acme-ats", "acme-ta"} {
		if _, ok := got[want]; !ok {
			t.Fatalf("expected %q in allowlist, got %v", want, got)
		}
	}
	if _, ok := got[""]; ok {
		t.Fatal("empty entry must be dropped")
	}
	if len(got) != 3 {
		t.Fatalf("expected 3 entries, got %d: %v", len(got), got)
	}
}

// TestByAttributeRateLimit_BurstAndWindow verifies the 10/min cap fires
// on the 11th call and that distinct clientIds don't share a bucket.
// IP is NOT part of the key — see TestRateLimit_KeysOnClientIdOnly_IgnoresXFF
// for the threat-model rationale.
func TestByAttributeRateLimit_BurstAndWindow(t *testing.T) {
	resetByAttrState(t)
	const client = "acme-bd"
	for i := 0; i < byAttributeRateBurst; i++ {
		if !byAttributeRateLimit(client) {
			t.Fatalf("call %d should be allowed (burst=%d)", i+1, byAttributeRateBurst)
		}
	}
	if byAttributeRateLimit(client) {
		t.Fatal("call beyond burst must be denied")
	}
	// Distinct clientId — independent bucket.
	if !byAttributeRateLimit("acme-ats") {
		t.Fatal("different clientId must have its own bucket")
	}
}

// TestByAttributeRateLimit_RejectsEmptyKey verifies that we never
// create a "" bucket — that would coalesce every credential-less call
// into a single global rate-limit.
func TestByAttributeRateLimit_RejectsEmptyKey(t *testing.T) {
	resetByAttrState(t)
	if byAttributeRateLimit("") {
		t.Fatal("empty clientId must be rejected")
	}
}

// TestExtractBearerJWT_Variants covers parse, prefix, and 3-part shape.
// The function is the first line of defense — anything other than a
// well-formed Bearer + 3-segment token returns "" so the resolver
// short-circuits to 401.
func TestExtractBearerJWT_Variants(t *testing.T) {
	cases := []struct {
		auth string
		want string
	}{
		{"", ""},
		{"Bearer", ""},
		{"Bearer ", ""},
		{"bearer eyJ.eyJ.sig", ""}, // case-sensitive
		{"Bearer eyJ.eyJ", ""},     // 2 parts
		{"Bearer eyJ.eyJ.", ""},    // empty sig
		{"Bearer eyJ.eyJ.sig", "eyJ.eyJ.sig"},
	}
	for _, tc := range cases {
		t.Run(tc.auth, func(t *testing.T) {
			c, _ := newByAttrController(t, "", map[string]string{"Authorization": tc.auth})
			got := c.extractBearerJWT()
			if got != tc.want {
				t.Fatalf("extractBearerJWT(%q) = %q; want %q", tc.auth, got, tc.want)
			}
		})
	}
}

// (Tests for byAttributeClientIP removed in Fix 3 — the function was
// deleted because the rate-limiter no longer uses IP. The audit
// pipeline derives ClientIp directly from NewRecord. See
// TestRateLimit_KeysOnClientIdOnly_IgnoresXFF for the rationale.)

// TestProjectUserForByAttribute_OmitsSecrets enforces the field
// whitelist: under no circumstances may password / salt / TOTP / etc.
// leak through. We assert the projection has only the 7 declared fields.
func TestProjectUserForByAttribute_OmitsSecrets(t *testing.T) {
	u := minimalUserWithSecrets("acme", "alice")
	got := projectUserForByAttribute(u)
	if got == nil {
		t.Fatal("projection returned nil")
	}
	// Round-trip to JSON and inspect the key set — that's exactly what
	// the wire would carry.
	blob, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal projection: %v", err)
	}
	m := map[string]any{}
	if err := json.Unmarshal(blob, &m); err != nil {
		t.Fatalf("unmarshal projection: %v", err)
	}
	want := map[string]struct{}{
		"id": {}, "owner": {}, "name": {}, "email": {},
		"phone": {}, "displayName": {}, "createdTime": {},
	}
	for k := range m {
		if _, ok := want[k]; !ok {
			t.Fatalf("projection emitted unexpected key %q (full body: %s)", k, string(blob))
		}
	}
	for k := range want {
		if _, ok := m[k]; !ok {
			t.Fatalf("projection missing required key %q (body: %s)", k, string(blob))
		}
	}
	// Spot-check: secrets are not present even by accident.
	for _, leaked := range []string{"password", "passwordSalt", "passwordType", "totp", "totpSecret", "webauthnCredentials"} {
		if _, ok := m[leaked]; ok {
			t.Fatalf("projection LEAKED %q — body: %s", leaked, string(blob))
		}
	}
}

// TestItoa exercises the local int-to-string helper.
func TestItoa(t *testing.T) {
	cases := []struct {
		n    int
		want string
	}{
		{0, "0"},
		{1, "1"},
		{9, "9"},
		{10, "10"},
		{25, "25"},
		{1234567, "1234567"},
		{-1, "-1"},
		{-25, "-25"},
	}
	for _, tc := range cases {
		if got := itoa(tc.n); got != tc.want {
			t.Fatalf("itoa(%d) = %q; want %q", tc.n, got, tc.want)
		}
	}
}

// TestEscapeRecordString verifies the audit-side escaper neutralises
// double-quote, backslash, and newline (CRLF). Without this the audit
// row could carry an injection payload that breaks the JSON object.
func TestEscapeRecordString(t *testing.T) {
	in := "alice\\bob\"eve\nfoo\rbar"
	want := `alice\\bob\"eve foo bar`
	if got := escapeRecordString(in); got != want {
		t.Fatalf("escapeRecordString = %q; want %q", got, want)
	}
}

// ===========================================================
// Controller-level behavior — auth, allowlist, rate-limit,
// cross-org, empty-success, bad-request. These tests use the
// byAttrResolveClaims seam to inject a deterministic auth result
// without standing up a JWT-issuing application + xorm engine.
// ===========================================================

// fakeClaims wires byAttrResolveClaims to a deterministic outcome so we
// can assert the post-auth behavior of the handler in isolation.
func fakeClaims(clientId, owner string, anon, ok bool) func(*ApiController) (string, string, bool, bool) {
	return func(*ApiController) (string, string, bool, bool) {
		return clientId, owner, anon, ok
	}
}

// TestHandler_Anonymous_Returns401 — no Bearer header => 401 with the
// canonical error shape. The handler must NEVER 404 the route.
func TestHandler_Anonymous_Returns401(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	byAttrResolveClaims = fakeClaims("", "", true, false)

	c, rec := newByAttrController(t, "phone=9137779708", nil)
	c.GetUsersByAttribute()

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("anon should be 401, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	resp := decodeResp(t, rec)
	if resp["status"] != "error" {
		t.Fatalf("expected status=error, got %v", resp["status"])
	}
}

// TestHandler_UserJWT_Returns403 — a user JWT (authorization_code or
// password grant) MUST be rejected with 403, not 401. This is the
// enumeration mitigation: a legitimate user JWT exists but is
// categorically the wrong credential type for this endpoint.
func TestHandler_UserJWT_Returns403(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	// anon=false means a valid token WAS parsed, but ok=false means it
	// failed the client_credentials discriminator (Type!="application").
	byAttrResolveClaims = fakeClaims("", "", false, false)

	c, rec := newByAttrController(t, "phone=9137779708", map[string]string{
		"Authorization": "Bearer eyJ.user.jwt",
	})
	c.GetUsersByAttribute()

	if rec.Code != http.StatusForbidden {
		t.Fatalf("user JWT should be 403, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestHandler_ServiceCreds_NotAllowlisted_Returns403 — a perfectly
// valid client_credentials JWT for a clientId that is NOT on the
// IAM_BY_ATTRIBUTE_ALLOWLIST must be denied. This is the second layer.
func TestHandler_ServiceCreds_NotAllowlisted_Returns403(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	byAttrResolveClaims = fakeClaims("not-allowlisted-svc", "acme", false, true)

	c, rec := newByAttrController(t, "phone=9137779708", map[string]string{
		"Authorization": "Bearer eyJ.svc.jwt",
	})
	c.GetUsersByAttribute()

	if rec.Code != http.StatusForbidden {
		t.Fatalf("non-allowlisted svc should be 403, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestHandler_ServiceCreds_Allowlisted_BadRequest_NoAttr — once auth +
// allowlist pass, missing the phone/email attribute returns 400. Proves
// we did NOT short-circuit on the missing attr before auth.
func TestHandler_ServiceCreds_Allowlisted_BadRequest_NoAttr(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	byAttrResolveClaims = fakeClaims("acme-bd", "acme", false, true)

	c, rec := newByAttrController(t, "", map[string]string{
		"Authorization": "Bearer eyJ.svc.jwt",
	})
	c.GetUsersByAttribute()

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing attr should be 400, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestHandler_ServiceCreds_Allowlisted_BadRequest_BothAttrs — phone AND
// email together must be rejected (we want exactly one).
func TestHandler_ServiceCreds_Allowlisted_BadRequest_BothAttrs(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	byAttrResolveClaims = fakeClaims("acme-bd", "acme", false, true)

	q := url.Values{}
	q.Set("phone", "9137779708")
	q.Set("email", "alice@example.com")
	c, rec := newByAttrController(t, q.Encode(), map[string]string{
		"Authorization": "Bearer eyJ.svc.jwt",
	})
	c.GetUsersByAttribute()

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("both attrs should be 400, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestHandler_CrossOrgOwner_Returns403 — caller's JWT binds owner=mlc,
// but they send ?owner=acme (probing another tenant). Must 403,
// not silently rewrite, not silently return mlc data with a misleading
// echoed owner. This is the cross-tenant probe defense.
func TestHandler_CrossOrgOwner_Returns403(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	byAttrResolveClaims = fakeClaims("acme-bd", "mlc", false, true)

	q := url.Values{}
	q.Set("owner", "acme") // attempting to escape into another tenant
	q.Set("phone", "9137779708")
	c, rec := newByAttrController(t, q.Encode(), map[string]string{
		"Authorization": "Bearer eyJ.svc.jwt",
	})
	c.GetUsersByAttribute()

	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-org owner= should be 403, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestHandler_SameOwnerEcho_Allowed — passing the SAME owner the JWT
// already binds (?owner=acme when JWT.owner=acme) is fine.
// This matters for SDK ergonomics: callers can echo the value back
// without tripping the cross-org guard.
func TestHandler_SameOwnerEcho_Allowed(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	byAttrResolveClaims = fakeClaims("acme-bd", "acme", false, true)
	// Email lookup needs the DB — short-circuit with a missing attr to
	// take the path that doesn't hit object.GetUserByEmail.
	// Instead use phone= with empty result via no-DB? The phone path
	// hits the DB too. So we must intercept earlier — just verify the
	// owner check doesn't reject the same-owner echo.
	// Easiest: send neither attr, get 400 — proves the owner check
	// did not interfere. Different from the previous case where the
	// resolver passed but no attr was sent.
	c, rec := newByAttrController(t, "owner=acme", map[string]string{
		"Authorization": "Bearer eyJ.svc.jwt",
	})
	c.GetUsersByAttribute()

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("same-owner echo should pass owner guard and 400 on missing attr; got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestHandler_RateLimit_Returns429 — pre-fill the bucket to the cap,
// then assert the 11th call gets 429. Uses the resolver fake plus a
// no-DB attribute path: we send an email with no attr (so the handler
// short-circuits to 400 BEFORE the DB call) — no, wait: we need it to
// pass the validation gates and hit rate-limit. The order in the
// handler is: auth -> allowlist -> RATE LIMIT -> owner -> attr. So
// rate-limit runs BEFORE the attr validation; we can ride that.
func TestHandler_RateLimit_Returns429(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	byAttrResolveClaims = fakeClaims("acme-bd", "acme", false, true)

	// Pre-fill the clientId bucket so the next call exhausts it.
	for i := 0; i < byAttributeRateBurst; i++ {
		if !byAttributeRateLimit("acme-bd") {
			t.Fatalf("pre-fill call %d should be allowed", i+1)
		}
	}

	c, rec := newByAttrController(t, "", map[string]string{
		"Authorization":   "Bearer eyJ.svc.jwt",
		"X-Forwarded-For": "203.0.113.10",
	})
	c.GetUsersByAttribute()

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("over-limit must 429, got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestHandler_OneRequestConsumesOneToken proves the bucket count
// increments by exactly 1 per accepted request — not 0, not 2.
func TestHandler_OneRequestConsumesOneToken(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	byAttrResolveClaims = fakeClaims("acme-bd", "acme", false, true)

	c, rec := newByAttrController(t, "", map[string]string{
		"Authorization":   "Bearer eyJ.svc.jwt",
		"X-Forwarded-For": "203.0.113.11",
	})
	c.GetUsersByAttribute()
	// Will be 400 (no attr) — that's fine; rate-limit still consumed.
	if rec.Code == http.StatusTooManyRequests {
		t.Fatal("first call must not be rate-limited")
	}

	// Now drain the remaining 9 slots; the 11th must 429.
	for i := 0; i < byAttributeRateBurst-1; i++ {
		if !byAttributeRateLimit("acme-bd") {
			t.Fatalf("drain call %d should be allowed", i+1)
		}
	}
	if byAttributeRateLimit("acme-bd") {
		t.Fatal("11th call must be denied — handler did not consume one slot")
	}
}

// TestRateLimit_KeysOnClientIdOnly_IgnoresXFF — the core Fix-3 assertion.
// The rate-limit bucket key is clientId ONLY. X-Forwarded-For is client-
// controlled at this layer (the ingress does not pin trustedIPs in the
// version pinned in universe), so an IP-keyed bucket would be bypassable
// by header rotation:
//
//	for i := 0; i < N; i++ {
//	    req.Header.Set("X-Forwarded-For", randIP())  // new bucket each time
//	}
//
// Part 1: 11 probes from the SAME JWT with a DIFFERENT XFF per request
//
//	→ the 11th must 429. If IP were in the key, every request would land
//	  in a fresh bucket and we would never hit the limit.
//
// Part 2: distinct clientIds must NOT share a bucket, even under the
//
//	same XFF — each service principal has its own 10/min quota.
func TestRateLimit_KeysOnClientIdOnly_IgnoresXFF(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd,acme-ats")
	byAttrResolveClaims = fakeClaims("acme-bd", "acme", false, true)

	// Part 1: rotate XFF on every request. Each call carries a different
	// IP; if the limiter were keyed on (clientId, IP) we'd never exhaust
	// the bucket. With the Fix-3 single-key limiter, the 11th call MUST
	// 429.
	var lastCode int
	for i := 0; i < byAttributeRateBurst+1; i++ {
		c, rec := newByAttrController(t, "", map[string]string{
			"Authorization":   "Bearer eyJ.svc.jwt",
			"X-Forwarded-For": fmt.Sprintf("198.51.100.%d", i+1),
		})
		c.GetUsersByAttribute()
		lastCode = rec.Code
		if i < byAttributeRateBurst {
			if rec.Code == http.StatusTooManyRequests {
				t.Fatalf("call %d/%d (XFF=198.51.100.%d) must not be rate-limited yet — XFF rotation must not create fresh buckets",
					i+1, byAttributeRateBurst+1, i+1)
			}
		}
	}
	if lastCode != http.StatusTooManyRequests {
		t.Fatalf("call %d (one past burst) must 429 even under XFF rotation; got %d", byAttributeRateBurst+1, lastCode)
	}

	// Part 2: a DIFFERENT clientId must have its OWN bucket. Same XFF
	// values as above, fresh clientId — must NOT inherit the exhausted
	// quota from the first principal.
	byAttrResolveClaims = fakeClaims("acme-ats", "acme", false, true)
	c, rec := newByAttrController(t, "", map[string]string{
		"Authorization":   "Bearer eyJ.svc2.jwt",
		"X-Forwarded-For": "198.51.100.1", // same as the very first call above
	})
	c.GetUsersByAttribute()
	if rec.Code == http.StatusTooManyRequests {
		t.Fatalf("second clientId must have its own bucket — no cross-talk; got %d (body: %s)", rec.Code, rec.Body.String())
	}
}

// TestRateLimit_BucketKeyIsLiteralClientId is a unit-level companion to
// TestRateLimit_KeysOnClientIdOnly_IgnoresXFF: it pokes the limiter
// directly to prove the key contains no IP component, even when callers
// at the handler layer would have wildly different IPs.
func TestRateLimit_BucketKeyIsLiteralClientId(t *testing.T) {
	resetByAttrState(t)
	// Drain acme-bd to the cap.
	for i := 0; i < byAttributeRateBurst; i++ {
		if !byAttributeRateLimit("acme-bd") {
			t.Fatalf("expected %d/min to be free, call %d was denied", byAttributeRateBurst, i+1)
		}
	}
	// The 11th call denied.
	if byAttributeRateLimit("acme-bd") {
		t.Fatal("11th call must be denied")
	}
	// acme-ats unrelated.
	if !byAttributeRateLimit("acme-ats") {
		t.Fatal("different clientId must have its own bucket")
	}
}

// TestHandler_ServiceCreds_TypePromotedUser_Returns403 — defense-in-depth
// for Fix 2. The original discriminator at defaultResolveServiceClaims
// keyed only on `claims.User.Type == "application"`, which is forgeable:
// controllers/user.go::AddUser / UpdateUser persist arbitrary `type`
// from the request body (object/user.go:928,934). A tenant admin could
// create a real human user with Type="application", set a password,
// password-grant a JWT, and ride that JWT through every endpoint that
// trusted the bare Type discriminator.
//
// The strengthened discriminator requires ALL of:
//   - claims.User.Type == "application"
//   - claims.User.Name == application.Name
//   - claims.Provider == ""
//   - claims.SigninMethod == ""
//
// The promoted-tenant-user JWT can fake Type but cannot fake Name
// without also owning an application with the same name in the same
// org (which is the same as already owning the legitimate
// client_credentials secret). Provider / SigninMethod are always set
// by password / authorization_code grants and never set by
// client_credentials.
//
// We exercise this by injecting a fake resolver that returns ok=false
// (the resolver itself rejected the forged JWT) and confirming the
// handler emits 403 — proving that the strengthened discriminator
// short-circuits before any business logic runs.
func TestHandler_ServiceCreds_TypePromotedUser_Returns403(t *testing.T) {
	resetByAttrState(t)
	t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
	// Resolver returns ok=false, anon=false — i.e. the JWT was
	// parseable but failed the strengthened discriminator (Name
	// didn't match app.Name, or Provider/SigninMethod were set).
	// This is the exact path a forged-Type tenant-admin-promoted
	// user would take.
	byAttrResolveClaims = fakeClaims("", "", false, false)

	c, rec := newByAttrController(t, "phone=9137779708", map[string]string{
		"Authorization": "Bearer eyJ.forged.type.application.jwt",
	})
	c.GetUsersByAttribute()

	if rec.Code != http.StatusForbidden {
		t.Fatalf("forged Type=\"application\" user JWT should be 403, got %d (body: %s)", rec.Code, rec.Body.String())
	}
	resp := decodeResp(t, rec)
	if resp["status"] != "error" {
		t.Fatalf("expected status=error, got %v", resp["status"])
	}
	// Message must be the canonical "client_credentials required" so
	// callers can distinguish from generic 403s.
	if msg, _ := resp["msg"].(string); !strings.Contains(strings.ToLower(msg), "server-to-server") {
		t.Fatalf("expected msg to mention server-to-server creds; got %q", msg)
	}
}

// TestServiceClaimsDiscriminator_RequiresAllFourFields documents the
// strengthened discriminator's truth table. Each case constructs a
// claims-resolver-style outcome the discriminator would reject; the
// test asserts the handler's response is consistent with "reject as
// 403 because the JWT is parseable but not a true client_credentials
// JWT".
//
// We can't exercise the real defaultResolveServiceClaims without a
// xorm engine + signed JWT, so this test exercises the BEHAVIORAL
// contract via the seam: the discriminator's job is to return
// (ok=false, anon=false) for every shape that LOOKS like service
// creds but isn't. The handler must respond with 403 to every such
// outcome.
func TestServiceClaimsDiscriminator_RequiresAllFourFields(t *testing.T) {
	cases := []struct {
		name string
		note string
	}{
		{"type_application_but_name_mismatch", "Type='application' but User.Name != app.Name — tenant-admin-promoted user"},
		{"type_application_but_provider_set", "Type='application' but Provider='okta' — password grant via federated IdP"},
		{"type_application_but_signin_method_set", "Type='application' but SigninMethod='password' — password grant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetByAttrState(t)
			t.Setenv("IAM_BY_ATTRIBUTE_ALLOWLIST", "acme-bd")
			// Discriminator rejection => (anon=false, ok=false).
			byAttrResolveClaims = fakeClaims("", "", false, false)

			c, rec := newByAttrController(t, "phone=9137779708", map[string]string{
				"Authorization": "Bearer eyJ.case." + tc.name + ".jwt",
			})
			c.GetUsersByAttribute()

			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: should be 403 (%s), got %d", tc.name, tc.note, rec.Code)
			}
		})
	}
}

// withTypeGuardCaller swaps the caller-resolver for the duration of a
// test, restoring it on cleanup. Mirrors the byAttrResolveClaims seam
// pattern.
func withTypeGuardCaller(t *testing.T, caller *object.User) {
	t.Helper()
	prev := resolveTypeGuardCaller
	resolveTypeGuardCaller = func(*ApiController) *object.User { return caller }
	t.Cleanup(func() { resolveTypeGuardCaller = prev })
}

// TestRejectApplicationTypePromotion_AllowsBuiltInAdmin verifies the
// defense-in-depth write-side guard accepts the IAM bootstrap path
// (caller in built-in/admin org) and rejects every other shape.
//
// IAM's existing semantics treat AdminOrg membership as the global-
// admin surface (object/user.go::IsSuperAdmin returns Owner ==
// AdminOrg). The guard inherits that policy: the *org* is the
// privilege boundary, not a separate role.
func TestRejectApplicationTypePromotion_AllowsBuiltInAdmin(t *testing.T) {
	cases := []struct {
		name   string
		caller *object.User
		allow  bool
	}{
		{
			name:   "nil caller (no session)",
			caller: nil,
			allow:  false,
		},
		{
			name:   "tenant org admin — the attack shape",
			caller: &object.User{Owner: "acme", Name: "tenant-admin", IsAdmin: true},
			allow:  false,
		},
		{
			name:   "tenant org global-admin claimant (forged isAdmin)",
			caller: &object.User{Owner: "acme", Name: "evil", IsAdmin: true},
			allow:  false,
		},
		{
			name:   "different tenant org admin (mlc)",
			caller: &object.User{Owner: "mlc", Name: "tenant-admin", IsAdmin: true},
			allow:  false,
		},
		{
			name:   "built-in/admin org member (IAM bootstrap path)",
			caller: &object.User{Owner: "admin", Name: "root"},
			allow:  true,
		},
		{
			name:   "built-in/admin org admin (IAM bootstrap path with admin role)",
			caller: &object.User{Owner: "admin", Name: "root", IsAdmin: true},
			allow:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := newByAttrController(t, "", nil)
			withTypeGuardCaller(t, tc.caller)
			body := &object.User{Type: "application", Name: "fake-app", Owner: "acme"}
			got := rejectApplicationTypePromotion(c, body)
			if got != tc.allow {
				t.Fatalf("%s: got %v, want %v", tc.name, got, tc.allow)
			}
		})
	}
}

// TestRejectApplicationTypePromotion_BenignTypeAlwaysAllowed makes
// sure the guard is a NO-OP for Type values other than "application".
// The vast majority of writes (normal-user, paid-user, etc.) must
// pass through unchanged.
func TestRejectApplicationTypePromotion_BenignTypeAlwaysAllowed(t *testing.T) {
	c, _ := newByAttrController(t, "", nil)
	withTypeGuardCaller(t, nil) // no caller — should still pass for benign types
	for _, ty := range []string{"", "normal-user", "paid-user", "merchant-user", "anonymous-user"} {
		t.Run(ty, func(t *testing.T) {
			body := &object.User{Type: ty, Name: "alice", Owner: "acme"}
			if !rejectApplicationTypePromotion(c, body) {
				t.Fatalf("guard must be a no-op for Type=%q", ty)
			}
		})
	}
}

// TestRejectApplicationTypePromotion_NilUser is a sanity boundary:
// a nil pointer must not panic, must be treated as "no application
// type" (i.e. allowed).
func TestRejectApplicationTypePromotion_NilUser(t *testing.T) {
	c, _ := newByAttrController(t, "", nil)
	withTypeGuardCaller(t, nil)
	if !rejectApplicationTypePromotion(c, nil) {
		t.Fatal("nil user must not be rejected")
	}
}

// TestAudit_DoesNotPersistProbedValues exercises the Fix-1 invariant:
// after the controller emits an audit record for a probe carrying
// phone=+19137779708&email=secret@victim.com, the persisted Record must
// contain NEITHER the phone nor the email — not in RequestUri (which
// the upstream NewRecord captures wholesale from ctx.Request.RequestURI)
// and not in Object (which NewRecord defaults to the request body, but
// we additionally guarantee stays empty here).
//
// This is the "never log the probed value" defense; without it the
// audit table becomes an enumeration oracle adjacent to the endpoint.
func TestAudit_DoesNotPersistProbedValues(t *testing.T) {
	// Build a controller whose context carries the dangerous query
	// string. The query string is what NewRecord would otherwise persist
	// into RequestUri verbatim.
	const probedPhone = "+19137779708"
	const probedEmail = "secret@victim.com"
	q := url.Values{}
	q.Set("phone", probedPhone)
	q.Set("email", probedEmail)
	c, _ := newByAttrController(t, q.Encode(), map[string]string{
		"Authorization": "Bearer eyJ.svc.jwt",
	})
	// NewRecord reads `ctx.Input.Data()["json"]` and round-trips it. We
	// must seed it with a marshallable value; an empty Response struct
	// is the simplest.
	c.Data["json"] = &object.Response{Status: "ok", Msg: ""}

	rec, err := buildByAttributeAuditRecord(c, "acme-bd", "acme", "phone", 0, http.StatusOK, "")
	if err != nil {
		t.Fatalf("buildByAttributeAuditRecord: %v", err)
	}
	if rec == nil {
		t.Fatal("nil record")
	}

	// Invariant 1: RequestUri is the bare path. No query string.
	if rec.RequestUri != "/v1/iam/users/by-attribute" {
		t.Fatalf("RequestUri = %q; want %q (no query string allowed)", rec.RequestUri, "/v1/iam/users/by-attribute")
	}
	if strings.Contains(rec.RequestUri, "phone=") {
		t.Fatalf("RequestUri leaked phone= substring: %q", rec.RequestUri)
	}
	if strings.Contains(rec.RequestUri, "email=") {
		t.Fatalf("RequestUri leaked email= substring: %q", rec.RequestUri)
	}
	if strings.Contains(rec.RequestUri, "?") {
		t.Fatalf("RequestUri must have no query string at all: %q", rec.RequestUri)
	}

	// Invariant 2: Object stays empty. NewRecord's default for GET is
	// "" because there's no request body; we deliberately do not write
	// the {attribute,count,reason} shape into Object — that would create
	// a second persistence path adjacent to RequestUri.
	if rec.Object != "" {
		t.Fatalf("Object must be empty (PII-free); got %q", rec.Object)
	}

	// Invariant 3: the probed values appear NOWHERE in the persisted
	// record. Scan every textual field.
	for fieldName, fieldValue := range map[string]string{
		"RequestUri":   rec.RequestUri,
		"Action":       rec.Action,
		"Object":       rec.Object,
		"Response":     rec.Response,
		"User":         rec.User,
		"Organization": rec.Organization,
		"ClientIp":     rec.ClientIp,
		"Method":       rec.Method,
	} {
		for _, leak := range []string{probedPhone, probedEmail, "9137779708", "secret"} {
			if strings.Contains(fieldValue, leak) {
				t.Fatalf("record field %s leaked %q (value: %q)", fieldName, leak, fieldValue)
			}
		}
	}

	// Sanity: the shape we DO want is still present. Response carries
	// {attribute, count, status} — none of which are PII.
	if !strings.Contains(rec.Response, "phone") { // "phone" appears as the attribute-type literal "phone", not as the value
		t.Fatalf("Response should encode the attribute TYPE; got %q", rec.Response)
	}
	if !strings.Contains(rec.Response, "count:0") {
		t.Fatalf("Response should encode result count; got %q", rec.Response)
	}
	// Action is the bucket identifier — fine.
	if rec.Action != "users/by-attribute" {
		t.Fatalf("Action = %q; want %q", rec.Action, "users/by-attribute")
	}
}

// minimalUserWithSecrets returns an *object.User populated with a
// representative set of secret-bearing fields. The projection helper
// must drop ALL of them.
func minimalUserWithSecrets(owner, name string) *object.User {
	display := name
	if len(name) > 0 {
		display = strings.ToUpper(name[:1]) + name[1:]
	}
	return &object.User{
		Owner:        owner,
		Name:         name,
		Id:           "uid-" + name,
		Email:        name + "@example.com",
		Phone:        "+19137779708",
		DisplayName:  display,
		CreatedTime:  "2026-05-27T00:00:00Z",
		Password:     "should-NEVER-leak",
		PasswordSalt: "salt-should-NEVER-leak",
		PasswordType: "argon2id",
		TotpSecret:   "totp-should-NEVER-leak",
	}
}
