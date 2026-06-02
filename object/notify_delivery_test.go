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

package object

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// resetNotifyDeliveryCache wipes the cached config so a test can re-run
// the guard against fresh env. Defer this in every test that touches
// IAM_NOTIFY_* env so leakage between tests is bounded.
func resetNotifyDeliveryCache() {
	notifyDeliveryCacheMu.Lock()
	cachedNotifyEnabled = false
	cachedNotifyURL = ""
	cachedNotifyToken = ""
	cachedNotifyTenant = ""
	cachedNotifyTimeout = 0
	cachedNotifyTemplate = ""
	notifyDeliveryCacheMu.Unlock()

	activeDelivererMu.Lock()
	activeDeliverer = nil
	activeDelivererMu.Unlock()
}

func TestEnforceNotifyDeliveryGuard_DisabledByDefault(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "")
	EnforceNotifyDeliveryGuard()
	if NotifyDeliveryEnabled() {
		t.Fatal("notify delivery should be disabled when IAM_NOTIFY_URL is unset")
	}
}

func TestEnforceNotifyDeliveryGuard_StubDisables(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "stub")
	EnforceNotifyDeliveryGuard()
	if NotifyDeliveryEnabled() {
		t.Fatal("notify delivery should be disabled when IAM_NOTIFY_URL=stub")
	}
}

func TestEnforceNotifyDeliveryGuard_StubCaseInsensitive(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "STUB")
	EnforceNotifyDeliveryGuard()
	if NotifyDeliveryEnabled() {
		t.Fatal("notify delivery should be disabled when IAM_NOTIFY_URL=STUB")
	}
}

func TestEnforceNotifyDeliveryGuard_RejectsNonHTTPURL(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "notify.example.com")
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on non-http URL")
		}
	}()
	EnforceNotifyDeliveryGuard()
}

func TestEnforceNotifyDeliveryGuard_EnabledOnValidURL(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080")
	t.Setenv(envIAMNotifyToken, "tok-xxx")
	t.Setenv(envIAMNotifyTenant, "liquidity")
	EnforceNotifyDeliveryGuard()
	if !NotifyDeliveryEnabled() {
		t.Fatal("notify delivery should be enabled when IAM_NOTIFY_URL is set")
	}
	notifyDeliveryCacheMu.RLock()
	defer notifyDeliveryCacheMu.RUnlock()
	if cachedNotifyURL != "http://notify.svc.local:8080" {
		t.Fatalf("cachedNotifyURL=%q, want http://notify.svc.local:8080", cachedNotifyURL)
	}
	if cachedNotifyToken != "tok-xxx" {
		t.Fatalf("cachedNotifyToken=%q, want tok-xxx", cachedNotifyToken)
	}
	if cachedNotifyTenant != "liquidity" {
		t.Fatalf("cachedNotifyTenant=%q, want liquidity", cachedNotifyTenant)
	}
	if cachedNotifyTimeout != defaultNotifyTimeout {
		t.Fatalf("cachedNotifyTimeout=%v, want %v", cachedNotifyTimeout, defaultNotifyTimeout)
	}
	if cachedNotifyTemplate != NotifyOTPEvent {
		t.Fatalf("cachedNotifyTemplate=%q, want %q", cachedNotifyTemplate, NotifyOTPEvent)
	}
}

func TestEnforceNotifyDeliveryGuard_TrimsTrailingSlash(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080/")
	EnforceNotifyDeliveryGuard()
	notifyDeliveryCacheMu.RLock()
	defer notifyDeliveryCacheMu.RUnlock()
	if cachedNotifyURL != "http://notify.svc.local:8080" {
		t.Fatalf("cachedNotifyURL=%q, want http://notify.svc.local:8080 (trailing slash should be trimmed)", cachedNotifyURL)
	}
}

func TestEnforceNotifyDeliveryGuard_TenantDefaultsToLiquidity(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080")
	t.Setenv(envIAMNotifyTenant, "")
	EnforceNotifyDeliveryGuard()
	notifyDeliveryCacheMu.RLock()
	defer notifyDeliveryCacheMu.RUnlock()
	if cachedNotifyTenant != "liquidity" {
		t.Fatalf("cachedNotifyTenant=%q, want liquidity (default when env unset)", cachedNotifyTenant)
	}
}

func TestEnforceNotifyDeliveryGuard_CustomTimeout(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080")
	t.Setenv(envIAMNotifyTimeout, "2s")
	EnforceNotifyDeliveryGuard()
	notifyDeliveryCacheMu.RLock()
	defer notifyDeliveryCacheMu.RUnlock()
	if cachedNotifyTimeout != 2*time.Second {
		t.Fatalf("cachedNotifyTimeout=%v, want 2s", cachedNotifyTimeout)
	}
}

func TestEnforceNotifyDeliveryGuard_CustomTemplate(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080")
	t.Setenv(envIAMNotifyTemplate, "liquidity.iam.otp")
	EnforceNotifyDeliveryGuard()
	notifyDeliveryCacheMu.RLock()
	defer notifyDeliveryCacheMu.RUnlock()
	if cachedNotifyTemplate != "liquidity.iam.otp" {
		t.Fatalf("cachedNotifyTemplate=%q, want liquidity.iam.otp", cachedNotifyTemplate)
	}
}

// fakeDeliverer captures DeliverOTPViaNotify calls so tests can assert
// the wire shape without standing up an HTTP server. Used to exercise
// the verification.go integration paths.
type fakeDeliverer struct {
	mu    sync.Mutex
	calls []NotifySendInput
	err   error
}

func (f *fakeDeliverer) Deliver(_ context.Context, in NotifySendInput) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, in)
	return f.err
}

func (f *fakeDeliverer) lastCall() NotifySendInput {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.calls) == 0 {
		return NotifySendInput{}
	}
	return f.calls[len(f.calls)-1]
}

func TestDeliverOTPViaNotify_RejectsBadChannel(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080")
	EnforceNotifyDeliveryGuard()

	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{
		Channel:   "push",
		Recipient: "+15551234567",
		OTP:       "123456",
	})
	if err == nil {
		t.Fatal("expected error for unsupported channel")
	}
	if !strings.Contains(err.Error(), "channel must be sms|email") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestDeliverOTPViaNotify_RejectsEmptyRecipient(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080")
	EnforceNotifyDeliveryGuard()

	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{
		Channel: "sms",
		OTP:     "123456",
	})
	if err == nil || !strings.Contains(err.Error(), "recipient is required") {
		t.Fatalf("expected recipient required error, got %v", err)
	}
}

func TestDeliverOTPViaNotify_RejectsEmptyOTP(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080")
	EnforceNotifyDeliveryGuard()

	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{
		Channel:   "sms",
		Recipient: "+15551234567",
	})
	if err == nil || !strings.Contains(err.Error(), "otp is required") {
		t.Fatalf("expected otp required error, got %v", err)
	}
}

func TestDeliverOTPViaNotify_DisabledReturnsError(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "")
	EnforceNotifyDeliveryGuard()

	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{
		Channel:   "sms",
		Recipient: "+15551234567",
		OTP:       "123456",
	})
	if err == nil {
		t.Fatal("expected error when delivery is disabled")
	}
}

func TestDeliverOTPViaNotify_DefaultsTenant(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080")
	t.Setenv(envIAMNotifyTenant, "myorg")
	EnforceNotifyDeliveryGuard()

	fake := &fakeDeliverer{}
	SetNotifyDeliverer(fake)

	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{
		Channel:   "sms",
		Recipient: "+15551234567",
		OTP:       "123456",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := fake.lastCall()
	if got.Tenant != "myorg" {
		t.Fatalf("tenant=%q, want myorg (default applied)", got.Tenant)
	}
}

func TestDeliverOTPViaNotify_HonorsExplicitTenant(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyURL, "http://notify.svc.local:8080")
	t.Setenv(envIAMNotifyTenant, "default-tenant")
	EnforceNotifyDeliveryGuard()

	fake := &fakeDeliverer{}
	SetNotifyDeliverer(fake)

	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{
		Channel:   "sms",
		Recipient: "+15551234567",
		OTP:       "123456",
		Tenant:    "explicit-tenant",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := fake.lastCall()
	if got.Tenant != "explicit-tenant" {
		t.Fatalf("tenant=%q, want explicit-tenant (explicit should win over default)", got.Tenant)
	}
}

// TestHTTPDeliverer_HappyPath stands up a fake notifyd, runs the HTTP
// deliverer against it, and asserts the wire shape: POST /v1/notify/send
// ?sync=true, JSON body with event/channel/to/template_vars, Authorization
// bearer header, X-Org-Id header.
func TestHTTPDeliverer_HappyPath(t *testing.T) {
	var (
		gotMethod, gotPath, gotQuery string
		gotAuth, gotOrgID            string
		gotBody                      notifySendBody
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		gotOrgID = r.Header.Get("X-Org-Id")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message_id":"m1","status":"sent"}`))
	}))
	defer srv.Close()

	d := newHTTPNotifyDeliverer(srv.URL, "tok-xxx", 5*time.Second)
	defer resetNotifyDeliveryCache()
	// notifyTemplateName() reads cachedNotifyTemplate; install it directly
	// without going through the guard so we don't need a full env setup.
	notifyDeliveryCacheMu.Lock()
	cachedNotifyTemplate = NotifyOTPEvent
	notifyDeliveryCacheMu.Unlock()

	err := d.Deliver(context.Background(), NotifySendInput{
		Channel:   "sms",
		Recipient: "+15551234567",
		OTP:       "987654",
		AppName:   "Liquidity",
		Tenant:    "liquidity",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method=%q, want POST", gotMethod)
	}
	if gotPath != "/v1/notify/send" {
		t.Errorf("path=%q, want /v1/notify/send", gotPath)
	}
	if gotQuery != "sync=true" {
		t.Errorf("query=%q, want sync=true", gotQuery)
	}
	if gotAuth != "Bearer tok-xxx" {
		t.Errorf("Authorization=%q, want 'Bearer tok-xxx'", gotAuth)
	}
	if gotOrgID != "liquidity" {
		t.Errorf("X-Org-Id=%q, want liquidity", gotOrgID)
	}
	if len(gotBody.To) != 1 || gotBody.To[0] != "+15551234567" {
		t.Errorf("body.to=%v, want [+15551234567]", gotBody.To)
	}
	if gotBody.Channel != "sms" {
		t.Errorf("body.channel=%q, want sms", gotBody.Channel)
	}
	if gotBody.Event != NotifyOTPEvent {
		t.Errorf("body.event=%q, want %q", gotBody.Event, NotifyOTPEvent)
	}
	if gotBody.TemplateVars["otp"] != "987654" {
		t.Errorf("body.template_vars[otp]=%v, want 987654", gotBody.TemplateVars["otp"])
	}
	if gotBody.TemplateVars["recipient"] != "+15551234567" {
		t.Errorf("body.template_vars[recipient]=%v, want +15551234567", gotBody.TemplateVars["recipient"])
	}
	if gotBody.TemplateVars["app"] != "Liquidity" {
		t.Errorf("body.template_vars[app]=%v, want Liquidity", gotBody.TemplateVars["app"])
	}
}

// TestHTTPDeliverer_4xxReturnsError verifies failure surface — a 400 from
// notifyd (e.g. template missing for tenant) propagates back to IAM with
// the body in the error string so operators can diagnose.
func TestHTTPDeliverer_4xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"template not found"}`))
	}))
	defer srv.Close()

	d := newHTTPNotifyDeliverer(srv.URL, "tok-xxx", 5*time.Second)
	err := d.Deliver(context.Background(), NotifySendInput{
		Channel:   "sms",
		Recipient: "+15551234567",
		OTP:       "111111",
		Tenant:    "liquidity",
	})
	if err == nil {
		t.Fatal("expected error on 4xx")
	}
	if !strings.Contains(err.Error(), "status=400") {
		t.Errorf("error should mention status=400, got %v", err)
	}
	if !strings.Contains(err.Error(), "template not found") {
		t.Errorf("error should propagate body, got %v", err)
	}
}

// TestHTTPDeliverer_FailedStatusReturnsError verifies the sync-mode
// failure path: notifyd returns 200 with status="failed", error="...".
func TestHTTPDeliverer_FailedStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message_id":"m1","status":"failed","error":"plivo: bad number"}`))
	}))
	defer srv.Close()

	d := newHTTPNotifyDeliverer(srv.URL, "", 5*time.Second)
	err := d.Deliver(context.Background(), NotifySendInput{
		Channel:   "sms",
		Recipient: "+15551234567",
		OTP:       "111111",
	})
	if err == nil {
		t.Fatal("expected error on status=failed")
	}
	if !strings.Contains(err.Error(), "plivo: bad number") {
		t.Errorf("error should propagate provider error, got %v", err)
	}
}

// TestHTTPDeliverer_UnexpectedStatusReturnsError covers the case where
// notifyd returns 200 + a non-terminal status — IAM must NOT treat that
// as success because sync mode promised a terminal result.
func TestHTTPDeliverer_UnexpectedStatusReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message_id":"m1","status":"queued"}`))
	}))
	defer srv.Close()

	d := newHTTPNotifyDeliverer(srv.URL, "", 5*time.Second)
	err := d.Deliver(context.Background(), NotifySendInput{
		Channel:   "sms",
		Recipient: "+15551234567",
		OTP:       "111111",
	})
	if err == nil {
		t.Fatal("expected error on unexpected sync-mode status")
	}
	if !strings.Contains(err.Error(), "unexpected status") {
		t.Errorf("error should mention unexpected status, got %v", err)
	}
}

func TestHTTPDeliverer_OmitsAuthHeaderWhenTokenEmpty(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"message_id":"m1","status":"sent"}`))
	}))
	defer srv.Close()

	d := newHTTPNotifyDeliverer(srv.URL, "", 5*time.Second)
	err := d.Deliver(context.Background(), NotifySendInput{
		Channel:   "sms",
		Recipient: "+15551234567",
		OTP:       "111111",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if gotAuth != "" {
		t.Errorf("Authorization header should be omitted when token is empty, got %q", gotAuth)
	}
}
