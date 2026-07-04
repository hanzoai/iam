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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	fasthttp "github.com/valyala/fasthttp"
	zaphttp "github.com/zap-proto/http"
)

// resetNotifyDeliveryCache wipes the cached config so a test can re-run the guard
// against fresh env. Defer this in every test that touches IAM_NOTIFY_* env.
func resetNotifyDeliveryCache() {
	notifyDeliveryCacheMu.Lock()
	cachedNotifyEnabled = false
	cachedNotifyZAPAddr = ""
	cachedNotifyTimeout = 0
	cachedNotifyTemplate = ""
	notifyDeliveryCacheMu.Unlock()

	activeDelivererMu.Lock()
	activeDeliverer = nil
	activeDelivererMu.Unlock()
}

func TestEnforceNotifyDeliveryGuard_DisabledByDefault(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyZAPAddr, "")
	EnforceNotifyDeliveryGuard()
	if NotifyDeliveryEnabled() {
		t.Fatal("notify delivery should be disabled when IAM_NOTIFY_ZAP_ADDR is unset")
	}
}

func TestEnforceNotifyDeliveryGuard_StubDisables(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyZAPAddr, "STUB")
	EnforceNotifyDeliveryGuard()
	if NotifyDeliveryEnabled() {
		t.Fatal("notify delivery should be disabled when IAM_NOTIFY_ZAP_ADDR=STUB")
	}
}

func TestEnforceNotifyDeliveryGuard_RejectsURLScheme(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyZAPAddr, "http://cloud.hanzo.svc:9653")
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic when IAM_NOTIFY_ZAP_ADDR carries a URL scheme (ZAP is a raw transport)")
		}
	}()
	EnforceNotifyDeliveryGuard()
}

func TestEnforceNotifyDeliveryGuard_EnabledOnBareAddr(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyZAPAddr, "cloud.hanzo.svc:9653")
	EnforceNotifyDeliveryGuard()
	if !NotifyDeliveryEnabled() {
		t.Fatal("notify delivery should be enabled on a bare host:port ZAP address")
	}
	notifyDeliveryCacheMu.RLock()
	defer notifyDeliveryCacheMu.RUnlock()
	if cachedNotifyZAPAddr != "cloud.hanzo.svc:9653" {
		t.Fatalf("cachedNotifyZAPAddr=%q, want cloud.hanzo.svc:9653", cachedNotifyZAPAddr)
	}
	if cachedNotifyTimeout != defaultNotifyTimeout {
		t.Fatalf("cachedNotifyTimeout=%v, want %v", cachedNotifyTimeout, defaultNotifyTimeout)
	}
	if cachedNotifyTemplate != NotifyOTPEvent {
		t.Fatalf("cachedNotifyTemplate=%q, want %q", cachedNotifyTemplate, NotifyOTPEvent)
	}
}

func TestEnforceNotifyDeliveryGuard_CustomTimeoutAndTemplate(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyZAPAddr, "cloud.hanzo.svc:9653")
	t.Setenv(envIAMNotifyTimeout, "2s")
	t.Setenv(envIAMNotifyTemplate, "hanzo.iam.otp")
	EnforceNotifyDeliveryGuard()
	notifyDeliveryCacheMu.RLock()
	defer notifyDeliveryCacheMu.RUnlock()
	if cachedNotifyTimeout != 2*time.Second {
		t.Fatalf("cachedNotifyTimeout=%v, want 2s", cachedNotifyTimeout)
	}
	if cachedNotifyTemplate != "hanzo.iam.otp" {
		t.Fatalf("cachedNotifyTemplate=%q, want hanzo.iam.otp", cachedNotifyTemplate)
	}
}

// fakeDeliverer captures DeliverOTPViaNotify calls so tests can assert the seam
// without a transport.
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

func enableWithFake(t *testing.T) *fakeDeliverer {
	t.Helper()
	t.Setenv(envIAMNotifyZAPAddr, "cloud.hanzo.svc:9653")
	EnforceNotifyDeliveryGuard()
	fake := &fakeDeliverer{}
	SetNotifyDeliverer(fake)
	return fake
}

func TestDeliverOTPViaNotify_RejectsBadChannel(t *testing.T) {
	defer resetNotifyDeliveryCache()
	enableWithFake(t)
	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{
		Channel: "push", Recipient: "+15551234567", OTP: "123456",
	})
	if err == nil || !strings.Contains(err.Error(), "channel must be sms|email") {
		t.Fatalf("expected unsupported-channel error, got %v", err)
	}
}

func TestDeliverOTPViaNotify_RejectsEmptyRecipient(t *testing.T) {
	defer resetNotifyDeliveryCache()
	enableWithFake(t)
	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{Channel: "sms", OTP: "123456"})
	if err == nil || !strings.Contains(err.Error(), "recipient is required") {
		t.Fatalf("expected recipient-required error, got %v", err)
	}
}

func TestDeliverOTPViaNotify_RejectsEmptyOTP(t *testing.T) {
	defer resetNotifyDeliveryCache()
	enableWithFake(t)
	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{Channel: "sms", Recipient: "+15551234567"})
	if err == nil || !strings.Contains(err.Error(), "otp is required") {
		t.Fatalf("expected otp-required error, got %v", err)
	}
}

func TestDeliverOTPViaNotify_DisabledReturnsError(t *testing.T) {
	defer resetNotifyDeliveryCache()
	t.Setenv(envIAMNotifyZAPAddr, "")
	EnforceNotifyDeliveryGuard()
	err := DeliverOTPViaNotify(context.Background(), NotifySendInput{
		Channel: "sms", Recipient: "+15551234567", OTP: "123456",
	})
	if err == nil {
		t.Fatal("expected error when delivery is disabled")
	}
}

func TestDeliverOTPViaNotify_PassesInputThrough(t *testing.T) {
	defer resetNotifyDeliveryCache()
	fake := enableWithFake(t)
	if err := DeliverOTPViaNotify(context.Background(), NotifySendInput{
		Channel: "sms", Recipient: "+15551234567", OTP: "123456", AppName: "Hanzo", Tenant: "acme",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := fake.lastCall()
	if got.Recipient != "+15551234567" || got.OTP != "123456" || got.AppName != "Hanzo" {
		t.Fatalf("input not passed through: %+v", got)
	}
}

// startZAPNotifyServer stands up a real ZAP server (zap-proto/http) that captures
// one request and replies with a fixed notify body. It returns the bound addr and
// a getter for the captured request. Proves the ZAP transport carries method,
// path, query, Authorization header, and JSON body end-to-end.
type capturedReq struct {
	method, path, query, auth string
	body                      notifySendBody
}

func startZAPNotifyServer(t *testing.T, replyStatus string) (addr string, captured func() capturedReq) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var mu sync.Mutex
	var cap capturedReq
	srv := &zaphttp.Server{Handler: func(ctx *fasthttp.RequestCtx) {
		mu.Lock()
		cap.method = string(ctx.Method())
		cap.path = string(ctx.Path())
		cap.query = string(ctx.QueryArgs().QueryString())
		cap.auth = string(ctx.Request.Header.Peek("Authorization"))
		_ = json.Unmarshal(ctx.PostBody(), &cap.body)
		mu.Unlock()
		ctx.SetContentType("application/json")
		_, _ = ctx.Write([]byte(`{"message_id":"m1","status":"` + replyStatus + `"}`))
	}}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), func() capturedReq {
		mu.Lock()
		defer mu.Unlock()
		return cap
	}
}

// staticTokenSource returns a serviceTokenSource whose token is pre-cached, so
// Deliver does not touch the DB-backed mint path in a unit test.
func staticTokenSource(tok string) *serviceTokenSource {
	return &serviceTokenSource{token: tok, expires: time.Now().Add(time.Hour)}
}

func TestZAPDeliverer_HappyPath(t *testing.T) {
	addr, captured := startZAPNotifyServer(t, "sent")

	d := newZAPNotifyDeliverer(addr, NotifyOTPEvent, 5*time.Second, staticTokenSource("tok-xxx"))
	if err := d.Deliver(context.Background(), NotifySendInput{
		Channel: "sms", Recipient: "+15551234567", OTP: "987654", AppName: "Hanzo", Tenant: "acme",
	}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	c := captured()
	if c.method != fasthttp.MethodPost {
		t.Errorf("method=%q, want POST", c.method)
	}
	if c.path != "/v1/notify/send" {
		t.Errorf("path=%q, want /v1/notify/send", c.path)
	}
	if c.query != "sync=true" {
		t.Errorf("query=%q, want sync=true", c.query)
	}
	if c.auth != "Bearer tok-xxx" {
		t.Errorf("Authorization=%q, want 'Bearer tok-xxx'", c.auth)
	}
	// The tenant is NEVER sent as a client header — cloud derives org from the
	// validated M2M token. The body carries only the send payload.
	if len(c.body.To) != 1 || c.body.To[0] != "+15551234567" {
		t.Errorf("body.to=%v, want [+15551234567]", c.body.To)
	}
	if c.body.Channel != "sms" {
		t.Errorf("body.channel=%q, want sms", c.body.Channel)
	}
	if c.body.Event != NotifyOTPEvent {
		t.Errorf("body.event=%q, want %q", c.body.Event, NotifyOTPEvent)
	}
	if c.body.TemplateVars["otp"] != "987654" {
		t.Errorf("body.template_vars[otp]=%v, want 987654", c.body.TemplateVars["otp"])
	}
	if c.body.TemplateVars["app"] != "Hanzo" {
		t.Errorf("body.template_vars[app]=%v, want Hanzo", c.body.TemplateVars["app"])
	}
}

func TestZAPDeliverer_ProviderFailedIsError(t *testing.T) {
	addr, _ := startZAPNotifyServer(t, "failed")
	d := newZAPNotifyDeliverer(addr, NotifyOTPEvent, 5*time.Second, staticTokenSource("tok-xxx"))
	err := d.Deliver(context.Background(), NotifySendInput{
		Channel: "sms", Recipient: "+15551234567", OTP: "1", AppName: "Hanzo",
	})
	if err == nil || !strings.Contains(err.Error(), "provider failed") {
		t.Fatalf("expected provider-failed error, got %v", err)
	}
}

// craftJWT builds an unsigned compact JWS carrying only `exp` — enough to exercise
// jwtExpiry (which never verifies the signature).
func craftJWT(exp int64) string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d,"owner":"hanzo"}`, exp)))
	return h + "." + p + ".sig"
}

func TestJWTExpiryDecode(t *testing.T) {
	want := time.Now().Add(30 * time.Minute).Unix()
	got, ok := jwtExpiry(craftJWT(want))
	if !ok || got.Unix() != want {
		t.Fatalf("jwtExpiry = %v,%v; want unix %d", got.Unix(), ok, want)
	}
	// Malformed / no-exp tokens must report !ok so the source falls back to a SHORT
	// re-mint interval rather than trusting a bogus long lifetime.
	for _, bad := range []string{"", "a.b", "a.b.c.d", "not-base64!.@#.$%", craftNoExpJWT()} {
		if _, ok := jwtExpiry(bad); ok {
			t.Errorf("jwtExpiry(%q) = ok; want !ok", bad)
		}
	}
}

func craftNoExpJWT() string {
	h := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`))
	p := base64.RawURLEncoding.EncodeToString([]byte(`{"owner":"hanzo"}`))
	return h + "." + p + ".sig"
}

// seqTokenSource returns tokens in sequence; Invalidate advances to the next. Lets
// a test model "stale token rejected, fresh token accepted".
type seqTokenSource struct {
	mu          sync.Mutex
	toks        []string
	idx         int
	calls       int
	invalidated int
}

func (s *seqTokenSource) Token(context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls++
	i := s.idx
	if i >= len(s.toks) {
		i = len(s.toks) - 1
	}
	return s.toks[i], nil
}
func (s *seqTokenSource) Invalidate() {
	s.mu.Lock()
	s.invalidated++
	if s.idx < len(s.toks)-1 {
		s.idx++
	}
	s.mu.Unlock()
}

// startAuthZAPServer replies 401 unless the request bearer equals wantBearer, in
// which case it replies 200 {status:sent}. Models cloud rejecting a stale token.
func startAuthZAPServer(t *testing.T, wantBearer string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &zaphttp.Server{Handler: func(ctx *fasthttp.RequestCtx) {
		if string(ctx.Request.Header.Peek("Authorization")) != "Bearer "+wantBearer {
			ctx.SetStatusCode(fasthttp.StatusUnauthorized)
			ctx.SetContentType("application/json")
			_, _ = ctx.Write([]byte(`{"status":"error","error":"unauthorized"}`))
			return
		}
		ctx.SetContentType("application/json")
		_, _ = ctx.Write([]byte(`{"message_id":"m","status":"sent"}`))
	}}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func TestZAPDeliverer_ReMintsOn401(t *testing.T) {
	addr := startAuthZAPServer(t, "fresh")
	ts := &seqTokenSource{toks: []string{"stale", "fresh"}}
	d := newZAPNotifyDeliverer(addr, NotifyOTPEvent, 5*time.Second, ts)

	if err := d.Deliver(context.Background(), NotifySendInput{
		Channel: "sms", Recipient: "+15551234567", OTP: "1", AppName: "Hanzo",
	}); err != nil {
		t.Fatalf("expected success after re-mint, got %v", err)
	}
	if ts.invalidated != 1 {
		t.Errorf("invalidated=%d, want 1 (cache dropped on 401)", ts.invalidated)
	}
	if ts.calls != 2 {
		t.Errorf("Token calls=%d, want 2 (stale + fresh)", ts.calls)
	}
}

func TestZAPDeliverer_Persistent401ErrorsNoLoop(t *testing.T) {
	addr := startAuthZAPServer(t, "never-matches") // every request 401s
	ts := &seqTokenSource{toks: []string{"a", "b"}}
	d := newZAPNotifyDeliverer(addr, NotifyOTPEvent, 5*time.Second, ts)

	err := d.Deliver(context.Background(), NotifySendInput{
		Channel: "sms", Recipient: "+15551234567", OTP: "1", AppName: "Hanzo",
	})
	if err == nil || !strings.Contains(err.Error(), "status=401") {
		t.Fatalf("expected surfaced 401 error, got %v", err)
	}
	if ts.calls != 2 { // exactly one retry — no infinite loop
		t.Errorf("Token calls=%d, want 2 (one retry only)", ts.calls)
	}
}

// flakyListener drops the FIRST accepted connection (client sees EOF/reset), then
// passes every subsequent connection through — models a pooled ZAP connection the
// peer closed between sends (the lone `read response: EOF` the 20-min G4 loop hit).
type flakyListener struct {
	net.Listener
	dropped atomic.Bool
}

func (l *flakyListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if l.dropped.CompareAndSwap(false, true) {
		_ = c.Close()   // first connection: drop it → the client's send errors
		return l.Accept() // block for the retry's fresh connection
	}
	return c, nil
}

func TestZAPDeliverer_RetriesTransientTransportError(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &zaphttp.Server{Handler: func(ctx *fasthttp.RequestCtx) {
		ctx.SetContentType("application/json")
		_, _ = ctx.Write([]byte(`{"message_id":"m","status":"sent"}`))
	}}
	go func() { _ = srv.Serve(&flakyListener{Listener: ln}) }()
	t.Cleanup(func() { _ = srv.Close() })

	// staticTokenSource never invalidates on this path, so a success here proves the
	// retry fired for the TRANSPORT error (not the 401 path).
	d := newZAPNotifyDeliverer(ln.Addr().String(), NotifyOTPEvent, 5*time.Second, staticTokenSource("tok"))
	if err := d.Deliver(context.Background(), NotifySendInput{
		Channel: "sms", Recipient: "+15551234567", OTP: "1", AppName: "Hanzo",
	}); err != nil {
		t.Fatalf("expected success after a transient-EOF retry, got %v", err)
	}
}

func TestIsInternalServiceApplication(t *testing.T) {
	// Explicit marker → internal.
	if !IsInternalServiceApplication(&Application{Name: "x", Organization: "hanzo", Description: InternalServiceAppMarker}) {
		t.Error("marker app should be internal")
	}
	// Reserved <org>-iam naming → internal (fallback even if Description stripped).
	if !IsInternalServiceApplication(&Application{Name: "hanzo-iam", Organization: "hanzo"}) {
		t.Error("hanzo-iam should be internal by naming")
	}
	// A normal public client_credentials app (e.g. hanzo-cloud) is NOT internal.
	if IsInternalServiceApplication(&Application{Name: "hanzo-cloud", Organization: "hanzo"}) {
		t.Error("hanzo-cloud must NOT be internal (legit public client_credentials)")
	}
	if IsInternalServiceApplication(nil) {
		t.Error("nil app must not be internal")
	}
}
