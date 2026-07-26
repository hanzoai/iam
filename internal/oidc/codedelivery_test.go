// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// The delivery seam, driven against a stand-in notify rail that speaks the real
// wire contract. The point of every test here is the same invariant from the two
// ends: what auth/methods ADVERTISES and what send-verification-code DOES are the
// same fact, and both track whether a code can actually be delivered.

// rail is a stand-in for the cloud notify fold. It records what it was sent so a
// test can assert iam2 spoke the documented contract, and can be made unhealthy
// or made to fail a send.
type rail struct {
	*httptest.Server
	mu       sync.Mutex
	healthy  bool
	status   string // terminal status returned for a sync send
	sends    []notifySendRequest
	auth     []string
	syncSeen []string
}

func newRail(t *testing.T) *rail {
	t.Helper()
	r := &rail{healthy: true, status: "sent"}
	mux := http.NewServeMux()
	mux.HandleFunc(pathNotifyHealth, func(w http.ResponseWriter, _ *http.Request) {
		r.mu.Lock()
		ok := r.healthy
		r.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte(`{"service":"notify","status":"ok"}`))
	})
	mux.HandleFunc(pathNotifySend, func(w http.ResponseWriter, req *http.Request) {
		var in notifySendRequest
		_ = json.NewDecoder(req.Body).Decode(&in)
		r.mu.Lock()
		r.sends = append(r.sends, in)
		r.auth = append(r.auth, req.Header.Get("Authorization"))
		r.syncSeen = append(r.syncSeen, req.URL.Query().Get("sync"))
		status := r.status
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(notifySendResponse{MessageID: "msg-1", Status: status})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	r.Server = srv
	return r
}

// useRail points iam2's courier at r and gives it a service credential. Each
// test gets a distinct httptest URL, so the reachability memo (keyed by
// endpoint) never serves one test a verdict taken for another.
func useRail(t *testing.T, r *rail) {
	t.Helper()
	t.Setenv("NOTIFY_ENDPOINT", r.URL)
	t.Setenv("IAM_SERVICE_TOKEN", "svc-token-do-not-log")
}

func (r *rail) lastSend(t *testing.T) notifySendRequest {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.sends) == 0 {
		t.Fatal("the rail received no send")
	}
	return r.sends[len(r.sends)-1]
}

// With a healthy, credentialed rail the method is real: auth/methods advertises
// it and the endpoint delivers.
func TestCodeDelivery_RailUpAdvertisesAndSends(t *testing.T) {
	r := newRail(t)
	useRail(t, r)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")
	enableCodeSignin(t, db, "conf")

	if code := authMethodsFor(t, app, "conf")["code"]; code != true {
		t.Fatalf("code = %v, want true with the rail up", code)
	}

	status, env := sendCode(t, app, map[string]string{
		"dest": "z@hanzo.ai", "type": "email", "applicationId": "admin/conf",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("status=%d env=%v, want 200 ok", status, env)
	}

	// iam2 spoke the rail's documented OTP contract.
	sent := r.lastSend(t)
	if len(sent.To) != 1 || sent.To[0] != "z@hanzo.ai" {
		t.Errorf("to = %v, want [z@hanzo.ai]", sent.To)
	}
	if sent.Channel != "email" {
		t.Errorf("channel = %q, want email", sent.Channel)
	}
	if sent.Event != otpEvent {
		t.Errorf("event = %q, want %q", sent.Event, otpEvent)
	}
	if len(sent.TemplateVars["otp"]) != verificationCodeLength {
		t.Errorf("template_vars.otp = %q, want %d digits", sent.TemplateVars["otp"], verificationCodeLength)
	}
	if sent.TemplateVars["recipient"] != "z@hanzo.ai" || sent.TemplateVars["app"] != "conf" {
		t.Errorf("template_vars = %v, want recipient+app carried", sent.TemplateVars)
	}
	if sent.IdempotencyKey == "" {
		t.Error("no idempotency key — a retry would send a second code")
	}
	// SYNC is mandatory: an async 202 would let iam2 claim success on a queue
	// insertion, which is the whole defect being fixed.
	r.mu.Lock()
	sync, auth := r.syncSeen[len(r.syncSeen)-1], r.auth[len(r.auth)-1]
	r.mu.Unlock()
	if sync != "true" {
		t.Errorf("sync = %q, want true", sync)
	}
	if auth != "Bearer svc-token-do-not-log" {
		t.Error("the send did not present the service credential")
	}

	// The code the user was sent is the code that verifies.
	rec, err := storeLatest(t, db, "z@hanzo.ai")
	if err != nil || rec == nil {
		t.Fatalf("a delivered code must be persisted: %v", err)
	}
	if rec.Code != sent.TemplateVars["otp"] {
		t.Fatal("the persisted code is not the code that was sent")
	}
}

// The rail is down: the method disappears from auth/methods AND the endpoint
// refuses. One authority, both ends, no window where the page offers what the
// endpoint would decline.
func TestCodeDelivery_RailDownWithdrawsAndRefuses(t *testing.T) {
	r := newRail(t)
	r.healthy = false
	useRail(t, r)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")
	enableCodeSignin(t, db, "conf")

	if code := authMethodsFor(t, app, "conf")["code"]; code != false {
		t.Fatalf("code = %v, want false with the rail down", code)
	}
	status, env := sendCode(t, app, map[string]string{
		"dest": "z@hanzo.ai", "type": "email", "applicationId": "admin/conf",
	})
	if status != 200 || env["status"] != "error" {
		t.Fatalf("status=%d env=%v, want 200 error", status, env)
	}
	if rec, _ := storeLatest(t, db, "z@hanzo.ai"); rec != nil {
		t.Fatal("nothing may be persisted when nothing was delivered")
	}
}

// No service credential is the same class of fact as no rail: the method is not
// available, and it is withheld rather than offered and then refused.
func TestCodeDelivery_NoServiceCredentialWithholds(t *testing.T) {
	r := newRail(t)
	t.Setenv("NOTIFY_ENDPOINT", r.URL)
	t.Setenv("HANZO_API_KEY", "")
	t.Setenv("KMS_SERVICE_TOKEN", "")
	t.Setenv("IAM_SERVICE_TOKEN", "")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")
	enableCodeSignin(t, db, "conf")

	if code := authMethodsFor(t, app, "conf")["code"]; code != false {
		t.Fatalf("code = %v, want false without a service credential", code)
	}
	if _, err := codeDelivery(); err == nil {
		t.Fatal("codeDelivery must fail closed with no credential")
	}
}

// The rail accepted the request but reported a non-terminal-success status. That
// is a delivery FAILURE: iam2 must not persist a code the user never got.
func TestCodeDelivery_QueuedIsNotDelivered(t *testing.T) {
	r := newRail(t)
	r.status = "queued"
	useRail(t, r)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")

	status, env := sendCode(t, app, map[string]string{
		"dest": "z@hanzo.ai", "type": "email", "applicationId": "admin/conf",
	})
	if status != 200 || env["status"] != "error" {
		t.Fatalf("status=%d env=%v, want 200 error on a non-sent status", status, env)
	}
	if rec, _ := storeLatest(t, db, "z@hanzo.ai"); rec != nil {
		t.Fatal("a queued send is not a delivered code — nothing may be persisted")
	}
}

// "delivered" is the rail's other success terminal and must be accepted.
func TestCodeDelivery_DeliveredIsSuccess(t *testing.T) {
	r := newRail(t)
	r.status = "delivered"
	useRail(t, r)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")

	if status, env := sendCode(t, app, map[string]string{
		"dest": "z@hanzo.ai", "type": "email", "applicationId": "admin/conf",
	}); status != 200 || env["status"] != "ok" {
		t.Fatalf("status=%d env=%v, want 200 ok", status, env)
	}
}

// A phone destination rides the sms channel — the type→channel mapping is the
// only thing that differs between the two OTP flavours.
func TestCodeDelivery_PhoneUsesSMSChannel(t *testing.T) {
	r := newRail(t)
	useRail(t, r)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")

	if status, env := sendCode(t, app, map[string]string{
		"dest": "+15550100", "type": "phone", "applicationId": "admin/conf",
	}); status != 200 || env["status"] != "ok" {
		t.Fatalf("status=%d env=%v, want 200 ok", status, env)
	}
	if ch := r.lastSend(t).Channel; ch != "sms" {
		t.Errorf("channel = %q, want sms", ch)
	}
}

// A rail that errors the send is a delivery failure, and the upstream detail
// never reaches the public caller.
func TestCodeDelivery_RailErrorIsNotLeaked(t *testing.T) {
	r := newRail(t)
	useRail(t, r)
	r.Config.Handler.(*http.ServeMux).HandleFunc("/boom", func(http.ResponseWriter, *http.Request) {})
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")
	r.mu.Lock()
	r.status = "failed"
	r.mu.Unlock()

	_, env := sendCode(t, app, map[string]string{
		"dest": "z@hanzo.ai", "type": "email", "applicationId": "admin/conf",
	})
	msg, _ := env["msg"].(string)
	if env["status"] != "error" {
		t.Fatalf("env=%v, want an error", env)
	}
	for _, leak := range []string{"svc-token-do-not-log", r.URL} {
		if msg != "" && strings.Contains(msg, leak) {
			t.Errorf("the client-visible message leaked %q: %q", leak, msg)
		}
	}
}

// storeLatest reads the most recent verification record for a receiver.
func storeLatest(t *testing.T, db orm.DB, receiver string) (*schema.VerificationRecord, error) {
	t.Helper()
	return store.GetLatestVerificationRecord(context.Background(), db, receiver)
}
