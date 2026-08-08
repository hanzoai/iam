// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/store"
)

// multipartReq builds a real multipart/form-data POST — the serialized format v1's
// SendVerificationCode requires (NOT JSON), so the test exercises the multipart
// parse path, not a urlencoded shortcut.
func multipartReq(path string, fields map[string]string) *http.Request {
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = w.WriteField(k, v)
	}
	_ = w.Close()
	req := httptest.NewRequest("POST", path, &body)
	req.Header.Set("Content-Type", w.FormDataContentType()) // multipart/form-data; boundary=…
	req.Host = "hanzo.id"
	return req
}

func sendCode(t *testing.T, app *zip.App, fields map[string]string) (int, map[string]any) {
	t.Helper()
	resp, raw := do(t, app, multipartReq(PathVerificationCodes, fields))
	return resp.StatusCode, decode(t, raw)
}

// The happy path parses the multipart form, persists a 6-digit unused code
// bound to the receiver, and reports ok — and that code then verifies through
// CheckVerificationCode while a wrong one fails closed.
func TestSendVerificationCode_PersistsAndVerifies(t *testing.T) {
	// A send that reports success must actually be able to send: DeliveryConfigured
	// gates the endpoint, so these persist/verify tests bind a sender the way any
	// real deployment does. Unbound, the endpoint refuses rather than answering ok,
	// which is its own test below.
	bindSender(t, &fakeSender{})
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")
	seedRichUser(t, db) // alice@hanzo.ai — exercises the user-resolution branch

	status, env := sendCode(t, app, map[string]string{
		"dest":          "alice@hanzo.ai",
		"type":          "email",
		"applicationId": "admin/conf",
		"captchaType":   "none",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("status=%d env=%v, want 200 ok", status, env)
	}

	ctx := context.Background()
	rec, err := store.GetLatestVerificationRecord(ctx, db, "alice@hanzo.ai")
	if err != nil || rec == nil {
		t.Fatalf("verification record not persisted: %v (nil=%v)", err, rec == nil)
	}
	if rec.Type != "email" || rec.IsUsed {
		t.Errorf("record type/used = %q/%v, want email/false", rec.Type, rec.IsUsed)
	}
	if len(rec.Code) != verificationCodeLength {
		t.Errorf("code = %q, want %d digits", rec.Code, verificationCodeLength)
	}
	if rec.User != "hanzo/alice" {
		t.Errorf("record.User = %q, want hanzo/alice (resolved from the dest)", rec.User)
	}

	// The validation surface: the persisted code verifies, a wrong one does not.
	if ok, err := CheckVerificationCode(ctx, db, "alice@hanzo.ai", rec.Code); err != nil || !ok {
		t.Fatalf("correct code must verify: ok=%v err=%v", ok, err)
	}
	if ok, _ := CheckVerificationCode(ctx, db, "alice@hanzo.ai", "000000"); ok {
		t.Error("a wrong code must not verify")
	}
	if ok, _ := CheckVerificationCode(ctx, db, "nobody@hanzo.ai", rec.Code); ok {
		t.Error("a code must not verify for a different receiver")
	}
}

// A urlencoded body reaches the same handler (fiber's FormValue reads both) —
// the code path is not multipart-only.
func TestSendVerificationCode_UrlencodedAlsoWorks(t *testing.T) {
	// A send that reports success must actually be able to send: DeliveryConfigured
	// gates the endpoint, so these persist/verify tests bind a sender the way any
	// real deployment does. Unbound, the endpoint refuses rather than answering ok,
	// which is its own test below.
	bindSender(t, &fakeSender{})
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")

	resp, raw := do(t, app, formReq("POST", PathVerificationCodes, url.Values{
		"dest":          {"someone@hanzo.ai"},
		"type":          {"email"},
		"applicationId": {"admin/conf"},
	}))
	if env := decode(t, raw); resp.StatusCode != 200 || env["status"] != "ok" {
		t.Fatalf("status=%d env=%v, want 200 ok", resp.StatusCode, env)
	}
	if rec, _ := store.GetLatestVerificationRecord(context.Background(), db, "someone@hanzo.ai"); rec == nil {
		t.Error("urlencoded send did not persist a record")
	}
}

// Every malformed request returns {status:"error"} on a 200 and persists nothing.
func TestSendVerificationCode_Errors(t *testing.T) {
	base := func() map[string]string {
		return map[string]string{"dest": "x@hanzo.ai", "type": "email", "applicationId": "admin/conf"}
	}
	cases := map[string]func(m map[string]string){
		"missing type":              func(m map[string]string) { delete(m, "type") },
		"missing dest":              func(m map[string]string) { delete(m, "dest") },
		"applicationId without '/'": func(m map[string]string) { m["applicationId"] = "conf" },
		"application not found":     func(m map[string]string) { m["applicationId"] = "admin/ghost" },
		"invalid email":             func(m map[string]string) { m["dest"] = "not-an-email" },
		"unsupported type":          func(m map[string]string) { m["type"] = "carrier-pigeon" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
			seedOrg(t, db, "hanzo")
			m := base()
			mutate(m)
			status, env := sendCode(t, app, m)
			if status != 400 || env["status"] != "error" {
				t.Fatalf("status=%d env=%v, want 400 error", status, env)
			}
		})
	}
}

// With nothing able to deliver, the endpoint says so instead of answering ok.
//
// It used to mint the code, persist it, and return {status:"ok"} — defensible as
// "the code exists", and not what the caller hears: the login screen asked to SEND
// one, so ok means sent, and the person waits for a message nobody sent. Measured
// against production, a send to probe@example.invalid — an address that cannot
// exist — answered ok.
func TestSendVerificationCode_RefusesWhenNothingCanDeliver(t *testing.T) {
	bindSender(t, nil)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")
	seedRichUser(t, db)

	status, env := sendCode(t, app, map[string]string{
		"dest": "alice@hanzo.ai", "type": "email",
		"applicationId": "admin/conf", "checkType": "none", "method": "signup",
	})
	if status != 400 {
		t.Fatalf("transport status = %d, want 400 — a send that cannot happen is a refusal, "+
			"and the transport must say so before the envelope repeats it", status)
	}
	if env["status"] != "error" {
		t.Errorf("status = %v, want error — reporting success for a send that cannot happen "+
			"is what left people waiting on a message nobody sent", env["status"])
	}
	if msg, _ := env["msg"].(string); !strings.Contains(msg, "deliver") {
		t.Errorf("msg = %q, want it to name delivery so the cause is actionable", msg)
	}
}

// A phone code has to survive the person spelling their own number two ways.
//
// The record was written under `dest` exactly as typed and matched back with an
// exact Receiver compare, while the ACCOUNT on the same request resolves through
// GetUserByPhone, which normalizes first. So "+1 415 555 0134" at send and
// "+14155550134" at login found the right user and then answered "the code is
// incorrect or has expired" — a refusal with no honest explanation available to
// the screen, and one nobody would meet until the first customer of the phone arm.
func TestPhoneCodeMatchesHoweverTheNumberWasTyped(t *testing.T) {
	for _, tc := range []struct{ sent, typed string }{
		{"+1 (415) 555-0134", "+14155550134"},
		{"+14155550134", "+1 415 555 0134"},
		{"415-555-0134", "4155550134"},
	} {
		t.Run(tc.sent+" then "+tc.typed, func(t *testing.T) {
			sender := &fakeSender{}
			bindSender(t, sender)
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
			seedOrg(t, db, "hanzo")

			status, env := sendCode(t, app, map[string]string{
				"dest": tc.sent, "type": "phone", "applicationId": "admin/conf",
			})
			if status != 200 || env["status"] != "ok" {
				t.Fatalf("send status=%d env=%v, want 200 ok", status, env)
			}
			if len(sender.sent) != 1 {
				t.Fatalf("sender saw %d deliveries, want 1", len(sender.sent))
			}
			// The message went to ONE canonical spelling, which is also the one the
			// record is keyed on.
			m := sender.sent[0]
			if m.To != store.NormalizePhone(tc.sent) {
				t.Errorf("delivered to %q, want the canonical %q", m.To, store.NormalizePhone(tc.sent))
			}
			code := codeIn(t, m.Body)

			ok, err := ConsumeVerificationCode(context.Background(), db, tc.typed, code)
			if err != nil {
				t.Fatalf("consume: %v", err)
			}
			if !ok {
				t.Errorf("a code sent to %q did not verify when typed as %q", tc.sent, tc.typed)
			}
		})
	}
}

// An address is not a number: NormalizePhone keeps only digits, so canonicalizing
// an email would leave nothing to match on. One function decides which is which,
// so the write and the read cannot disagree about it.
func TestReceiverKeyLeavesAnythingThatIsNotAPhoneAlone(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"alice@hanzo.ai", "alice@hanzo.ai"},
		{"zeekay", "zeekay"},
		{"+1 (415) 555-0134", "+14155550134"},
		{"415-555-0134", "4155550134"},
	} {
		if got := receiverKey(tc.in); got != tc.want {
			t.Errorf("receiverKey(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// codeIn reads the six digits out of a delivered message body, so a test can spend
// the code the person would have typed rather than reaching into the table.
func codeIn(t *testing.T, body string) string {
	t.Helper()
	digits := regexp.MustCompile(`\d{` + fmt.Sprint(verificationCodeLength) + `}`).FindString(body)
	if digits == "" {
		t.Fatalf("no %d-digit code in the delivered body %q", verificationCodeLength, body)
	}
	return digits
}
