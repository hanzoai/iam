// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// multipartReq builds a real multipart/form-data POST — the wire format v1's
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
	resp, raw := do(t, app, multipartReq(PathSendVerificationCode, fields))
	return resp.StatusCode, decode(t, raw)
}

// A well-formed request reaches the delivery step and is REFUSED there, because
// codeDelivery reports no transport — and, decisively, persists NOTHING. A code
// that never left the building is not a credential anyone can redeem, and this
// route is public: were it stored anyway, any anonymous caller could grow the
// identity store one dead code at a time.
func TestSendVerificationCode_RefusedAndStoresNothingWithoutDelivery(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")
	seedRichUser(t, db) // alice@hanzo.ai — the request clears every validation gate

	status, env := sendCode(t, app, map[string]string{
		"dest":          "alice@hanzo.ai",
		"type":          "email",
		"applicationId": "admin/conf",
		"captchaType":   "none",
	})
	if status != 200 || env["status"] != "error" {
		t.Fatalf("status=%d env=%v, want 200 error while delivery is unwired", status, env)
	}
	if msg, _ := env["msg"].(string); msg != codeDelivery().Error() {
		t.Errorf("msg = %q, want the codeDelivery reason %q", msg, codeDelivery().Error())
	}
	if rec, _ := store.GetLatestVerificationRecord(context.Background(), db, "alice@hanzo.ai"); rec != nil {
		t.Fatal("an undelivered code must never be persisted")
	}
}

// A urlencoded body reaches the same handler (fiber's FormValue reads both) —
// the request contract is not multipart-only, and it refuses identically.
func TestSendVerificationCode_UrlencodedReachesTheSameHandler(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})
	seedOrg(t, db, "hanzo")

	resp, raw := do(t, app, formReq("POST", PathSendVerificationCode, url.Values{
		"dest":          {"someone@hanzo.ai"},
		"type":          {"email"},
		"applicationId": {"admin/conf"},
	}))
	env := decode(t, raw)
	if resp.StatusCode != 200 || env["status"] != "error" {
		t.Fatalf("status=%d env=%v, want 200 error", resp.StatusCode, env)
	}
	// It reached DELIVERY, not a parse failure — proving the urlencoded body was
	// read: a body the handler could not parse would have failed on "missing
	// parameter: type" long before.
	if msg, _ := env["msg"].(string); msg != codeDelivery().Error() {
		t.Errorf("msg = %q, want the codeDelivery reason (the urlencoded form did not parse)", msg)
	}
}

// The mint + redeem machinery the endpoint gates: a persisted code verifies in
// constant time, and every near miss fails closed. Driven directly, because the
// endpoint stops short of persisting while there is no transport — testing it
// through a door that is shut would assert nothing.
func TestCheckVerificationCode(t *testing.T) {
	_, db := newServer(t)
	ctx := context.Background()

	code, err := generateCode(verificationCodeLength)
	if err != nil || len(code) != verificationCodeLength {
		t.Fatalf("generateCode = %q, %v; want %d digits", code, err, verificationCodeLength)
	}
	rec := &schema.VerificationRecord{
		Owner: "hanzo", Name: "rec-1", Type: "email",
		Receiver: "alice@hanzo.ai", Code: code, Time: nowFunc().Unix(),
	}
	if err := store.AddVerificationRecord(ctx, db, rec); err != nil {
		t.Fatalf("persist record: %v", err)
	}

	if ok, err := CheckVerificationCode(ctx, db, "alice@hanzo.ai", code); err != nil || !ok {
		t.Fatalf("the correct code must verify: ok=%v err=%v", ok, err)
	}
	for name, tc := range map[string]struct{ receiver, code string }{
		"wrong code":     {"alice@hanzo.ai", "000000"},
		"other receiver": {"nobody@hanzo.ai", code},
		"empty code":     {"alice@hanzo.ai", ""},
		"empty receiver": {"", code},
	} {
		if ok, _ := CheckVerificationCode(ctx, db, tc.receiver, tc.code); ok {
			t.Errorf("%s must not verify", name)
		}
	}

	// Past the TTL the record is no longer redeemable, without being consumed.
	nowFuncSet(t, time.Now().Add(verificationCodeTTL+time.Second))
	if ok, _ := CheckVerificationCode(ctx, db, "alice@hanzo.ai", code); ok {
		t.Error("an expired code must not verify")
	}
}

// Every malformed request returns {status:"error"} on a 200 and persists nothing.
// Each case must be refused by its OWN validation gate and never reach delivery,
// so this stays a test of the request contract rather than of the shut door: the
// assertion is that the message is anything BUT the codeDelivery reason.
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
			if status != 200 || env["status"] != "error" {
				t.Fatalf("status=%d env=%v, want 200 error", status, env)
			}
			if msg, _ := env["msg"].(string); msg == codeDelivery().Error() {
				t.Errorf("reached delivery; %s must be refused by its own validation gate", name)
			}
		})
	}
}
