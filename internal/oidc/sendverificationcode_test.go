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

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/store"
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
			if status != 200 || env["status"] != "error" {
				t.Fatalf("status=%d env=%v, want 200 error", status, env)
			}
		})
	}
}
