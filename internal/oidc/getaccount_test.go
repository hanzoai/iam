// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package oidc

import (
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// getAccountReq drives GET the account endpoint with an optional bearer,
// returning the status code and decoded envelope.
func getAccountReq(t *testing.T, app *zip.App, bearer string) (int, map[string]any) {
	t.Helper()
	req := formReqNoBody("GET", PathAccount)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, body := do(t, app, req)
	return resp.StatusCode, decode(t, body)
}

// The bearer path resolves the caller and returns a REDACTED account whose
// `owner` (the admin-guard's SuperAdmin input) is correct and whose secrets are
// stripped — the security contract, end to end through the real router.
func TestGetAccount_BearerReturnsRedactedAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	access := accessTokenFor(t, app, "openid profile email")
	status, env := getAccountReq(t, app, access)
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("status=%d env=%v, want 200 ok", status, env)
	}
	if env["sub"] != "hanzo/alice" || env["name"] != "alice" {
		t.Errorf("sub/name = %v/%v, want hanzo/alice / alice", env["sub"], env["name"])
	}
	data, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("data is not an object: %v", env["data"])
	}
	// The admin-guard reads data.owner — it MUST be present and correct.
	if data["owner"] != "hanzo" {
		t.Errorf("data.owner = %v, want hanzo (the admin-guard SuperAdmin input)", data["owner"])
	}
	// Every secret MUST be stripped — a leak here hands out password hashes.
	for _, secret := range []string{"passwordHash", "passwordSalt", "accessSecret", "accessSecretHash", "totpSecret", "accessToken"} {
		if v, present := data[secret]; present && v != "" {
			t.Errorf("get-account leaked %q = %v", secret, v)
		}
	}
}

// Anonymous callers get {status:"error"} (200, casibase convention) — never a
// leak and never a 5xx. The admin-guard reads status=="error" → not-admin,
// fail-closed. Same for an invalid bearer.
func TestGetAccount_AnonymousIsErrorNotLeak(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	for name, bearer := range map[string]string{"no bearer": "", "garbage bearer": "not-a-real-token"} {
		t.Run(name, func(t *testing.T) {
			status, env := getAccountReq(t, app, bearer)
			if status != 200 || env["status"] != "error" {
				t.Fatalf("status=%d env=%v, want 200 error", status, env)
			}
			if _, leaked := env["data"]; leaked {
				t.Errorf("anonymous get-account must carry no data, got %v", env["data"])
			}
		})
	}
}

// Redact keeps the admin-guard fields (owner, isAdmin) while stripping every
// secret — the invariant get-account relies on. Unit-level, no db/login flow.
func TestUserMask_KeepsAdminFieldsStripsSecrets(t *testing.T) {
	u := &schema.User{
		Owner:        "admin",
		Name:         "root",
		IsAdmin:      true,
		PasswordHash: "$argon2id$v=19$…",
		PasswordSalt: "salt",
		AccessSecret: "sk_live_abc",
		TotpSecret:   "JBSWY3DPEHPK3PXP",
	}
	got := u.Mask()
	if got.Owner != "admin" || !got.IsAdmin {
		t.Errorf("Mask dropped an admin-guard field: owner=%q isAdmin=%v", got.Owner, got.IsAdmin)
	}
	if got.PasswordHash != "" || got.PasswordSalt != "" || got.AccessSecret != "" || got.TotpSecret != "" {
		t.Errorf("Mask left a secret: %+v", got)
	}
	// Mask returns a COPY — the login-verify path must still see the live hash on
	// the original row, so masking a response can never blank it.
	if u.PasswordHash == "" {
		t.Errorf("Mask must NOT mutate the receiver, but the original's PasswordHash was cleared")
	}
}
