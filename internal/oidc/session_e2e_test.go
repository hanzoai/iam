// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package oidc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/sessions"
)

// The full portal session path: a bare (type=login) sign-in sets the session
// cookie, and get-account resolves the caller FROM that cookie (no bearer). This
// is the path the hanzo.id portal + the gateway admin-guard use.
func TestSession_LoginCookieResolvesGetAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db) // hanzo/alice, password "pw"

	// 1) Bare portal login → sets the hanzo_session cookie.
	form := url.Values{
		"organization": {"hanzo"},
		"application":  {"conf"},
		"username":     {"alice"},
		"password":     {"pw"},
		"type":         {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("login status=%d body=%s", resp.StatusCode, body)
	}
	cookie := resp.Header.Get("Set-Cookie")
	if !strings.HasPrefix(cookie, sessions.CookieName+"=") {
		t.Fatalf("login did not set the session cookie: %q", cookie)
	}
	for _, want := range []string{"HttpOnly", "secure", "SameSite=Lax", "path=/"} {
		if !strings.Contains(cookie, want) {
			t.Errorf("session cookie missing %s: %q", want, cookie)
		}
	}

	// 2) get-account WITH the cookie (no bearer) → resolves alice, redacted.
	req := formReqNoBody("GET", PathAccount)
	req.Header.Set("Cookie", cookieKV(cookie))
	resp2, body2 := do(t, app, req)
	env := decode(t, body2)
	if resp2.StatusCode != 200 || env["status"] != "ok" {
		t.Fatalf("get-account via cookie status=%d body=%s", resp2.StatusCode, body2)
	}
	data, _ := env["data"].(map[string]any)
	if data["owner"] != "hanzo" || env["name"] != "alice" {
		t.Fatalf("cookie session resolved wrong principal: owner=%v name=%v", data["owner"], env["name"])
	}
	if v, ok := data["passwordHash"]; ok && v != "" {
		t.Errorf("cookie get-account leaked passwordHash")
	}
}

// A FORGED session cookie (attacker flips owner→admin) does not authenticate:
// the signature fails, get-account stays anonymous. The whole security point.
func TestSession_ForgedCookieRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	// A hand-built cookie with a bogus payload + mac — no valid signature exists
	// without the platform cert key.
	req := formReqNoBody("GET", PathAccount)
	req.Header.Set("Cookie", sessions.CookieName+"=eyJvIjoiYWRtaW4ifQ.deadbeef")
	resp, body := do(t, app, req)
	if resp.StatusCode != 200 || decode(t, body)["status"] != "error" {
		t.Fatalf("forged cookie must not authenticate: status=%d body=%s", resp.StatusCode, body)
	}
}

// cookieKV extracts "name=value" from a Set-Cookie header for the request echo.
func cookieKV(setCookie string) string {
	if i := strings.Index(setCookie, ";"); i >= 0 {
		return setCookie[:i]
	}
	return setCookie
}

var _ = http.MethodGet
