// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zap-proto/zip"
)

// A credential travels in the body and only in the body.
//
// zip binds a typed op's scalar fields from the query string on EVERY method, and
// the query is bound after the body, so a scalar with no `url:"-"` is not merely
// also-settable from the URL — it OVERRIDES what the body said. On this endpoint
// that reaches the three fields that decide a password write, and a URL is the one
// part of a request that gets written down: proxy logs, access logs, browser
// history, the Referer of whatever the response links to.
//
// PUT /v1/iam/password is public on its code arm, which is what makes it first.

// putPasswordTo is putPassword with the target spelled out, so a test can put a
// query string on the URL.
func putPasswordTo(t *testing.T, app *zip.App, target, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("PUT", target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "hanzo.id"
	resp, raw := do(t, app, req)
	return resp.StatusCode, decode(t, raw)
}

// A reset stated ENTIRELY in the query string sets nothing. The refusal is the
// empty-password one, which is the observable proof that `password` never
// arrived — the arm check that follows it would have answered differently.
func TestPasswordIgnoresACredentialInTheQuery(t *testing.T) {
	app, db := recoveryServer(t)
	code := deliveredCode(t, app, db, "alice@hanzo.ai", "email")

	target := fmt.Sprintf("%s?organization=hanzo&username=%s&code=%s&password=%s",
		PathPassword, "alice%40hanzo.ai", code, "chosen+by+a+stranger")
	status, env := putPasswordTo(t, app, target, `{}`)
	if status != 400 {
		t.Fatalf("a query-only reset was not refused: status=%d env=%v", status, env)
	}
	if msg, _ := env["msg"].(string); msg != "password cannot be empty" {
		t.Fatalf("the new password bound from the query: msg=%q", msg)
	}

	if ok, _ := signInWith(t, app, "chosen by a stranger"); ok {
		t.Error("a password stated in the query string signs in")
	}
	if ok, msg := signInWith(t, app, "old correct horse"); !ok {
		t.Fatalf("the real password stopped working: %q", msg)
	}
}

// The body is not merely a second source — it is the ONLY one. A legitimate reset
// carrying a stranger's password in the query writes the password the BODY chose,
// because the query binds after the body and would otherwise win.
func TestPasswordBodyOutranksTheQuery(t *testing.T) {
	app, db := recoveryServer(t)
	code := deliveredCode(t, app, db, "alice@hanzo.ai", "email")

	target := PathPassword + "?password=chosen+by+a+stranger&code=000000&oldPassword=guessed"
	body := fmt.Sprintf(`{"organization":"hanzo","username":"alice@hanzo.ai","code":%q,"password":%q}`,
		code, "chosen by alice")
	status, env := putPasswordTo(t, app, target, body)
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("the reset was refused: status=%d env=%v", status, env)
	}

	if ok, msg := signInWith(t, app, "chosen by alice"); !ok {
		t.Fatalf("the password the body chose was not written: %q", msg)
	}
	if ok, _ := signInWith(t, app, "chosen by a stranger"); ok {
		t.Error("the password the query string carried was written instead")
	}
}
