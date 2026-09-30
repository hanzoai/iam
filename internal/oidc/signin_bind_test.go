// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/store"
)

// A portal session is minted only from a code the platform's own application
// requested, redeemed with that request's PKCE verifier, and it keeps the moment
// the person signed in: a session two hours old cannot come back through signin
// as a fresh one and pass the ten-minute step-up.
func TestSignin_keepsTheSignInTimeAndTakesOnlyThePortalsProvenCode(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "portal", secret: "s3cret", redirectURIs: []string{testRedirect}, platform: true})
	seedApp(t, db, appOpts{clientID: "second", redirectURIs: []string{secondRedirect}})
	seedRichUser(t, db)
	fresh := signIn(t, app, "portal")

	cert, err := store.PlatformSigningCert(tctx(), db)
	if err != nil || cert == nil {
		t.Fatalf("cert: %v", err)
	}
	key := sessions.SessionKey(cert.PrivateKey)
	sc, err := sessions.Verify(strings.Split(strings.TrimPrefix(fresh, sessions.CookieName+"="), "~")[0], key)
	if err != nil {
		t.Fatal(err)
	}
	signedAt := time.Now().Add(-2 * time.Hour).Unix()
	sc.AuthTime = signedAt
	stale := sessions.CookieName + "=" + sessions.Issue(*sc, key, time.Hour)

	silent := func(cookie, client, redirect, verifier string) string {
		q := url.Values{
			"client_id": {client}, "redirect_uri": {redirect}, "response_type": {"code"},
			"scope": {"openid"}, "state": {"s"}, "prompt": {"none"},
			"code_challenge": {pkce.Challenge(verifier)}, "code_challenge_method": {"S256"},
		}
		return codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), redirect))
	}
	signin := func(code, verifier string) (int, string, string) {
		path := PathSignin + "?code=" + url.QueryEscape(code)
		if verifier != "" {
			path += "&code_verifier=" + url.QueryEscape(verifier)
		}
		resp, body := do(t, app, formReqNoBody("POST", path))
		return resp.StatusCode, string(body), cookieKV(resp.Header.Get("Set-Cookie"))
	}

	const v = "verifier-signin-bind-0123456789012345678901234567890"
	if _, body, _ := signin(silent(stale, "second", secondRedirect, v), v); !strings.Contains(body, `"status":"error"`) {
		t.Errorf("a code issued to a tenant's application minted a portal session: %s", body)
	}
	if _, body, _ := signin(silent(stale, "portal", testRedirect, v), ""); !strings.Contains(body, `"status":"error"`) {
		t.Errorf("a portal code without its PKCE verifier minted a session: %s", body)
	}
	if _, body, _ := signin(silent(stale, "portal", testRedirect, v), "verifier-of-somebody-else-0123456789012345678901"); !strings.Contains(body, `"status":"error"`) {
		t.Errorf("a portal code with another verifier minted a session: %s", body)
	}
	_, body, laundered := signin(silent(stale, "portal", testRedirect, v), v)
	if !strings.HasPrefix(laundered, sessions.CookieName+"=") {
		t.Fatalf("the portal's own proven code was refused: %s", body)
	}
	got, err := sessions.Verify(strings.Split(strings.TrimPrefix(laundered, sessions.CookieName+"="), "~")[0], key)
	if err != nil {
		t.Fatal(err)
	}
	if got.AuthTime != signedAt {
		t.Fatalf("signin minted a session signed in at %d, want the code's %d", got.AuthTime, signedAt)
	}

	// A code with no sign-in recorded mints nothing.
	code := silent(fresh, "portal", testRedirect, v)
	row, _ := store.GetTokenByCode(tctx(), db, code)
	row.AuthTime = 0
	if err := store.SaveToken(tctx(), db, row); err != nil {
		t.Fatal(err)
	}
	if _, body, _ := signin(code, v); !strings.Contains(body, `"status":"error"`) {
		t.Errorf("a code recording no sign-in minted a session: %s", body)
	}
}
