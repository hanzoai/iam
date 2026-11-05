// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/store"
)

// SINGLE SIGN-ON off a live IAM session. A signed-in person asking for a grant to
// the next app must get an authorization code without re-typing their password —
// and must get exactly the grant a password post would have got, no wider.

// A live session mints the code — no credential, no login wall.
func TestLogin_SessionMintsCodeForTheNextApp(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")

	cookie := portalSession(t, app, "hanzo", "alice")

	req := fromPage(jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri="+testRedirect+
		"&scope=openid+profile+email&type=code", map[string]any{
		"type": "code", "application": "conf", "autoSignin": true,
	}))
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	env := decode(t, body)
	if resp.StatusCode != 200 || env["status"] != "ok" {
		t.Fatalf("silent SSO refused a live session: status=%d body=%s", resp.StatusCode, body)
	}
	code, _ := env["data"].(string)
	if code == "" {
		t.Fatalf("no authorization code minted: %s", body)
	}
	// The code is a real, redeemable grant for the signed-in user.
	tok, err := store.GetTokenByCode(context.Background(), db, code)
	if err != nil || tok == nil {
		t.Fatalf("minted code is not persisted: %v", err)
	}
	if tok.User != "hanzo/alice" {
		t.Errorf("code bound to %q, want hanzo/alice", tok.User)
	}
	if tok.RedirectUri != testRedirect {
		t.Errorf("code redirect_uri = %q, want %q", tok.RedirectUri, testRedirect)
	}
}

// No session, no code: an anonymous credential-less post is still refused.
func TestLogin_NoSessionStillNeedsACredential(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")

	req := fromPage(jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri="+testRedirect+"&type=code",
		map[string]any{"type": "code", "application": "conf"}))
	_, body := do(t, app, req)
	if decode(t, body)["status"] != "error" {
		t.Fatalf("credential-less login with NO session was granted: %s", body)
	}
}

// The session is a proof of identity, not a widening of scope: every gate the
// password path applies still applies. An unregistered redirect_uri is refused.
func TestLogin_SessionGrantKeepsTheRedirectBinding(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")
	cookie := portalSession(t, app, "hanzo", "alice")

	req := fromPage(jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri=https://evil.example/steal&type=code",
		map[string]any{"type": "code", "application": "conf"}))
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if decode(t, body)["status"] != "error" {
		t.Fatalf("session SSO minted a code for an UNREGISTERED redirect_uri: %s", body)
	}
}

// A revoked identity cannot ride its old session into a new grant.
func TestLogin_ForbiddenUserCannotSsoOnAnOldSession(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")
	cookie := portalSession(t, app, "hanzo", "alice")

	u, err := store.GetUserByName(ctx, db, "hanzo", "alice")
	if err != nil || u == nil {
		t.Fatalf("load alice: %v", err)
	}
	u.IsForbidden = true
	if err := u.UpdateCtx(ctx); err != nil {
		t.Fatalf("forbid alice: %v", err)
	}

	req := fromPage(jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri="+testRedirect+"&type=code",
		map[string]any{"type": "code", "application": "conf"}))
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if decode(t, body)["status"] != "error" {
		t.Fatalf("a forbidden user rode an old session into a fresh grant: %s", body)
	}
}

// Signing into the admin console after signing into hanzo.ai puts admin/<user>
// at the front of the multi-account session cookie: [admin/alice, hanzo/alice].
// A subsequent SSO request for a hanzo-org app (via POST /v1/iam/login or
// GET /v1/iam/oauth/authorize) must pick the hanzo/alice session rather than
// failing because list[0] is in a reserved org.
func TestLogin_MultiAccountCookiePicksSessionServingTheApp(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	console := seedApp(t, db, appOpts{clientID: "console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	console.Organization = "admin"
	if err := console.Update(); err != nil {
		t.Fatalf("retarget console: %v", err)
	}
	seedFounder(t, db, "hanzo", "alice")
	seedUserInOrg(t, db, "admin", "alice", "alice@hanzo.ai", "pw")

	// 1. Sign in as hanzo/alice, then as admin/alice on the same browser cookie.
	cookie := portalSession(t, app, "hanzo", "alice")
	adminLogin := jsonReq("POST", PathLogin, map[string]any{
		"organization": "admin", "application": "console", "username": "alice", "password": "pw", "autoSignin": true,
	})
	adminLogin.Header.Set("Cookie", cookie)
	resp, body := do(t, app, adminLogin)
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("admin login failed: status=%d body=%s", resp.StatusCode, body)
	}
	bothCookie := cookieKV(resp.Header.Get("Set-Cookie"))

	// 2. Credential-less POST /v1/iam/login (iam.resume) for the hanzo app mints for hanzo/alice.
	req := jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri="+testRedirect+
		"&scope=openid+profile+email&type=code", map[string]any{
		"type": "code", "application": "conf", "autoSignin": true,
	})
	req.Header.Set("Cookie", bothCookie)
	resp, body = do(t, app, req)
	env := decode(t, body)
	if resp.StatusCode != 200 || env["status"] != "ok" {
		t.Fatalf("multi-account silent SSO failed on POST /v1/iam/login: status=%d body=%s", resp.StatusCode, body)
	}
	code, _ := env["data"].(string)
	tok, err := store.GetTokenByCode(ctx, db, code)
	if err != nil || tok == nil || tok.User != "hanzo/alice" {
		t.Fatalf("minted code user = %v (err=%v), want hanzo/alice", tok, err)
	}

	// 3. GET /v1/iam/oauth/authorize with prompt=none also mints for hanzo/alice.
	verifier := "verifier-multi-account-sso-01234567890123456789012345"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"conf"},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid"},
		"state":                 {"st-multi"},
		"prompt":                {"none"},
		"code_challenge":        {pkce.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	loc := requireRedirect(t, authorizeWith(t, app, q, bothCookie, nil), testRedirect)
	u, _ := url.Parse(loc)
	if u.Query().Get("code") == "" {
		t.Fatalf("authorize prompt=none did not mint a code with [admin/alice, hanzo/alice]: %q", loc)
	}
}
