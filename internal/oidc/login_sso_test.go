// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package oidc

import (
	"context"
	"testing"

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

	req := jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri="+testRedirect+
		"&scope=openid+profile+email&type=code", map[string]any{
		"type": "code", "application": "conf", "autoSignin": true,
	})
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

	req := jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri="+testRedirect+"&type=code",
		map[string]any{"type": "code", "application": "conf"})
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

	req := jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri=https://evil.example/steal&type=code",
		map[string]any{"type": "code", "application": "conf"})
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

	req := jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri="+testRedirect+"&type=code",
		map[string]any{"type": "code", "application": "conf"})
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if decode(t, body)["status"] != "error" {
		t.Fatalf("a forbidden user rode an old session into a fresh grant: %s", body)
	}
}
