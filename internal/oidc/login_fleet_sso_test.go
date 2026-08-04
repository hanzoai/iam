// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package oidc

import (
	"net/url"
	"testing"
)

// ONE SIGN-IN FOR THE WHOLE FLEET.
//
// Signing in through the OAuth code flow — which is how EVERY app on the fleet
// signs a person in — must leave the IdP session behind, so the next app is a
// silent hop instead of a second credential entry.
//
// This is the property that was missing. loginGrant established the session only
// for `type != "code"` (a bare portal sign-in nothing links to), so the one path
// humans actually walk minted a code and left no session. Silent SSO downstream
// (login.go's session branch) was fully built and simply had nothing to read:
// hanzo.id asked for the password again on every app.
//
// The session is the IDENTITY PROVIDER's memory of who signed in. It is not the
// relying party's session, so the grant SHAPE a client asked for (code vs bare
// login) has no business deciding whether the IdP remembers the human.
func TestLogin_CodeFlowLeavesTheIdPSessionForTheNextApp(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "first", secret: "s1", redirectURIs: []string{testRedirect}})
	seedApp(t, db, appOpts{clientID: "second", secret: "s2", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")

	// 1. The ONLY credential entry: a normal OAuth sign-in to the first app.
	form := url.Values{
		"organization": {"hanzo"}, "application": {"first"}, "clientId": {"first"},
		"username": {"alice"}, "password": {"pw"}, "type": {"code"},
		"responseType": {"code"}, "redirectUri": {testRedirect},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("credential sign-in to the first app failed: %s", body)
	}

	cookie := cookieKV(resp.Header.Get("Set-Cookie"))
	if cookie == "" {
		t.Fatalf("the code flow left NO IdP session: every further app must ask for the password again")
	}

	// 2. The payoff: the SECOND app mints a code from that session alone.
	req := jsonReq("POST", PathLogin+"?clientId=second&responseType=code&redirectUri="+testRedirect+
		"&scope=openid+profile+email&type=code", map[string]any{
		"type": "code", "application": "second", "autoSignin": true,
	})
	req.Header.Set("Cookie", cookie)
	resp2, body2 := do(t, app, req)
	env := decode(t, body2)
	if resp2.StatusCode != 200 || env["status"] != "ok" {
		t.Fatalf("second app demanded a fresh credential: %s", body2)
	}
	if code, _ := env["data"].(string); code == "" {
		t.Fatalf("second app minted no authorization code: %s", body2)
	}
}
