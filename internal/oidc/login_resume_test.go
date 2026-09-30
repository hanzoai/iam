// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/store"
)

// A code minted from a session alone is S256-bound, carries the session's sign-in
// time, and on an application's own host is minted only for the application the
// session was opened under. The identity provider's host keeps single sign-on.
func TestLogin_ResumeMintsOnlyAProvenCodeForTheSessionsApplication(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedApp(t, db, appOpts{clientID: "second", redirectURIs: []string{secondRedirect}})
	seedRichUser(t, db)

	cert, err := store.PlatformSigningCert(tctx(), db)
	if err != nil || cert == nil {
		t.Fatalf("cert: %v", err)
	}
	key := sessions.SessionKey(cert.PrivateKey)
	sc, err := sessions.Verify(strings.Split(strings.TrimPrefix(signIn(t, app, "conf"), sessions.CookieName+"="), "~")[0], key)
	if err != nil {
		t.Fatal(err)
	}
	signedAt := time.Now().Add(-2 * time.Hour).Unix()
	sc.AuthTime = signedAt
	cookie := sessions.CookieName + "=" + sessions.Issue(*sc, key, time.Hour)

	const v = "verifier-login-resume-0123456789012345678901234567"
	resume := func(host, client, redirect, challenge, method string) map[string]any {
		q := "?clientId=" + client + "&responseType=code&redirectUri=" + redirect + "&scope=openid&type=code"
		if challenge != "" {
			q += "&code_challenge=" + challenge + "&code_challenge_method=" + method
		}
		req := jsonReq("POST", PathLogin+q, map[string]any{"type": "code", "application": client})
		req.Host = host
		req.Header.Set("Cookie", cookie)
		_, body := do(t, app, req)
		return decode(t, body)
	}

	if env := resume("hanzo.id", "conf", testRedirect, "", ""); env["status"] != "error" {
		t.Errorf("a session minted a code with no PKCE challenge: %v", env)
	}
	if env := resume("hanzo.id", "conf", testRedirect, v, "plain"); env["status"] != "error" {
		t.Errorf("a session minted a code under a plain challenge: %v", env)
	}
	if env := resume("app.example", "second", secondRedirect, pkce.Challenge(v), "S256"); env["status"] != "error" {
		t.Errorf("on an application's host a session minted a code for another application: %v", env)
	}
	if env := resume("hanzo.id", "second", secondRedirect, pkce.Challenge(v), "S256"); env["status"] != "ok" {
		t.Errorf("single sign-on on the identity provider's host was refused: %v", env)
	}
	env := resume("app.example", "conf", testRedirect, pkce.Challenge(v), "S256")
	code, _ := env["data"].(string)
	if env["status"] != "ok" || code == "" {
		t.Fatalf("the session's own application was refused on its host: %v", env)
	}
	tok, err := store.GetTokenByCode(tctx(), db, code)
	if err != nil || tok == nil {
		t.Fatalf("minted code not stored: %v", err)
	}
	if tok.AuthTime != signedAt {
		t.Fatalf("a code from a session two hours old claims sign-in at %d, want %d", tok.AuthTime, signedAt)
	}
}
