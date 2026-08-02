// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

// A browser client cannot hold a client secret, and the apps it signs into are
// registered WITH one for their backend paths (chat's passport OpenID, cloud's
// client_credentials machine auth). Requiring the secret at the authorization_code
// grant therefore broke every @hanzo/iam SPA login with `401 invalid_client` —
// signed in at hanzo.id, back at /auth/callback, no session. The code's PKCE
// binding authenticates the browser instead. These tests fix that contract from
// both sides: the browser exchange succeeds, and nothing else is loosened.

import (
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/pkce"
)

const browserVerifier = "browser-client-verifier-000000000000000000000000"

// The live shape: an app registered with a secret, a code minted with PKCE, and a
// token request that carries the verifier but no secret.
func TestBrowserClient_PKCECodeNeedsNoSecret(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-chat", secret: "backend-secret", redirectURIs: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "hanzo-chat", "redirectUri": testRedirect, "scope": "openid",
		"codeChallenge": pkce.Challenge(browserVerifier), "codeChallengeMethod": "S256",
	})
	if code == "" {
		t.Fatal("setup: no authorization code minted")
	}

	resp, m := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"hanzo-chat"},
		"code_verifier": {browserVerifier}, "redirect_uri": {testRedirect},
	})
	if resp.StatusCode != 200 || m["access_token"] == nil {
		t.Fatalf("browser PKCE exchange got %d %v, want 200 with a token", resp.StatusCode, m)
	}
}

// A WRONG secret is still a wrong secret, PKCE or not — presenting one means you
// claim to be the confidential client.
func TestBrowserClient_WrongSecretStillFails(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-chat", secret: "backend-secret", redirectURIs: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "hanzo-chat", "redirectUri": testRedirect, "scope": "openid",
		"codeChallenge": pkce.Challenge(browserVerifier), "codeChallengeMethod": "S256",
	})

	resp, m := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"hanzo-chat"}, "client_secret": {"wrong"},
		"code_verifier": {browserVerifier}, "redirect_uri": {testRedirect},
	})
	if resp.StatusCode != 401 || m["error"] != "invalid_client" {
		t.Fatalf("wrong secret got %d %v, want 401 invalid_client", resp.StatusCode, m)
	}
}

// No PKCE and no secret stays refused: the relaxation is PKCE-bound, so client
// authentication cannot be skipped by simply omitting the challenge.
func TestBrowserClient_NoPKCENoSecretStillFails(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-chat", secret: "backend-secret", redirectURIs: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "hanzo-chat", "redirectUri": testRedirect, "scope": "openid",
	})
	if code == "" {
		t.Fatal("setup: no authorization code minted")
	}

	resp, m := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"hanzo-chat"}, "redirect_uri": {testRedirect},
	})
	if resp.StatusCode != 401 || m["error"] != "invalid_client" {
		t.Fatalf("no PKCE, no secret got %d %v, want 401 invalid_client", resp.StatusCode, m)
	}
}

// The confidential path is untouched: secret + code, no PKCE, still mints.
func TestBrowserClient_ConfidentialExchangeUnchanged(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-chat", secret: "backend-secret", redirectURIs: []string{testRedirect}})
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")

	code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "hanzo-chat", "redirectUri": testRedirect, "scope": "openid",
	})

	resp, m := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"hanzo-chat"}, "client_secret": {"backend-secret"},
		"redirect_uri": {testRedirect},
	})
	if resp.StatusCode != 200 || m["access_token"] == nil {
		t.Fatalf("confidential exchange got %d %v, want 200 with a token", resp.StatusCode, m)
	}
}
