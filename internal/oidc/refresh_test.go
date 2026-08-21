// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/zap-proto/zip"
)

// grantViaPKCE runs the public authorization-code+PKCE flow and returns the
// issued token set.
func grantViaPKCE(t *testing.T, app *zip.App, clientID, scope string) map[string]any {
	t.Helper()
	verifier := "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	params := loginParams(clientID, scope)
	params["codeChallenge"] = pkce.Challenge(verifier)
	params["codeChallengeMethod"] = "S256"
	code, _, _ := loginForCode(t, app, params)
	resp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {clientID}, "redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("grant failed: %d %v", resp.StatusCode, tok)
	}
	return tok
}

func refresh(t *testing.T, app *zip.App, clientID, refreshToken string, extra url.Values) (int, map[string]any) {
	t.Helper()
	form := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}, "client_id": {clientID}}
	for k, vs := range extra {
		form[k] = vs
	}
	resp, tok := postToken(t, app, form)
	return resp.StatusCode, tok
}

// A refresh rotates: it returns a new access token AND a new refresh token,
// distinct from the one presented.
func TestRefresh_Rotates(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	refresh1 := tok["refresh_token"].(string)

	status, out := refresh(t, app, "pub", refresh1, nil)
	if status != 200 {
		t.Fatalf("refresh status = %d, body %v", status, out)
	}
	refresh2, _ := out["refresh_token"].(string)
	if refresh2 == "" || refresh2 == refresh1 {
		t.Fatalf("refresh must rotate the token: got %q (old %q)", refresh2, refresh1)
	}
	if out["access_token"] == nil {
		t.Fatal("refresh must issue a new access token")
	}
}

// Replaying a rotated (consumed) refresh token is detected and revokes the whole
// family — the legitimate successor dies with it.
func TestRefresh_ReuseDetectionRevokesFamily(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	refresh1 := tok["refresh_token"].(string)

	// Legitimate rotation → refresh2.
	_, out := refresh(t, app, "pub", refresh1, nil)
	refresh2 := out["refresh_token"].(string)

	// Replay the consumed refresh1 → reuse detected.
	status, replay := refresh(t, app, "pub", refresh1, nil)
	if status != 400 || replay["error"] != "invalid_grant" {
		t.Fatalf("replay of rotated token: status=%d err=%v, want 400 invalid_grant", status, replay["error"])
	}

	// The family is revoked: the legitimate successor refresh2 no longer works.
	status, after := refresh(t, app, "pub", refresh2, nil)
	if status != 400 || after["error"] != "invalid_grant" {
		t.Fatalf("successor after reuse: status=%d err=%v, want 400 invalid_grant (family revoked)", status, after["error"])
	}
}

// Refresh may narrow scope but never widen it.
func TestRefresh_ScopeNarrowingOnly(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid profile email")
	rt := tok["refresh_token"].(string)

	t.Run("narrow ok", func(t *testing.T) {
		status, out := refresh(t, app, "pub", rt, url.Values{"scope": {"openid"}})
		if status != 200 || out["scope"] != "openid" {
			t.Fatalf("narrowing failed: status=%d scope=%v", status, out["scope"])
		}
	})

	t.Run("widen rejected", func(t *testing.T) {
		tok2 := grantViaPKCE(t, app, "pub", "openid")
		status, out := refresh(t, app, "pub", tok2["refresh_token"].(string), url.Values{"scope": {"openid profile admin"}})
		if status != 400 || out["error"] != "invalid_scope" {
			t.Fatalf("widening should be invalid_scope: status=%d err=%v", status, out["error"])
		}
	})
}

// An unknown refresh token is refused without leaking whether it ever existed.
func TestRefresh_UnknownToken(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}})
	status, out := refresh(t, app, "pub", "not-a-real-refresh-token", nil)
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("unknown refresh: status=%d err=%v", status, out["error"])
	}
}

// grantWithSecret runs the SAME PKCE flow but presents the client secret at the
// exchange, so the grant is established under client authentication.
func grantWithSecret(t *testing.T, app *zip.App, clientID, secret, scope string) map[string]any {
	t.Helper()
	verifier := "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	params := loginParams(clientID, scope)
	params["codeChallenge"] = pkce.Challenge(verifier)
	params["codeChallengeMethod"] = "S256"
	code, _, _ := loginForCode(t, app, params)
	resp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {clientID}, "client_secret": {secret},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("grant with secret failed: %d %v", resp.StatusCode, tok)
	}
	return tok
}

// A registration that HOLDS a client secret still serves a PUBLIC surface: a CLI,
// or an SPA whose secret exists only for a backend path. Such a client exchanges
// a PKCE code without presenting the secret, which authorizationCodeGrant
// deliberately allows — so refresh must accept the same client on the same terms,
// or the session it just established dies at the access token's expiry and the
// human signs in again every hour.
func TestRefresh_PKCEGrantNeedsNoSecretOnASecretHoldingClient(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "cli", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 720})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "cli", "openid offline_access") // no client_secret, exactly as the CLI
	status, out := refresh(t, app, "cli", tok["refresh_token"].(string), nil)
	if status != 200 {
		t.Fatalf("first refresh: status=%d body=%v, want 200 (a PKCE grant refreshes without a secret)", status, out)
	}

	// And the SECOND refresh: the successor row must carry the same
	// establishment fact, or refresh works exactly once and then 401s.
	rt2, _ := out["refresh_token"].(string)
	if rt2 == "" {
		t.Fatal("refresh did not rotate")
	}
	status2, out2 := refresh(t, app, "cli", rt2, nil)
	if status2 != 200 {
		t.Fatalf("second refresh: status=%d body=%v, want 200 (PublicGrant must survive rotation)", status2, out2)
	}
}

// The relaxation never widens: a grant that WAS established with the client
// secret still has to present it (RFC 6749 §6), so a stolen refresh token alone
// does not renew a confidential client's session.
func TestRefresh_ClientAuthenticatedGrantStillRequiresTheSecret(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "web", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 720})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	rt := grantWithSecret(t, app, "web", "s3cret", "openid offline_access")["refresh_token"].(string)

	if status, out := refresh(t, app, "web", rt, nil); status != 401 || out["error"] != "invalid_client" {
		t.Fatalf("secret-established grant refreshed without a secret: status=%d err=%v", status, out["error"])
	}
	// A wrong secret is refused too — the check is not merely "present".
	if status, _ := refresh(t, app, "web", rt, url.Values{"client_secret": {"wrong"}}); status != 401 {
		t.Fatalf("wrong secret accepted: status=%d", status)
	}
	if status, out := refresh(t, app, "web", rt, url.Values{"client_secret": {"s3cret"}}); status != 200 {
		t.Fatalf("correct secret refused: status=%d body=%v", status, out)
	}
}
