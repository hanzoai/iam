// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/store"
)

// RFC 7662 introspection + RFC 7009 revocation, end to end: mint a real token via
// the password grant, introspect it (active + claims), revoke it, and confirm it
// then reads inactive AND its bearer no longer resolves at userinfo.

// postForm posts a form to path as the confidential client (client_secret_basic).
func postForm(t *testing.T, app *zip.App, path, clientID, secret string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	req := formReq("POST", path, form)
	if clientID != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	}
	resp, body := do(t, app, req)
	return resp, decode(t, body)
}

// mintPasswordToken issues an access+refresh token for the seeded user.
func mintPasswordToken(t *testing.T, app *zip.App) (access, refresh string) {
	t.Helper()
	_, tok := postToken(t, app, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"hanzo-console"},
		"client_secret": {"top-secret"},
		"username":      {"alice@hanzo.ai"},
		"password":      {"correct horse"},
		"scope":         {"openid profile email offline_access"},
	})
	access, _ = tok["access_token"].(string)
	refresh, _ = tok["refresh_token"].(string)
	if access == "" {
		t.Fatalf("no access_token minted; body=%v", tok)
	}
	return access, refresh
}

func TestIntrospect_activeToken_returnsClaims(t *testing.T) {
	app, db := newServer(t)
	_ = db
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	access, _ := mintPasswordToken(t, app)

	_, ir := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if ir["active"] != true {
		t.Fatalf("active = %v, want true; body=%v", ir["active"], ir)
	}
	if ir["sub"] != "hanzo/alice" {
		t.Errorf("sub = %v, want hanzo/alice", ir["sub"])
	}
	if ir["owner"] != "hanzo" {
		t.Errorf("owner = %v, want hanzo", ir["owner"])
	}
	if ir["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", ir["token_type"])
	}
}

func TestIntrospect_requiresConfidentialClientAuth(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	access, _ := mintPasswordToken(t, app)

	// No client auth → 401 (introspection is privileged).
	resp, _ := postForm(t, app, PathIntrospect, "", "", url.Values{"token": {access}})
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated introspect status = %d, want 401", resp.StatusCode)
	}
	// Wrong secret → 401.
	resp2, _ := postForm(t, app, PathIntrospect, "hanzo-console", "WRONG", url.Values{"token": {access}})
	if resp2.StatusCode != 401 {
		t.Fatalf("bad-secret introspect status = %d, want 401", resp2.StatusCode)
	}
}

func TestIntrospect_garbageToken_inactive(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	_, ir := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {"not-a-real-token"}})
	if ir["active"] != false {
		t.Fatalf("garbage token active = %v, want false", ir["active"])
	}
}

func TestRevoke_accessToken_thenInactive(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	access, _ := mintPasswordToken(t, app)

	// Active before revoke.
	_, before := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if before["active"] != true {
		t.Fatalf("token not active before revoke; body=%v", before)
	}

	// Revoke → 200.
	resp, _ := postForm(t, app, PathRevoke, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if resp.StatusCode != 200 {
		t.Fatalf("revoke status = %d, want 200", resp.StatusCode)
	}

	// Inactive after revoke — introspection reflects the deleted grant row.
	_, after := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if after["active"] != false {
		t.Fatalf("token still active after revoke; body=%v", after)
	}

	// And the bearer no longer resolves at userinfo (revocation is real).
	req := formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+access)
	if resp, _ := do(t, app, req); resp.StatusCode == 200 {
		t.Fatalf("userinfo still 200 for a revoked bearer")
	}
}

func TestRevoke_unknownToken_is200_noOracle(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	// RFC 7009 §2.2: an unknown token is a silent 200, not an error.
	resp, _ := postForm(t, app, PathRevoke, "hanzo-console", "top-secret", url.Values{"token": {"unknown"}})
	if resp.StatusCode != 200 {
		t.Fatalf("unknown-token revoke status = %d, want 200", resp.StatusCode)
	}
}

// The other half of a public client's session: it can END one.
//
// A public PKCE client can hold a long-lived refresh token, and revocation is the
// ONLY thing that cuts its session short before expiry. If the endpoint required a
// stored secret, such a client could not revoke: its logout would drop the local
// copy while the credential stayed spendable until it expired. This test requires
// a secret and asserts the public client is refused, pinning that it is not.
func TestRevoke_publicClient_revokesItsOwnRefreshFamily(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{
		clientID:     "hanzo-cli",
		secret:       "", // public: PKCE is the proof, there is no secret to present
		redirectURIs: []string{runtimeRedirect},
		refreshHours: 720,
		grants:       []string{"authorization_code", "refresh_token"},
	})
	seedUser(t, db, "z", "z@hanzo.ai", "correct horse battery staple")

	verifier := "KmKyPMK1T4JxydUiDsLmCaz79cqcmYqoBCpaeWWoxrU"
	code, _, body := loginForCode(t, app, map[string]string{
		"application": "hanzo-cli", "organization": "hanzo",
		"username": "z", "password": "correct horse battery staple",
		"clientId": "hanzo-cli", "redirectUri": runtimeRedirect,
		"codeChallenge": pkce.Challenge(verifier),
		"scope":         "openid profile email offline_access",
	})
	if code == "" {
		t.Fatalf("login produced no code: %s", body)
	}
	_, tok := exchangeCode(t, app, url.Values{
		"client_id": {"hanzo-cli"}, "code": {code},
		"redirect_uri": {runtimeRedirect}, "code_verifier": {verifier},
	})
	refresh, _ := tok["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("no refresh_token minted; body=%v", tok)
	}

	// Sign out: client_id and the token, which is all a public client HAS.
	resp, _ := postForm(t, app, PathRevoke, "hanzo-cli", "", url.Values{
		"token": {refresh}, "token_type_hint": {"refresh_token"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("public-client revoke status = %d, want 200 — logout cannot reach the server", resp.StatusCode)
	}

	// Signed out means signed out: the family is gone, so the token cannot renew.
	resp2, after := postForm(t, app, PathToken, "", "", url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"hanzo-cli"}, "refresh_token": {refresh},
	})
	if resp2.StatusCode == 200 {
		t.Fatalf("a revoked refresh token still minted a token: %v", after)
	}
}

// Widening authentication must not widen it for a client that HAS a secret:
// a caller that PRESENTS one must present the right one, and a Basic attempt is
// answered with the Basic challenge it used — and only a Basic attempt is.
func TestRevoke_confidentialClient_stillNeedsItsSecret(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	access, _ := mintPasswordToken(t, app)

	for name, secret := range map[string]string{"basic, empty secret": "", "basic, wrong secret": "nope"} {
		resp, body := postForm(t, app, PathRevoke, "hanzo-console", secret, url.Values{"token": {access}})
		if resp.StatusCode != 401 || body["error"] != "invalid_client" {
			t.Fatalf("%s: revoke status = %d %v, want 401 invalid_client", name, resp.StatusCode, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="OAuth2"` {
			t.Fatalf("%s: a failed Basic attempt must be answered with the Basic challenge, got %q", name, got)
		}
	}
	resp, body := postBody(t, app, PathRevoke, url.Values{
		"token": {access}, "client_id": {"hanzo-console"}, "client_secret": {"nope"},
	}, nil)
	if resp.StatusCode != 401 || body["error"] != "invalid_client" {
		t.Fatalf("wrong client_secret in the body: status = %d %v, want 401 invalid_client", resp.StatusCode, body)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Fatalf("the client never used Basic, so no Basic challenge: got %q", got)
	}

	// And the token it failed to revoke is untouched.
	_, ir := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if ir["active"] != true {
		t.Fatalf("an unauthenticated revoke killed the token anyway; body=%v", ir)
	}
}

// postBody posts a form with the client named in the body (client_secret_post or
// a public client), plus any extra headers — never HTTP Basic.
func postBody(t *testing.T, app *zip.App, path string, form url.Values, header map[string]string) (*http.Response, map[string]any) {
	t.Helper()
	req := formReq("POST", path, form)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, body := do(t, app, req)
	return resp, decode(t, body)
}

// requireRevoked asserts the RFC 7009 §2.2 success answer and no challenge.
func requireRevoked(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp.StatusCode != 200 {
		t.Fatalf("revoke status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Fatalf("revoke 200 carried WWW-Authenticate %q", got)
	}
}

// What a browser app's sign-out sends: client_id and the token in the body, and
// its access token as a Bearer — which is not client authentication. The app's
// registration holds a secret for a backend path, and the browser half signed in
// by PKCE without it, so the grant is public and client_id revokes it. Before,
// this answered 401 with a Basic challenge, which a browser turns into a
// password prompt, and the refresh token stayed spendable.
func TestRevoke_publicHalfOfAConfidentialRegistration(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedRichUser(t, db)

	verifier := "KmKyPMK1T4JxydUiDsLmCaz79cqcmYqoBCpaeWWoxrU"
	params := loginParams("conf", "openid offline_access")
	params["codeChallenge"] = pkce.Challenge(verifier)
	code, _, body := loginForCode(t, app, params)
	if code == "" {
		t.Fatalf("login produced no code: %s", body)
	}
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	access, _ := tok["access_token"].(string)
	refreshTok, _ := tok["refresh_token"].(string)
	if access == "" || refreshTok == "" {
		t.Fatalf("PKCE exchange without the secret minted no tokens: %v", tok)
	}

	bearer := map[string]string{"Authorization": "Bearer " + access}
	resp, _ := postBody(t, app, PathRevoke, url.Values{
		"token": {refreshTok}, "token_type_hint": {"refresh_token"}, "client_id": {"conf"},
	}, bearer)
	requireRevoked(t, resp)
	resp, _ = postBody(t, app, PathRevoke, url.Values{
		"token": {access}, "token_type_hint": {"access_token"}, "client_id": {"conf"},
	}, bearer)
	requireRevoked(t, resp)

	if status, out := refresh(t, app, "conf", refreshTok, nil); status == 200 {
		t.Fatalf("a revoked refresh token still minted a token: %v", out)
	}
	req := formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+access)
	if resp, _ := do(t, app, req); resp.StatusCode == 200 {
		t.Fatal("userinfo still 200 for a revoked bearer")
	}
}

// The public half names the client; it does not prove the secret. So it revokes
// only grants that were established without the secret. A grant the secret
// established (here the password grant) still needs the secret, and the answer
// stays 200 so it tells the caller nothing about the token (RFC 7009 §2.2).
func TestRevoke_publicHalfCannotRevokeAConfidentialGrant(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	access, refreshTok := mintPasswordToken(t, app)

	for _, token := range []string{access, refreshTok, "junk"} {
		resp, _ := postBody(t, app, PathRevoke, url.Values{"token": {token}, "client_id": {"hanzo-console"}}, nil)
		requireRevoked(t, resp)
	}
	_, ir := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if ir["active"] != true {
		t.Fatalf("client_id alone revoked a grant the secret established; body=%v", ir)
	}
	if row, _ := store.GetTokenByRefreshHash(tctx(), db, hashToken(refreshTok)); row == nil {
		t.Fatal("client_id alone revoked a confidential refresh family")
	}
}

// A request that names no client, or an unknown one, is refused — without a
// Basic challenge, because it did not attempt Basic. The SDK's Bearer header is
// not client authentication, and a browser prompts for a password on a Basic
// challenge.
func TestRevoke_unidentifiedClient_401WithoutBasicChallenge(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret"})

	for name, form := range map[string]url.Values{
		"no client_id":      {"token": {"junk"}},
		"unknown client_id": {"token": {"junk"}, "client_id": {"nobody"}},
	} {
		resp, body := postBody(t, app, PathRevoke, form, map[string]string{"Authorization": "Bearer junk"})
		if resp.StatusCode != 401 || body["error"] != "invalid_client" {
			t.Fatalf("%s: status = %d %v, want 401 invalid_client", name, resp.StatusCode, body)
		}
		if got := resp.Header.Get("WWW-Authenticate"); got != "" {
			t.Fatalf("%s: no Basic attempt, yet WWW-Authenticate = %q", name, got)
		}
	}
}

// Introspection is NOT widened with revocation. It reports on tokens the caller
// did not issue, so it stays addressed to a protected resource (RFC 7662 §2.1);
// a public client_id proves nothing and is refused.
func TestIntrospect_publicClientStillRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cli", secret: ""})
	resp, _ := postForm(t, app, PathIntrospect, "hanzo-cli", "", url.Values{"token": {"anything"}})
	if resp.StatusCode != 401 {
		t.Fatalf("public-client introspect status = %d, want 401", resp.StatusCode)
	}
}
