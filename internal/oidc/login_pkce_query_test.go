// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/store"
)

// These tests drive POST /v1/iam/login the way the id SPA's client.login() /
// silentLogin() actually do (pkgs/auth/src/client.ts): the CREDENTIALS in the JSON
// body, but the OAuth authorize passthrough — the PKCE challenge, redirect_uri,
// scope — on the QUERY STRING. The prior login tests posted every field in the
// BODY, so they never exercised this wire and green-passed while the real browser
// 401'd invalid_client at /token — the defect that forced three cutover rollbacks.
// The QUERY is the contract these assert.

// loginQueryWire is the authorize passthrough the SPA puts on the query string
// (code_challenge / code_challenge_method snake_case; clientId / redirectUri
// camelCase — client.ts's exact spelling).
type loginQueryWire struct {
	clientId            string
	redirectUri         string
	scope               string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
}

// loginBodyCreds is the credential set the SPA puts in the JSON body.
type loginBodyCreds struct {
	organization string
	application  string
	username     string
	password     string
}

// loginSPAWire POSTs /v1/iam/login with the authorize passthrough on the QUERY and
// the credentials in the JSON body — the exact shape id's client.login() sends
// (type echoed in both). Returns the minted authorization code from the Response
// envelope alongside the raw response.
func loginSPAWire(t *testing.T, app *zip.App, q loginQueryWire, b loginBodyCreds) (string, *http.Response, []byte) {
	t.Helper()
	u := url.Values{}
	setIfPresent(u, "clientId", q.clientId)
	setIfPresent(u, "redirectUri", q.redirectUri)
	setIfPresent(u, "scope", q.scope)
	setIfPresent(u, "state", q.state)
	setIfPresent(u, "nonce", q.nonce)
	setIfPresent(u, "code_challenge", q.codeChallenge)
	setIfPresent(u, "code_challenge_method", q.codeChallengeMethod)
	u.Set("type", "code")
	body := map[string]string{"type": "code"}
	if b.organization != "" {
		body["organization"] = b.organization
	}
	if b.application != "" {
		body["application"] = b.application
	}
	if b.username != "" {
		body["username"] = b.username
	}
	if b.password != "" {
		body["password"] = b.password
	}
	resp, raw := do(t, app, jsonReq("POST", PathLogin+"?"+u.Encode(), body))
	code, _ := decode(t, raw)["data"].(string)
	return code, resp, raw
}

// Defect 1 — the PKCE challenge arrives on the QUERY (as the SPA sends it), so the
// minted code is PKCE-bound and a secret-less browser redeem succeeds. The app also
// holds a client_secret (every migrated app does); the browser authenticates by
// PKCE and sends NO secret — the exact hanzo-cloud cutover shape.
//
// FAIL-BEFORE: loginHandler bound the challenge from the body only, so it arrived
// empty → CodeChallenge persisted "" → non-PKCE code → /token confidential branch →
// no secret → 401 invalid_client.
// PASS-AFTER: the query is read → CodeChallenge populated → PKCE branch → verifier
// verifies → 200 with a real token.
func TestLoginQueryWire_PKCEChallengeMintsPKCECode_SecretlessRedeem200(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	verifier := "login-verifier-000000000000000000000000000000000"
	challenge := ComputeS256Challenge(verifier)

	code, resp, raw := loginSPAWire(t, app,
		loginQueryWire{clientId: "conf", redirectUri: testRedirect, scope: "openid profile email", codeChallenge: challenge, codeChallengeMethod: "S256"},
		loginBodyCreds{organization: "hanzo", application: "conf", username: "alice", password: "pw"})
	if code == "" {
		t.Fatalf("login (challenge on the query) minted no code: status=%d body=%s", resp.StatusCode, raw)
	}

	// The stored code MUST be PKCE-bound — the assertion the body-only tests could
	// never make, because they never sent the challenge on the query.
	tok, err := store.GetTokenByCode(context.Background(), db, code)
	if err != nil || tok == nil {
		t.Fatalf("stored code lookup: err=%v nil=%v", err, tok == nil)
	}
	if tok.CodeChallenge != challenge {
		t.Fatalf("minted code is NOT PKCE-bound: CodeChallenge=%q, want %q — the challenge was dropped from the query", tok.CodeChallenge, challenge)
	}
	if tok.CodeChallengeMethod != "S256" {
		t.Fatalf("minted code method=%q, want S256", tok.CodeChallengeMethod)
	}

	// Secret-less PKCE exchange with the verifier → 200.
	tokResp, tokBody := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if tokResp.StatusCode != 200 || tokBody["access_token"] == nil {
		t.Fatalf("secret-less PKCE redeem must be 200 with a token, got %d %v (Defect 1)", tokResp.StatusCode, tokBody)
	}
	claims, err := verifyToken(context.Background(), db, tokBody["access_token"].(string))
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims.Subject != "hanzo/alice" {
		t.Fatalf("token subject=%q, want hanzo/alice", claims.Subject)
	}
	// The openid scope also came from the QUERY — its presence proves scope was not
	// dropped either (a strict OIDC client needs this id_token).
	if tokBody["id_token"] == nil {
		t.Fatal("no id_token — the openid scope was dropped from the query")
	}
}

// Defect 2 — a type=code authorization-code login establishes the session cookie,
// so a returning browser can silently mint the next app's code.
//
// FAIL-BEFORE: loginGrant called sessions.Set only for type != "code", so a code
// login set NO cookie and silent SSO was dead (get-account → "please sign in").
// PASS-AFTER: the cookie is set and resolves the signed-in identity.
func TestLoginQueryWire_TypeCodeSetsSessionCookie(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	verifier := "login-verifier-111111111111111111111111111111111"
	code, resp, raw := loginSPAWire(t, app,
		loginQueryWire{clientId: "conf", redirectUri: testRedirect, scope: "openid", codeChallenge: ComputeS256Challenge(verifier), codeChallengeMethod: "S256"},
		loginBodyCreds{organization: "hanzo", application: "conf", username: "alice", password: "pw"})
	if code == "" {
		t.Fatalf("type=code login minted no code: status=%d body=%s", resp.StatusCode, raw)
	}

	// The code login MUST set the session cookie.
	var sessionCookie string
	for _, c := range resp.Header.Values("Set-Cookie") {
		if strings.HasPrefix(c, sessions.CookieName+"=") {
			sessionCookie = c
		}
	}
	if sessionCookie == "" {
		t.Fatalf("type=code login set no %s cookie: Set-Cookie=%v (Defect 2)", sessions.CookieName, resp.Header.Values("Set-Cookie"))
	}

	// And the cookie resolves the signed-in identity via get-account — the read the
	// SPA's silentLogin does before it mints the next app's code.
	req := formReqNoBody("GET", PathGetAccount)
	req.Header.Set("Cookie", cookieKV(sessionCookie))
	gaResp, gaBody := do(t, app, req)
	if gaResp.StatusCode != 200 || decode(t, gaBody)["status"] != "ok" {
		t.Fatalf("get-account via the code-login cookie failed: status=%d body=%s", gaResp.StatusCode, gaBody)
	}
}

// Regression — the fix does NOT reopen the confidential client-auth hole. A login
// with NO PKCE challenge on the query mints a non-PKCE code, so /token still demands
// the client_secret: a secret-less redeem is 401 invalid_client, and only the
// correct secret yields a token. (This is the hanzo-commerce shape — pkce:false,
// secret auth — which the gate already showed at 200.)
func TestLoginQueryWire_NonPKCEConfidentialStillRequiresSecret(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	// SPA wire, but NO PKCE challenge on the query — a confidential login.
	code, resp, raw := loginSPAWire(t, app,
		loginQueryWire{clientId: "conf", redirectUri: testRedirect, scope: "openid"},
		loginBodyCreds{organization: "hanzo", application: "conf", username: "alice", password: "pw"})
	if code == "" {
		t.Fatalf("login minted no code: status=%d body=%s", resp.StatusCode, raw)
	}
	tok, _ := store.GetTokenByCode(context.Background(), db, code)
	if tok == nil {
		t.Fatal("no-challenge login stored no code")
	}
	if tok.CodeChallenge != "" {
		t.Fatalf("a no-challenge login must mint a NON-PKCE code (CodeChallenge=\"\"), got %q", tok.CodeChallenge)
	}

	// Secret-less redeem → 401 invalid_client (confidential branch unchanged).
	r1, b1 := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {"conf"}, "redirect_uri": {testRedirect}})
	if r1.StatusCode != 401 || b1["error"] != "invalid_client" {
		t.Fatalf("secret-less non-PKCE redeem must be 401 invalid_client, got %d %v", r1.StatusCode, b1)
	}
	// The correct secret → 200 (a 401 at client-auth does not burn the code).
	r2, b2 := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect}})
	if r2.StatusCode != 200 || b2["access_token"] == nil {
		t.Fatalf("confidential redeem with the secret must be 200, got %d %v", r2.StatusCode, b2)
	}
}
