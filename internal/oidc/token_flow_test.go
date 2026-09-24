// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/zap-proto/zip"
)

// loginParams builds a type=code login body for org "hanzo" / user alice.
func loginParams(clientID, scope string) map[string]string {
	return map[string]string{
		"organization": "hanzo",
		"username":     "alice",
		"password":     "pw",
		"clientId":     clientID,
		"redirectUri":  testRedirect,
		"scope":        scope,
		"nonce":        "nonce-1",
	}
}

// The confidential authorization-code flow, end to end over HTTP: login mints a
// code, the token endpoint exchanges it for a verifiable access token, an
// id_token that echoes the nonce, and a refresh token — with no-store caching.
func TestAuthCodeFlow_ConfidentialHappyPath(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	code, resp, body := loginForCode(t, app, loginParams("conf", "openid profile email"))
	if code == "" {
		t.Fatalf("login did not mint a code: status=%d body=%s", resp.StatusCode, body)
	}

	form := url.Values{
		"code":          {code},
		"client_id":     {"conf"},
		"client_secret": {"s3cret"},
		"redirect_uri":  {testRedirect},
	}
	tokResp, tok := exchangeCode(t, app, form)
	if tokResp.StatusCode != 200 {
		t.Fatalf("token status = %d, body = %v", tokResp.StatusCode, tok)
	}
	if cc := tokResp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	if tok["token_type"] != "Bearer" || tok["access_token"] == nil ||
		tok["id_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("token response missing fields: %v", tok)
	}

	// The access token verifies through iam's own verify path with the right
	// issuer, audience, subject, and tenant.
	access := tok["access_token"].(string)
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("verify access token: %v", err)
	}
	if claims.Issuer != "https://hanzo.id" {
		t.Errorf("iss = %q, want https://hanzo.id", claims.Issuer)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "conf" {
		t.Errorf("aud = %v, want [conf]", claims.Audience)
	}
	if claims.Subject != "hanzo/alice" || claims.Owner != "hanzo" {
		t.Errorf("sub/owner = %q/%q, want hanzo/alice + hanzo", claims.Subject, claims.Owner)
	}

	// The id_token echoes the request nonce.
	idClaims, err := verifyToken(context.Background(), db, tok["id_token"].(string))
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if idClaims.Nonce != "nonce-1" {
		t.Errorf("id_token nonce = %q, want nonce-1", idClaims.Nonce)
	}
}

// The public client flow requires and verifies PKCE; a tampered verifier fails.
func TestAuthCodeFlow_PublicPKCE(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	verifier := "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	params := loginParams("pub", "openid")
	params["codeChallenge"] = pkce.Challenge(verifier)
	params["codeChallengeMethod"] = "S256"

	t.Run("valid verifier", func(t *testing.T) {
		code, _, _ := loginForCode(t, app, params)
		resp, tok := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {"pub"}, "redirect_uri": {testRedirect}, "code_verifier": {verifier}})
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("valid PKCE exchange failed: %d %v", resp.StatusCode, tok)
		}
	})

	t.Run("tampered verifier", func(t *testing.T) {
		code, _, _ := loginForCode(t, app, params)
		resp, tok := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {"pub"}, "redirect_uri": {testRedirect}, "code_verifier": {"the-WRONG-verifier-000000000000000000000000"}})
		if resp.StatusCode != 400 || tok["error"] != "invalid_grant" {
			t.Fatalf("tampered PKCE: status=%d err=%v, want 400 invalid_grant", resp.StatusCode, tok["error"])
		}
	})

	t.Run("missing verifier", func(t *testing.T) {
		code, _, _ := loginForCode(t, app, params)
		resp, tok := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {"pub"}, "redirect_uri": {testRedirect}})
		if resp.StatusCode != 400 || tok["error"] != "invalid_grant" {
			t.Fatalf("missing verifier: status=%d err=%v", resp.StatusCode, tok["error"])
		}
	})
}

// The RFC 6749 §5.2 error taxonomy: invalid_client → 401, with the Basic
// challenge only when the client used Basic; every other error → 400, each with
// the right code.
func TestToken_ErrorTaxonomy(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	t.Run("missing grant_type", func(t *testing.T) {
		resp, tok := postToken(t, app, url.Values{})
		requireError(t, resp, tok, 400, "invalid_request")
	})
	t.Run("unsupported grant_type", func(t *testing.T) {
		// A grant iam does not implement (RFC 7523 jwt-bearer) — device_code and
		// password ARE supported now.
		resp, tok := postToken(t, app, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:jwt-bearer"}})
		requireError(t, resp, tok, 400, "unsupported_grant_type")
	})
	t.Run("unknown code", func(t *testing.T) {
		resp, tok := exchangeCode(t, app, url.Values{"code": {"nope"}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect}})
		requireError(t, resp, tok, 400, "invalid_grant")
	})
	t.Run("wrong client secret is invalid_client 401", func(t *testing.T) {
		code, _, _ := loginForCode(t, app, loginParams("conf", "openid"))
		resp, tok := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {"conf"}, "client_secret": {"WRONG"}, "redirect_uri": {testRedirect}})
		requireError(t, resp, tok, 401, "invalid_client")
		if got := resp.Header.Get("WWW-Authenticate"); got != "" {
			t.Errorf("client_secret_post never used Basic, yet WWW-Authenticate = %q", got)
		}
	})
	t.Run("wrong Basic credentials are invalid_client 401 with the Basic challenge", func(t *testing.T) {
		code, _, _ := loginForCode(t, app, loginParams("conf", "openid"))
		req := formReq("POST", PathToken, url.Values{"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {testRedirect}})
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("conf:WRONG")))
		resp, body := do(t, app, req)
		requireError(t, resp, decode(t, body), 401, "invalid_client")
		if got := resp.Header.Get("WWW-Authenticate"); got != `Basic realm="OAuth2"` {
			t.Errorf("a failed Basic attempt must be answered with the Basic challenge, got %q", got)
		}
	})
	t.Run("redirect_uri mismatch", func(t *testing.T) {
		code, _, _ := loginForCode(t, app, loginParams("conf", "openid"))
		resp, tok := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {"https://app.example/other"}})
		requireError(t, resp, tok, 400, "invalid_grant")
	})
	t.Run("code is single-use", func(t *testing.T) {
		code, _, _ := loginForCode(t, app, loginParams("conf", "openid"))
		form := url.Values{"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect}}
		if resp, _ := exchangeCode(t, app, cloneValues(form)); resp.StatusCode != 200 {
			t.Fatalf("first exchange failed: %d", resp.StatusCode)
		}
		resp, tok := exchangeCode(t, app, cloneValues(form))
		requireError(t, resp, tok, 400, "invalid_grant")
	})
}

// A code past its TTL is refused.
func TestToken_ExpiredCode(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	base := time.Unix(1_800_000_000, 0)
	nowFuncSet(t, base)
	code, _, _ := loginForCode(t, app, loginParams("conf", "openid"))

	// Advance past the 5-minute code TTL.
	nowFuncSet(t, base.Add(codeTTL+time.Minute))
	resp, tok := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect}})
	requireError(t, resp, tok, 400, "invalid_grant")
}

// client_credentials issues a machine token (no user, no id_token, no refresh);
// a public client or a bad secret is refused 401.
func TestClientCredentials(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", redirectURIs: []string{testRedirect}, grants: machineGrants})
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}})

	t.Run("post credentials", func(t *testing.T) {
		resp, tok := postToken(t, app, url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"svc-secret"}, "scope": {"read"}})
		if resp.StatusCode != 200 {
			t.Fatalf("status = %d, body = %v", resp.StatusCode, tok)
		}
		if tok["refresh_token"] != nil || tok["id_token"] != nil {
			t.Errorf("client_credentials must not issue refresh/id_token: %v", tok)
		}
		claims, err := verifyToken(context.Background(), db, tok["access_token"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject != "admin/svc" || claims.Owner != "hanzo" {
			t.Errorf("sub/owner = %q/%q, want admin/svc + hanzo", claims.Subject, claims.Owner)
		}
	})

	t.Run("basic auth", func(t *testing.T) {
		req := formReq("POST", PathToken, url.Values{"grant_type": {"client_credentials"}})
		req.SetBasicAuth("svc", "svc-secret")
		resp, body := do(t, app, req)
		if resp.StatusCode != 200 {
			t.Fatalf("basic-auth client_credentials: status %d, body %s", resp.StatusCode, body)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		resp, tok := postToken(t, app, url.Values{"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"nope"}})
		requireError(t, resp, tok, 401, "invalid_client")
	})

	t.Run("public client refused", func(t *testing.T) {
		resp, tok := postToken(t, app, url.Values{"grant_type": {"client_credentials"}, "client_id": {"pub"}})
		requireError(t, resp, tok, 401, "invalid_client")
	})
}

// A confidential client that holds a secret for its code exchange but never
// declared client_credentials is refused unauthorized_client, and nothing is
// minted: the secret proves who the client is, the declaration says what it may
// do. The same registration with the grant declared mints.
func TestClientCredentials_undeclaredGrantRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "web", secret: "web-secret", redirectURIs: []string{testRedirect},
		grants: []string{"authorization_code", "refresh_token"}})
	seedApp(t, db, appOpts{clientID: "webm2m", secret: "webm2m-secret", redirectURIs: []string{testRedirect},
		grants: []string{"authorization_code", "refresh_token", "client_credentials"}})
	seedApp(t, db, appOpts{clientID: "bare", secret: "bare-secret"})

	for _, id := range []string{"web", "bare"} {
		t.Run(id+" undeclared", func(t *testing.T) {
			before := tokens(t, db)
			resp, tok := postToken(t, app, url.Values{"grant_type": {"client_credentials"}, "client_id": {id}, "client_secret": {id + "-secret"}})
			requireError(t, resp, tok, 400, "unauthorized_client")
			if tok["access_token"] != nil {
				t.Fatalf("an application without the grant minted: %v", tok)
			}
			if n := tokens(t, db); n != before {
				t.Fatalf("token rows = %d after a refused mint, want %d", n, before)
			}
		})
	}

	t.Run("basic auth undeclared", func(t *testing.T) {
		req := formReq("POST", PathToken, url.Values{"grant_type": {"client_credentials"}})
		req.SetBasicAuth("web", "web-secret")
		resp, body := do(t, app, req)
		requireError(t, resp, decode(t, body), 400, "unauthorized_client")
	})

	// Client authentication is decided first: a wrong secret on an app without
	// the grant is invalid_client, so the grant list is no oracle to a caller
	// that cannot authenticate.
	t.Run("wrong secret is invalid_client first", func(t *testing.T) {
		resp, tok := postToken(t, app, url.Values{"grant_type": {"client_credentials"}, "client_id": {"web"}, "client_secret": {"nope"}})
		requireError(t, resp, tok, 401, "invalid_client")
	})

	t.Run("declared mints", func(t *testing.T) {
		resp, tok := postToken(t, app, url.Values{"grant_type": {"client_credentials"}, "client_id": {"webm2m"}, "client_secret": {"webm2m-secret"}})
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("declared client_credentials: status = %d, body = %v", resp.StatusCode, tok)
		}
		claims, err := verifyToken(context.Background(), db, tok["access_token"].(string))
		if err != nil {
			t.Fatal(err)
		}
		if claims.Subject != "admin/webm2m" {
			t.Errorf("sub = %q, want admin/webm2m", claims.Subject)
		}
	})
}

// --- helpers ---

func postToken(t *testing.T, app *zip.App, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	resp, body := do(t, app, formReq("POST", PathToken, form))
	return resp, decode(t, body)
}

func requireError(t *testing.T, resp *http.Response, tok map[string]any, status int, code string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("status = %d, want %d (body %v)", resp.StatusCode, status, tok)
	}
	if tok["error"] != code {
		t.Fatalf("error = %v, want %q", tok["error"], code)
	}
}

func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, vs := range v {
		out[k] = append([]string(nil), vs...)
	}
	// exchangeCode re-sets grant_type; drop it so the clone re-adds cleanly.
	out.Del("grant_type")
	return out
}
