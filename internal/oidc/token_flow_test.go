// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

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

	// The access token verifies through iam2's own verify path with the right
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
	params["codeChallenge"] = ComputeS256Challenge(verifier)
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

// The RFC 6749 §5.2 error taxonomy: invalid_client → 401 + WWW-Authenticate,
// every other error → 400, each with the right code.
func TestToken_ErrorTaxonomy(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	t.Run("missing grant_type", func(t *testing.T) {
		resp, tok := postToken(t, app, url.Values{})
		requireError(t, resp, tok, 400, "invalid_request")
	})
	t.Run("unsupported grant_type", func(t *testing.T) {
		// A grant iam2 does not implement (device_code) — password IS supported now.
		resp, tok := postToken(t, app, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}})
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
		if resp.Header.Get("WWW-Authenticate") == "" {
			t.Error("401 invalid_client must carry WWW-Authenticate")
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
	seedApp(t, db, appOpts{clientID: "svc", secret: "svc-secret", redirectURIs: []string{testRedirect}})
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
