// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/zap-proto/zip"
)

// Every real relying party posts the authorize request on the QUERY STRING and
// keeps the BODY to the credential. The hosted login page is loaded at the URL
// /v1/iam/oauth/authorize handed it (authorizeForwardQuery, snake_case) and the
// @hanzo/iam SDK re-sends those parameters on its own query (camelCase); the
// body it posts is only {type,username,password,application}.
//
// Reading them from the body alone silently dropped a request the client had
// sent in full, and the damage surfaced two hops later at the relying party:
// no scope means no `openid`, so the token exchange answered 200 with NO
// id_token and userinfo withheld `email`; no nonce failed the id_token claim
// check of every strict consumer; no redirect_uri skipped the RFC 6749 §4.1.3
// binding at redemption. Every login_*_test.go in this package posted the
// parameters in the body, so CI proved a contract no client uses.
//
// These cases post exactly what the wire carries.

// queryLoginBody is what the live hanzo.id bundle actually PUTS IN THE BODY —
// the credential and nothing else.
func queryLoginBody() map[string]string {
	return map[string]string{
		"type":         "code",
		"organization": "hanzo",
		"username":     "alice",
		"password":     "pw",
		"application":  "conf",
	}
}

// loginWithQuery drives POST /v1/iam/login with the authorize request on the
// query and only the credential in the body, returning the minted code.
func loginWithQuery(t *testing.T, app *zip.App, q url.Values) string {
	t.Helper()
	resp, raw := do(t, app, jsonReq("POST", PathLogin+"?"+q.Encode(), queryLoginBody()))
	code, _ := decode(t, raw)["data"].(string)
	if code == "" {
		t.Fatalf("login minted no code: status=%d body=%s", resp.StatusCode, raw)
	}
	return code
}

// The SDK spelling (camelCase query): the minted code must carry the scope, the
// nonce and the redirect_uri, so the exchange yields a scoped id_token that
// echoes the nonce and a userinfo response holding the email.
func TestLogin_AuthorizePassthroughFromQuery_SDKSpelling(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	code := loginWithQuery(t, app, url.Values{
		"clientId":     {"conf"},
		"responseType": {"code"},
		"redirectUri":  {testRedirect},
		"scope":        {"openid profile email"},
		"state":        {"st-1"},
		"nonce":        {"nonce-from-rp"},
		"type":         {"code"},
	})

	resp, tok := exchangeCode(t, app, url.Values{
		"code":          {code},
		"client_id":     {"conf"},
		"client_secret": {"s3cret"},
		"redirect_uri":  {testRedirect},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("token status = %d, body = %v", resp.StatusCode, tok)
	}

	// scope reached the code, so the grant is an OIDC one.
	if tok["scope"] != "openid profile email" {
		t.Errorf("scope = %v, want %q", tok["scope"], "openid profile email")
	}
	// The relying party cannot sign a user in without this: python-social-auth
	// reads response["id_token"] unguarded and a missing key is a 500.
	idToken, _ := tok["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in the token response: %v", tok)
	}
	idClaims, err := verifyToken(context.Background(), db, idToken)
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	// A strict consumer rejects an id_token whose nonce is not the one it sent.
	if idClaims.Nonce != "nonce-from-rp" {
		t.Errorf("id_token nonce = %q, want nonce-from-rp", idClaims.Nonce)
	}
	// The `email` scope reached userinfo, so the RP can provision an account.
	access, _ := tok["access_token"].(string)
	status, info := userinfo(t, app, access)
	if status != 200 {
		t.Fatalf("userinfo status = %d, body %v", status, info)
	}
	if info["email"] != "alice@hanzo.ai" {
		t.Errorf("userinfo email = %v, want alice@hanzo.ai", info["email"])
	}
}

// The RFC spelling (snake_case query) is what THIS server's own authorize
// endpoint redirects the hosted login to (authorizeForwardQuery), so it must be
// read too — including the PKCE challenge that a public client depends on.
func TestLogin_AuthorizePassthroughFromQuery_RFCSpelling(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	verifier := "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	code := loginWithQuery(t, app, url.Values{
		"response_type":         {"code"},
		"client_id":             {"conf"},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid email"},
		"state":                 {"st-1"},
		"nonce":                 {"nonce-rfc"},
		"code_challenge":        {pkce.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	})

	resp, tok := exchangeCode(t, app, url.Values{
		"code":          {code},
		"client_id":     {"conf"},
		"redirect_uri":  {testRedirect},
		"code_verifier": {verifier},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("token status = %d, body = %v", resp.StatusCode, tok)
	}
	idToken, _ := tok["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token in the token response: %v", tok)
	}
	idClaims, err := verifyToken(context.Background(), db, idToken)
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if idClaims.Nonce != "nonce-rfc" {
		t.Errorf("id_token nonce = %q, want nonce-rfc", idClaims.Nonce)
	}
}

// A redirect_uri that only ever appeared on the query still BINDS the code:
// redeeming it without that exact redirect_uri is refused (RFC 6749 §4.1.3).
func TestLogin_QueryRedirectUriBindsTheCode(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	q := url.Values{
		"clientId":    {"conf"},
		"redirectUri": {testRedirect},
		"scope":       {"openid"},
	}
	resp, tok := exchangeCode(t, app, url.Values{
		"code":          {loginWithQuery(t, app, q)},
		"client_id":     {"conf"},
		"client_secret": {"s3cret"},
	})
	if resp.StatusCode != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("redeeming without the bound redirect_uri = %d %v, want 400 invalid_grant", resp.StatusCode, tok)
	}
}

// A redirect_uri on the query that the application never registered is refused
// at login — the query is a fallback for a MISSING value, never a way around
// the checks the body path runs.
func TestLogin_QueryRedirectUriMustBeRegistered(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	q := url.Values{"clientId": {"conf"}, "redirectUri": {"https://evil.example/steal"}, "scope": {"openid"}}
	_, raw := do(t, app, jsonReq("POST", PathLogin+"?"+q.Encode(), queryLoginBody()))
	m := decode(t, raw)
	if m["status"] != "error" {
		t.Fatalf("unregistered query redirect_uri was accepted: %v", m)
	}
}

// The body still WINS: a value present in both places takes the body's.
func TestLogin_BodyBeatsQuery(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	body := queryLoginBody()
	body["scope"] = "openid"
	body["nonce"] = "from-body"
	q := url.Values{"clientId": {"conf"}, "redirectUri": {testRedirect}, "scope": {"openid profile email"}, "nonce": {"from-query"}}

	_, raw := do(t, app, jsonReq("POST", PathLogin+"?"+q.Encode(), body))
	code, _ := decode(t, raw)["data"].(string)
	if code == "" {
		t.Fatalf("login minted no code: %s", raw)
	}
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	if tok["scope"] != "openid" {
		t.Errorf("scope = %v, want the body's %q", tok["scope"], "openid")
	}
	idClaims, err := verifyToken(context.Background(), db, tok["id_token"].(string))
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	if idClaims.Nonce != "from-body" {
		t.Errorf("id_token nonce = %q, want the body's from-body", idClaims.Nonce)
	}
}
