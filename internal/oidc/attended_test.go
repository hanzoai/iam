// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func seedReservedApp(t *testing.T, db orm.DB, clientID, secret string, redirects []string, enableSession bool) *schema.Application {
	t.Helper()
	seedRSACert(t, db, "cert-"+clientID)
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId = "admin", clientID, clientID
	a.ClientSecret = secret
	a.Organization = "admin"
	a.Cert = "cert-" + clientID
	a.EnablePassword = true
	a.EnableSigninSession = enableSession
	a.ExpireInHours = 1
	a.RefreshExpireInHours = 24
	a.RedirectUris = redirects
	a.SetId("admin/" + clientID)
	if err := a.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed reserved app %s: %v", clientID, err)
	}
	return a
}

func signInAdmin(t *testing.T, app *zip.App, clientID string) string {
	t.Helper()
	resp, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "admin", "application": clientID,
		"username": "root", "password": "pw", "type": "login",
	}))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("admin login failed: %d %s", resp.StatusCode, body)
	}
	cookie := cookieKV(resp.Header.Get("Set-Cookie"))
	if cookie == "" {
		t.Fatal("admin login set no session cookie")
	}
	return cookie
}

// Reserved-org applications never accept silent sign-on from an existing browser
// session — neither on the canonical issuer nor on a sign-in origin listed in
// IAM_SIGNOUT_APPS, whether EnableSigninSession is true or false, and whether
// the client is public or confidential. Interactive credential proof still works.
func TestAttended_ReservedOrgAppRefusesSilentSession(t *testing.T) {
	t.Setenv(envSignoutApps, "admin-pub,admin-conf")
	app, db := newServer(t)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	seedUserInOrg(t, db, "admin", "root", "root@admin.example", "pw")
	seedReservedApp(t, db, "admin-pub", "", []string{secondRedirect}, true)
	seedReservedApp(t, db, "admin-conf", "admin-sec", []string{secondRedirect}, true)

	cookie := signInAdmin(t, app, "admin-pub")
	verifier := "verifier-attended-admin-012345678901234567890123456789"

	for _, clientID := range []string{"admin-pub", "admin-conf"} {
		t.Run(clientID, func(t *testing.T) {
			q := url.Values{
				"response_type":         {"code"},
				"client_id":             {clientID},
				"redirect_uri":          {secondRedirect},
				"scope":                 {"openid profile"},
				"state":                 {"st-admin"},
				"code_challenge":        {pkce.Challenge(verifier)},
				"code_challenge_method": {"S256"},
			}

			// No prompt + live session: must send browser to hosted login page, never mint a code.
			resp := authorizeWith(t, app, q, cookie, nil)
			if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, hostedLoginPath+"?") || strings.Contains(loc, "code=") {
				t.Fatalf("no-prompt authorize on reserved app answered %d %q, want hosted login", resp.StatusCode, loc)
			}

			// prompt=none without session: standards-compliant login_required.
			qNone := url.Values{}
			for k, v := range q {
				qNone[k] = v
			}
			qNone.Set("prompt", "none")
			locNoSess := requireRedirect(t, authorizeWith(t, app, qNone, "", nil), secondRedirect)
			if !strings.Contains(locNoSess, "error=login_required") || strings.Contains(locNoSess, "code=") {
				t.Fatalf("prompt=none without session = %q, want login_required", locNoSess)
			}

			// prompt=none with live session: standards-compliant interaction_required.
			locWithSess := requireRedirect(t, authorizeWith(t, app, qNone, cookie, nil), secondRedirect)
			if !strings.Contains(locWithSess, "error=interaction_required") || strings.Contains(locWithSess, "code=") {
				t.Fatalf("prompt=none with session = %q, want interaction_required", locWithSess)
			}

			// Even on a sign-in origin listed in IAM_SIGNOUT_APPS: no silent code!
			req := formReqNoBody("GET", authorizeURL(qNone))
			req.Host = "hanzo.ai"
			req.Header.Set("Cookie", cookie)
			req.Header.Set("Sec-Fetch-Mode", "navigate")
			req.Header.Set("Sec-Fetch-Site", "cross-site")
			req.Header.Set("Sec-Fetch-Dest", "document")
			respOrigin, _ := do(t, app, req)
			locOrigin := requireRedirect(t, respOrigin, secondRedirect)
			if strings.Contains(locOrigin, "code=") || !strings.Contains(locOrigin, "error=") {
				t.Fatalf("sign-in origin prompt=none for reserved app = %q, want error and no code", locOrigin)
			}

			// POST /v1/iam/login {type:"code"} with cookie only (no credentials): refused.
			reqLogin := fromPage(jsonReq("POST", PathLogin, map[string]string{
				"type": "code", "clientId": clientID, "redirectUri": secondRedirect,
				"scope": "openid", "codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
			}))
			reqLogin.Header.Set("Cookie", cookie)
			_, body := do(t, app, reqLogin)
			if env := decode(t, body); env["status"] != "error" || env["code"] != CodeLoginRequired {
				t.Fatalf("cookie-only type=code on reserved app = %v, want %s", env, CodeLoginRequired)
			}

			// Interactive credential login still succeeds.
			code, _, raw := loginForCode(t, app, map[string]string{
				"organization": "admin", "username": "root", "password": "pw",
				"clientId": clientID, "redirectUri": secondRedirect, "scope": "openid",
				"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
			})
			if code == "" {
				t.Fatalf("interactive admin login failed: %s", raw)
			}
		})
	}
}

// enableSigninSession is an explicit per-application policy: when false on an
// ordinary tenant app, silent sign-on is disabled and prompt=none returns
// interaction_required (with session) or login_required (without session).
func TestAttended_EnableSigninSessionFalseRefusesSilentSession(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "portal", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedApp(t, db, appOpts{clientID: "strict-app", redirectURIs: []string{secondRedirect}, noSession: true})
	seedApp(t, db, appOpts{clientID: "sso-app", redirectURIs: []string{secondRedirect}, noSession: false})
	seedRichUser(t, db)

	cookie := signIn(t, app, "portal")
	verifier := "verifier-nosession-0123456789012345678901234567890123"
	makeQ := func(clientID, prompt string) url.Values {
		q := url.Values{
			"response_type":         {"code"},
			"client_id":             {clientID},
			"redirect_uri":          {secondRedirect},
			"scope":                 {"openid profile"},
			"state":                 {"st-1"},
			"code_challenge":        {pkce.Challenge(verifier)},
			"code_challenge_method": {"S256"},
		}
		if prompt != "" {
			q.Set("prompt", prompt)
		}
		return q
	}

	// Ordinary app with enableSigninSession=true still mints silently.
	if loc := requireRedirect(t, authorizeWith(t, app, makeQ("sso-app", "none"), cookie, nil), secondRedirect); !strings.Contains(loc, "code=") {
		t.Fatalf("enableSigninSession=true app should mint silently, got %q", loc)
	}

	// Ordinary app with enableSigninSession=false never mints from session.
	resp := authorizeWith(t, app, makeQ("strict-app", ""), cookie, nil)
	if loc := resp.Header.Get("Location"); resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, hostedLoginPath+"?") || strings.Contains(loc, "code=") {
		t.Fatalf("no-prompt on enableSigninSession=false answered %d %q, want hosted login", resp.StatusCode, loc)
	}
	if loc := requireRedirect(t, authorizeWith(t, app, makeQ("strict-app", "none"), "", nil), secondRedirect); !strings.Contains(loc, "error=login_required") {
		t.Fatalf("prompt=none without session = %q, want login_required", loc)
	}
	if loc := requireRedirect(t, authorizeWith(t, app, makeQ("strict-app", "none"), cookie, nil), secondRedirect); !strings.Contains(loc, "error=interaction_required") {
		t.Fatalf("prompt=none with session = %q, want interaction_required", loc)
	}

	// Cookie-only POST /v1/iam/login {type:"code"} is refused; password succeeds.
	req := fromPage(jsonReq("POST", PathLogin, map[string]string{
		"type": "code", "clientId": "strict-app", "redirectUri": secondRedirect,
		"scope": "openid", "codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	}))
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if env := decode(t, body); env["status"] != "error" || env["code"] != CodeLoginRequired {
		t.Fatalf("cookie-only type=code on strict-app = %v, want %s", env, CodeLoginRequired)
	}
	code, _, raw := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"clientId": "strict-app", "redirectUri": secondRedirect, "scope": "openid",
		"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	})
	if code == "" {
		t.Fatalf("interactive login on strict-app failed: %s", raw)
	}
}

// Confidential reserved-org applications never relax client authentication via
// PKCE or PublicGrant: the secret is required on code exchange, refresh, and
// revocation.
func TestAttended_ConfidentialReservedOrgAppNeverRelaxesSecret(t *testing.T) {
	app, db := newServer(t)
	seedUserInOrg(t, db, "admin", "root", "root@admin.example", "pw")
	seedReservedApp(t, db, "admin-conf", "admin-s3cret", []string{testRedirect}, false)

	verifier := "verifier-conf-admin-012345678901234567890123456789012"
	code, _, raw := loginForCode(t, app, map[string]string{
		"organization": "admin", "username": "root", "password": "pw",
		"clientId": "admin-conf", "redirectUri": testRedirect, "scope": "openid offline_access",
		"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	})
	if code == "" {
		t.Fatalf("login failed: %s", raw)
	}

	// Code exchange with PKCE verifier alone (no secret): MUST fail 401 invalid_client.
	resp, m := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"admin-conf"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 401 || m["error"] != "invalid_client" {
		t.Fatalf("secretless code exchange on confidential admin app: %d %v, want 401 invalid_client", resp.StatusCode, m)
	}

	// With the secret: code still live and exchanges cleanly.
	resp, m = exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"admin-conf"}, "client_secret": {"admin-s3cret"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	})
	if resp.StatusCode != 200 || m["access_token"] == nil || m["refresh_token"] == nil {
		t.Fatalf("authenticated code exchange failed: %d %v", resp.StatusCode, m)
	}
	rt := m["refresh_token"].(string)

	// Even if a stored row somehow carries PublicGrant=true, refresh MUST still require secret.
	row, err := store.GetTokenByRefreshHash(tctx(), db, hashToken(rt))
	if err != nil || row == nil {
		t.Fatalf("load refresh row: %v", err)
	}
	row.PublicGrant = true
	if err := store.SaveToken(tctx(), db, row); err != nil {
		t.Fatal(err)
	}

	status, out := refresh(t, app, "admin-conf", rt, nil)
	if status != 401 || out["error"] != "invalid_client" {
		t.Fatalf("secretless refresh on confidential admin app: %d %v, want 401 invalid_client", status, out)
	}
	status, out = refresh(t, app, "admin-conf", rt, url.Values{"client_secret": {"admin-s3cret"}})
	if status != 200 || out["access_token"] == nil {
		t.Fatalf("authenticated refresh failed: %d %v", status, out)
	}
	access2 := out["access_token"].(string)

	// Mark rotated row PublicGrant=true and verify secretless revoke cannot kill it.
	row2, err := store.GetTokenByAccessTokenHash(tctx(), db, hashToken(access2))
	if err != nil || row2 == nil {
		t.Fatalf("load rotated row: %v", err)
	}
	row2.PublicGrant = true
	if err := store.SaveToken(tctx(), db, row2); err != nil {
		t.Fatal(err)
	}
	do(t, app, formReq("POST", PathRevoke, url.Values{"client_id": {"admin-conf"}, "token": {access2}}))
	if st, _ := userinfo(t, app, access2); st != 200 {
		t.Fatalf("secretless revoke killed confidential admin token (userinfo=%d)", st)
	}

	// Authenticated revoke kills it immediately.
	do(t, app, formReq("POST", PathRevoke, url.Values{
		"client_id": {"admin-conf"}, "client_secret": {"admin-s3cret"}, "token": {access2},
	}))
	if st, _ := userinfo(t, app, access2); st != 401 {
		t.Fatalf("authenticated revoke did not kill token (userinfo=%d)", st)
	}
}
