// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// An application of a reserved org is granted only on a credential proved in the sign-in.

const cliRedirect = "http://127.0.0.1:8765/callback"

// superSession seeds the admin org's console and CLI and admin/root, and returns root's session cookie.
func superSession(t *testing.T, app *zip.App, db orm.DB) string {
	t.Helper()
	console := seedApp(t, db, appOpts{clientID: "console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	cli := seedApp(t, db, appOpts{clientID: "admin-cli", redirectURIs: []string{cliRedirect}})
	console.Organization, cli.Organization = "admin", "admin"
	if err := console.Update(); err != nil {
		t.Fatalf("move the console into the admin org: %v", err)
	}
	if err := cli.Update(); err != nil {
		t.Fatalf("move the CLI into the admin org: %v", err)
	}
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "pw")
	resp, body := do(t, app, formReq("POST", PathLogin, url.Values{
		"organization": {"admin"}, "application": {"console"},
		"username": {"root"}, "password": {"pw"}, "type": {"login"},
	}))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("SuperAdmin sign-in failed: %s", body)
	}
	return cookieKV(resp.Header.Get("Set-Cookie"))
}

// cliAuthorize is admin-cli's authorize request, with an optional prompt.
func cliAuthorize(verifier, prompt string) url.Values {
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"admin-cli"},
		"redirect_uri":          {cliRedirect},
		"scope":                 {"openid"},
		"state":                 {"st-cli"},
		"code_challenge":        {pkce.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	return q
}

// Authorize sends a signed-in SuperAdmin to the page, and answers prompt=none with interaction_required.
func TestAttended_AuthorizeNeverAnswersFromASession(t *testing.T) {
	app, db := newServer(t)
	cookie := superSession(t, app, db)
	verifier := "verifier-attended-authorize-0123456789012345678901234"

	resp := authorizeWith(t, app, cliAuthorize(verifier, ""), cookie, nil)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 || !strings.HasPrefix(loc, hostedLoginPath) {
		t.Fatalf("a session answered admin-cli: status=%d Location=%q, want the sign-in page", resp.StatusCode, loc)
	}

	loc = requireRedirect(t, authorizeWith(t, app, cliAuthorize(verifier, "none"), cookie, nil), cliRedirect)
	u, _ := url.Parse(loc)
	if u.Query().Get("code") != "" {
		t.Fatalf("prompt=none minted a code for admin-cli from a session: %q", loc)
	}
	if got := u.Query().Get("error"); got != errInteractionRequired {
		t.Fatalf("error = %q, want %q", got, errInteractionRequired)
	}
}

// The login endpoint's session branch refuses with login_required.
func TestAttended_LoginNeverAnswersFromASession(t *testing.T) {
	app, db := newServer(t)
	cookie := superSession(t, app, db)
	verifier := "verifier-attended-login-012345678901234567890123456789"

	req := jsonReq("POST", PathLogin+"?"+cliAuthorize(verifier, "").Encode(), map[string]any{
		"type": "code", "clientId": "admin-cli",
	})
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	env := decode(t, body)
	if env["status"] != "error" || env["code"] != CodeLoginRequired {
		t.Fatalf("a session answered admin-cli at login: %s", body)
	}
	if code, _ := env["data"].(string); code != "" {
		t.Fatalf("a code was minted: %q", code)
	}
}

// Typing the credential still signs the SuperAdmin in, and the code exchanges.
func TestAttended_CredentialSignsIn(t *testing.T) {
	app, db := newServer(t)
	cookie := superSession(t, app, db)
	verifier := "verifier-attended-credential-0123456789012345678901"

	req := jsonReq("POST", PathLogin+"?"+cliAuthorize(verifier, "").Encode(), map[string]any{
		"type": "code", "clientId": "admin-cli",
		"organization": "admin", "username": "root", "password": "pw",
	})
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	env := decode(t, body)
	code, _ := env["data"].(string)
	if env["status"] != "ok" || code == "" {
		t.Fatalf("a typed credential was refused: %s", body)
	}
	resp, tok := exchangeCode(t, app, url.Values{
		"code":          {code},
		"client_id":     {"admin-cli"},
		"redirect_uri":  {cliRedirect},
		"code_verifier": {verifier},
	})
	if resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("exchange: %d %v", resp.StatusCode, tok)
	}
	row, err := store.GetTokenByCode(tctx(), db, code)
	if err != nil || row == nil || row.User != "admin/root" {
		t.Fatalf("code row = %+v (%v), want admin/root", row, err)
	}
}

// A session answers the admin org's confidential console neither at authorize nor at login.
func TestAttended_ConsoleNeverAnswersFromASession(t *testing.T) {
	app, db := newServer(t)
	cookie := superSession(t, app, db)
	verifier := "verifier-attended-console-01234567890123456789012345"
	q := cliAuthorize(verifier, "none")
	q.Set("client_id", "console")
	q.Set("redirect_uri", testRedirect)

	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), testRedirect)
	u, _ := url.Parse(loc)
	if u.Query().Get("code") != "" || u.Query().Get("error") != errInteractionRequired {
		t.Fatalf("a session answered the admin console: %q", loc)
	}
	q.Del("prompt")
	req := jsonReq("POST", PathLogin+"?"+q.Encode(), map[string]any{"type": "code", "clientId": "console"})
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if env := decode(t, body); env["status"] != "error" || env["code"] != CodeLoginRequired {
		t.Fatalf("a session answered the admin console at login: %s", body)
	}
}

// A reserved org's application holding a secret needs it at every redemption; a public one redeems by PKCE.
func TestAttended_AReservedOrgSecretBindsEveryRedemption(t *testing.T) {
	app, db := newServer(t)
	superSession(t, app, db)
	code, verifier := consoleCode(t, app)
	form := url.Values{
		"code": {code}, "client_id": {"console"},
		"redirect_uri": {testRedirect}, "code_verifier": {verifier},
	}
	resp, tok := exchangeCode(t, app, form)
	if resp.StatusCode != 401 || tok["error"] != "invalid_client" || tok["access_token"] != nil {
		t.Fatalf("a PKCE-only redemption for the admin console: %d %v, want 401 invalid_client", resp.StatusCode, tok)
	}
	form.Set("client_secret", "s3cret")
	if resp, tok = exchangeCode(t, app, form); resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("the console with its secret: %d %v", resp.StatusCode, tok)
	}

	// A public-grant family renews only with the secret.
	refresh := "legacy-console-refresh"
	row := &schema.Token{
		Owner: "admin", Name: "legacy-console", Application: "console", Organization: "admin",
		User: "admin/root", Scope: "openid", TokenType: "Bearer", PublicGrant: true,
		RefreshTokenHash: hashToken(refresh), RefreshExpireIn: time.Now().Add(time.Hour).Unix(),
	}
	row.RefreshFamily = "admin/legacy-console"
	if err := store.PersistToken(tctx(), db, row); err != nil {
		t.Fatalf("store the family: %v", err)
	}
	resp, body := do(t, app, formReq("POST", PathToken, url.Values{
		"grant_type": {"refresh_token"}, "client_id": {"console"}, "refresh_token": {refresh},
	}))
	if resp.StatusCode != 401 {
		t.Fatalf("a public-grant refresh for the admin console: %d %s, want 401", resp.StatusCode, body)
	}
}

// A tenant application that keeps no sign-in session is answered by no session.
func TestAttended_SessionlessAppNeverAnswersFromASession(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	seedApp(t, db, appOpts{clientID: "cli", redirectURIs: []string{cliRedirect}, noSession: true})
	cookie := signIn(t, app, "portal")
	verifier := "verifier-sessionless-0123456789012345678901234567890"
	q := cliAuthorize(verifier, "none")
	q.Set("client_id", "cli")

	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), cliRedirect)
	if u, _ := url.Parse(loc); u.Query().Get("code") != "" || u.Query().Get("error") != errInteractionRequired {
		t.Fatalf("a session answered an app keeping no sessions: %q", loc)
	}
	q.Del("prompt")
	req := jsonReq("POST", PathLogin+"?"+q.Encode(), map[string]any{"type": "code", "clientId": "cli"})
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	if env := decode(t, body); env["status"] != "error" || env["code"] != CodeLoginRequired {
		t.Fatalf("a session answered an app keeping no sessions at login: %s", body)
	}
}
