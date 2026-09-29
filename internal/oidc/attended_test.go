// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/store"
)

// A public client of the admin org (admin-cli) is granted only on a credential
// proved in the sign-in that asks for it. Its code is redeemed with the PKCE
// verifier alone at a loopback address, so a SuperAdmin's session answering for
// it would hand a platform token to whoever started the flow.

const cliRedirect = "http://127.0.0.1:8765/callback"

// superSession seeds the admin org's confidential console, its public CLI and
// the SuperAdmin admin/root, signs root in at the console, and returns the
// session cookie.
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

// The authorize endpoint sends a signed-in SuperAdmin to the page, and answers
// prompt=none with interaction_required on the CLI's own callback.
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

// The login endpoint's single-sign-on branch refuses too, with the reason the
// page routes to its credential form.
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

// The admin org's confidential console keeps single sign-on: only a public
// client needs the person present.
func TestAttended_ConfidentialConsoleKeepsSSO(t *testing.T) {
	app, db := newServer(t)
	cookie := superSession(t, app, db)
	verifier := "verifier-attended-console-01234567890123456789012345"
	q := cliAuthorize(verifier, "none")
	q.Set("client_id", "console")
	q.Set("redirect_uri", testRedirect)

	codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), testRedirect))
}
