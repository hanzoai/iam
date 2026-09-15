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

	"github.com/hanzoai/iam/internal/sessions"
)

// Several people signed in on one browser: the cookie holds each of them, the
// chooser lists them, and an authorize request names the one it is for.

// signInOn signs username in on a browser that already carries cookie, and
// returns the cookie the browser holds afterwards.
func signInOn(t *testing.T, app *zip.App, cookie, username string) string {
	t.Helper()
	form := url.Values{
		"organization": {"hanzo"}, "application": {"portal"},
		"username": {username}, "password": {"pw"}, "type": {"login"},
	}
	req := formReq("POST", PathLogin, form)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, body := do(t, app, req)
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("sign-in as %s failed: status=%d body=%s", username, resp.StatusCode, body)
	}
	if set := cookieKV(resp.Header.Get("Set-Cookie")); strings.HasPrefix(set, sessions.CookieName+"=") {
		return set
	}
	return cookie
}

// twoPeople signs alice in, then bob, on one browser.
func twoPeople(t *testing.T) (*zip.App, orm.DB, string) {
	t.Helper()
	app, db := newServer(t)
	twoApps(t, db)
	seedUserInOrg(t, db, "hanzo", "bob", "bob@hanzo.ai", "pw")
	cookie := signInOn(t, app, "", "alice")
	return app, db, signInOn(t, app, cookie, "bob")
}

// accountsOn reads GET /v1/iam/accounts as the browser carrying cookie.
func accountsOn(t *testing.T, app *zip.App, cookie string) []map[string]any {
	t.Helper()
	req := formReqNoBody("GET", PathAccounts)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, body := do(t, app, req)
	env := decode(t, body)
	if resp.StatusCode != 200 || env["status"] != "ok" {
		t.Fatalf("accounts: status=%d body=%s", resp.StatusCode, body)
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Errorf("accounts must not be cached, Cache-Control=%q", resp.Header.Get("Cache-Control"))
	}
	raw, _ := env["data"].([]any)
	out := make([]map[string]any, len(raw))
	for i, v := range raw {
		out[i], _ = v.(map[string]any)
	}
	return out
}

func TestAccounts_ListsEveryoneSignedInHere(t *testing.T) {
	app, _, cookie := twoPeople(t)

	got := accountsOn(t, app, cookie)
	if len(got) != 2 || got[0]["name"] != "bob" || got[1]["name"] != "alice" {
		t.Fatalf("accounts = %v, want bob then alice", got)
	}
	if got[1]["email"] != "alice@hanzo.ai" || got[1]["displayName"] != "Alice Example" || got[1]["sub"] == "" {
		t.Fatalf("alice is not recognisable in the chooser: %v", got[1])
	}
	for _, a := range got {
		for _, secret := range []string{"password", "passwordHash", "accessSecret", "totpSecret"} {
			if _, leaked := a[secret]; leaked {
				t.Fatalf("accounts leaked %s: %v", secret, a)
			}
		}
	}

	if none := accountsOn(t, app, ""); len(none) != 0 {
		t.Fatalf("a browser with nobody signed in lists %v", none)
	}
}

func TestSilent_LoginHintPicksAmongTheAccounts(t *testing.T) {
	app, db, cookie := twoPeople(t)

	cases := []struct{ hint, want string }{
		{"", "bob"},
		{"alice@hanzo.ai", "alice"},
		{"ALICE@hanzo.ai", "alice"},
		{"alice", "alice"},
		{"bob@hanzo.ai", "bob"},
	}
	for _, tc := range cases {
		t.Run("hint="+tc.hint, func(t *testing.T) {
			verifier := "verifier-login-hint-0123456789012345678901234567890123"
			q := silentQuery(verifier)
			if tc.hint != "" {
				q.Set("login_hint", tc.hint)
			}
			code := codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect))
			resp, env := exchangeCode(t, app, url.Values{
				"code": {code}, "client_id": {"second"}, "redirect_uri": {secondRedirect}, "code_verifier": {verifier},
			})
			if resp.StatusCode != 200 {
				t.Fatalf("exchange: status=%d body=%v", resp.StatusCode, env)
			}
			if got := verifiedClaims(t, db, env["id_token"].(string)).Name; got != tc.want {
				t.Fatalf("login_hint %q signed in %q, want %q", tc.hint, got, tc.want)
			}
		})
	}
}

// A hint naming nobody signed in here is never answered with somebody who is.
// The page gets the hint so its form starts with that identifier.
func TestSilent_LoginHintNamingNobodyHereReachesThePage(t *testing.T) {
	app, _, cookie := twoPeople(t)

	q := silentQuery("verifier-hint-nobody-01234567890123456789012345678901")
	q.Set("login_hint", "carol@hanzo.ai")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), hostedLoginPath)
	u, _ := url.Parse(loc)
	if u.Query().Get("code") != "" {
		t.Fatalf("a code was issued for a person the hint did not name: %q", loc)
	}
	if got := u.Query().Get("login_hint"); got != "carol@hanzo.ai" {
		t.Fatalf("login_hint on the page = %q, want carol@hanzo.ai", got)
	}

	q.Set("prompt", "none")
	loc = requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
	if got, _ := url.Parse(loc); got.Query().Get("error") != errLoginRequired {
		t.Fatalf("prompt=none with an unknown hint = %q, want error=%s", loc, errLoginRequired)
	}
}

// id_token_hint picks the person it names even when they are not the most recent
// sign-in.
func TestSilent_IdTokenHintPicksAHeldPerson(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	seedUserInOrg(t, db, "hanzo", "bob", "bob@hanzo.ai", "pw")
	cookie := signInOn(t, app, signInOn(t, app, "", "alice"), "bob")

	verifier := "verifier-idhint-held-0123456789012345678901234567890123"
	q := silentQuery(verifier)
	q.Set("prompt", "none")
	q.Set("id_token_hint", idTokenFor(t, db, "hanzo", "alice", "second", -time.Hour))
	code := codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect))
	_, env := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"second"}, "redirect_uri": {secondRedirect}, "code_verifier": {verifier},
	})
	if got := verifiedClaims(t, db, env["id_token"].(string)).Name; got != "alice" {
		t.Fatalf("id_token_hint for alice signed in %q", got)
	}
}

// Logging out ends every account on the browser.
func TestLogout_EndsEveryAccountHere(t *testing.T) {
	app, _, cookie := twoPeople(t)

	req := formReqNoBody("GET", PathLogout)
	req.Header.Set("Cookie", cookie)
	do(t, app, req)

	if left := accountsOn(t, app, cookie); len(left) != 0 {
		t.Fatalf("after logout the old cookie still lists %v", left)
	}
}

// A sign-in posted from another site, or from a sibling host, completes for the
// caller and adds nobody to the browser: the person it names does not move in
// front of the people already signed in here.
func TestLogin_FromElsewhereSignsNobodyInHere(t *testing.T) {
	app, _, cookie := twoPeople(t)
	for _, site := range []string{"cross-site", "same-site"} {
		t.Run(site, func(t *testing.T) {
			form := url.Values{
				"organization": {"hanzo"}, "application": {"portal"},
				"username": {"alice"}, "password": {"pw"}, "type": {"login"},
			}
			req := formReq("POST", PathLogin, form)
			req.Header.Set("Cookie", cookie)
			req.Header.Set("Sec-Fetch-Site", site)
			resp, body := do(t, app, req)
			if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
				t.Fatalf("the sign-in itself must still answer: status=%d body=%s", resp.StatusCode, body)
			}
			if set := resp.Header.Get("Set-Cookie"); strings.HasPrefix(set, sessions.CookieName+"=") {
				t.Fatalf("a %s post wrote the session cookie: %q", site, set)
			}
			if got := accountsOn(t, app, cookie); len(got) != 2 || got[0]["name"] != "bob" {
				t.Fatalf("accounts = %v, want bob still first", got)
			}
		})
	}
}
