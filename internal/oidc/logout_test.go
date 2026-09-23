// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/sessions"
)

// signIn drives a bare portal sign-in and returns the "name=value" session cookie.
func signIn(t *testing.T, app *zip.App, application string) string {
	t.Helper()
	form := url.Values{
		"organization": {"hanzo"}, "application": {application},
		"username": {"alice"}, "password": {"pw"}, "type": {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("sign-in failed: status=%d body=%s", resp.StatusCode, body)
	}
	cookie := cookieKV(resp.Header.Get("Set-Cookie"))
	if !strings.HasPrefix(cookie, sessions.CookieName+"=") || len(cookie) < len(sessions.CookieName)+9 {
		t.Fatalf("sign-in set no usable session cookie: %q", cookie)
	}
	return cookie
}

// sessionLives reports whether a session cookie still authenticates. get-account
// resolves the caller FROM the cookie, so it answers the only question a logout
// test actually cares about: is this credential still good?
func sessionLives(t *testing.T, app *zip.App, cookie string) bool {
	t.Helper()
	req := formReqNoBody("GET", PathAccount)
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	return resp.StatusCode == 200 && decode(t, body)["status"] == "ok"
}

// signInFor is the hosted sign-in page a GET logout lands on when no registered
// return address is named: the issuer's own /login, for the application when one
// was identified.
func signInFor(clientID string) string {
	page := Issuer("hanzo.id") + PathSignIn
	if clientID != "" {
		page += "?client_id=" + clientID
	}
	return page
}

// requireSignedOut asserts the answer is a 302 to exactly the sign-in page.
func requireSignedOut(t *testing.T, resp *http.Response, clientID string) {
	t.Helper()
	if loc := resp.Header.Get("Location"); resp.StatusCode != 302 || loc != signInFor(clientID) {
		t.Fatalf("logout: status=%d Location=%q, want 302 to %q", resp.StatusCode, loc, signInFor(clientID))
	}
}

// logout calls the endpoint with an optional session cookie and Accept header.
func logout(t *testing.T, app *zip.App, cookie, accept, query string) *http.Response {
	t.Helper()
	path := PathLogout
	if query != "" {
		path += "?" + query
	}
	req := formReqNoBody("GET", path)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	resp, _ := do(t, app, req)
	return resp
}

// THE regression this endpoint shipped: logout answered {"status":"ok"} while
// destroying nothing — no session ended, no token revoked. A logout that reports
// success on a live session is worse than none, because the person on the shared
// machine believes it worked.
//
// The assertion that matters is the CAPTURED cookie, not the response header:
// expiring the cookie in the browser is cosmetic if the value still authenticates,
// and an attacker who copied it never runs the browser's expiry.
func TestLogout_EndsTheSession(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	stolen := signIn(t, app, "conf")
	if !sessionLives(t, app, stolen) {
		t.Fatal("precondition: the session must authenticate before logout")
	}

	resp := logout(t, app, stolen, "", "")
	requireSignedOut(t, resp, "")

	// The load-bearing half: the session is dead SERVER-side.
	if sessionLives(t, app, stolen) {
		t.Fatal("logout reported success but the session still authenticates — nothing was revoked")
	}

	// And the browser is told to drop it.
	if sc := resp.Header.Get("Set-Cookie"); !strings.Contains(sc, sessions.CookieName+"=;") {
		t.Errorf("logout did not expire the session cookie: %q", sc)
	}
}

// Logging out twice, or with no session at all, is a no-op that still answers
// success — revocation is idempotent and must never error.
func TestLogout_IdempotentAndAnonymousSafe(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	requireSignedOut(t, logout(t, app, "", "", ""), "")
	cookie := signIn(t, app, "conf")
	requireSignedOut(t, logout(t, app, cookie, "", ""), "")
	requireSignedOut(t, logout(t, app, cookie, "", ""), "")
	if sessionLives(t, app, cookie) {
		t.Fatal("session survived a repeated logout")
	}
}

// One person's logout must not sign out another's session.
func TestLogout_DoesNotTouchAnotherSession(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	keep := signIn(t, app, "conf")
	drop := signIn(t, app, "conf")
	logout(t, app, drop, "", "")

	if sessionLives(t, app, drop) {
		t.Fatal("the logged-out session still authenticates")
	}
	if !sessionLives(t, app, keep) {
		t.Fatal("logout revoked a DIFFERENT session — revocation is not scoped to the presented sid")
	}
}

// Logout revokes the relying party's refresh token. A JWT's `exp` still reads
// valid for days, so expiry is necessary but never sufficient: revocation state
// is the authority, and the refresh must stop minting the moment the human leaves.
func TestLogout_RevokesRefreshToken(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedRichUser(t, db)

	code, _, _ := loginForCode(t, app, loginParams("conf", "openid offline_access"))
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	refreshTok, _ := tok["refresh_token"].(string)
	idToken, _ := tok["id_token"].(string)
	if refreshTok == "" || idToken == "" {
		t.Fatalf("need a refresh token and id_token to test revocation: %v", tok)
	}
	// Precondition: it mints. This ROTATES, so the token to test after logout is
	// the one this returns — asserting on the presented token instead would pass
	// on reuse-detection alone and prove nothing about revocation.
	status, out := refresh(t, app, "conf", refreshTok, url.Values{"client_secret": {"s3cret"}})
	if status != 200 {
		t.Fatalf("precondition: refresh must work before logout: status=%d %v", status, out)
	}
	live, _ := out["refresh_token"].(string)
	if live == "" || live == refreshTok {
		t.Fatalf("precondition: refresh must rotate: %v", out)
	}

	// A live session is required to revoke — an id_token_hint is not proof of
	// present possession, so hint alone must never let a stranger kill a grant.
	cookie := signIn(t, app, "conf")
	q := url.Values{"id_token_hint": {idToken}}.Encode()
	requireSignedOut(t, logout(t, app, cookie, "", q), "conf")

	liveAccess, _ := out["access_token"].(string)
	status, out = refresh(t, app, "conf", live, url.Values{"client_secret": {"s3cret"}})
	if status == 200 {
		t.Fatalf("refresh token still mints after logout — the grant was not revoked: %v", out)
	}
	requireBearerDead(t, app, liveAccess)
}

// requireBearerDead asserts an access token no longer resolves at userinfo.
func requireBearerDead(t *testing.T, app *zip.App, access string) {
	t.Helper()
	req := formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+access)
	if resp, _ := do(t, app, req); resp.StatusCode == 200 {
		t.Fatal("the access token still resolves after logout — it was not revoked")
	}
}

// A relying party that navigates to logout with nothing but the browser's own
// session still leaves no spendable token behind: the grant retired is the one
// for the application the session was opened for. The client needs no separate
// revoke call before it navigates.
func TestLogout_WithoutHintRevokesTheSessionApplicationsTokens(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedRichUser(t, db)

	code, _, _ := loginForCode(t, app, loginParams("conf", "openid offline_access"))
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	access, _ := tok["access_token"].(string)
	refreshTok, _ := tok["refresh_token"].(string)
	if access == "" || refreshTok == "" {
		t.Fatalf("need an access and a refresh token: %v", tok)
	}

	requireSignedOut(t, logout(t, app, signIn(t, app, "conf"), "", ""), "")

	if status, out := refresh(t, app, "conf", refreshTok, url.Values{"client_secret": {"s3cret"}}); status == 200 {
		t.Fatalf("refresh token still mints after logout: %v", out)
	}
	requireBearerDead(t, app, access)
}

// An id_token_hint is a token, not a proof of present possession. Revoking on a
// hint ALONE would let anyone holding an old id_token tear down that user's
// grant: a denial of service. A session must back it.
func TestLogout_HintAloneDoesNotRevoke(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedRichUser(t, db)

	code, _, _ := loginForCode(t, app, loginParams("conf", "openid offline_access"))
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	refreshTok, _ := tok["refresh_token"].(string)
	idToken, _ := tok["id_token"].(string)

	// No session cookie — an attacker replaying a captured id_token.
	q := url.Values{"id_token_hint": {idToken}}.Encode()
	logout(t, app, "", "", q)

	if status, out := refresh(t, app, "conf", refreshTok, url.Values{"client_secret": {"s3cret"}}); status != 200 {
		t.Fatalf("a bare id_token_hint revoked someone's grant: status=%d %v", status, out)
	}
}

// A GET is the end-session navigation, so it always lands on a page — whatever
// it Accepts, because a browser following a link, a window.location assignment
// and curl all send something different. A POST is how a program signs out, and
// it keeps the JSON envelope it parses unless it is a form asking for HTML.
func TestLogout_NavigationAndAPI(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	for name, accept := range map[string]string{
		"browser":       "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"no preference": "",
		"any":           "*/*",
		"json":          "application/json",
	} {
		t.Run("GET "+name+" lands on the sign-in page", func(t *testing.T) {
			requireSignedOut(t, logout(t, app, signIn(t, app, "conf"), accept, ""), "")
		})
	}

	post := func(accept, requestedWith string) *http.Response {
		req := formReq("POST", PathLogout, url.Values{})
		req.Header.Set("Cookie", signIn(t, app, "conf"))
		if accept != "" {
			req.Header.Set("Accept", accept)
		}
		if requestedWith != "" {
			req.Header.Set("X-Requested-With", requestedWith)
		}
		resp, _ := do(t, app, req)
		return resp
	}

	t.Run("POST form asking for html lands on the sign-in page", func(t *testing.T) {
		requireSignedOut(t, post("text/html", ""), "")
	})
	for name, h := range map[string][2]string{
		"json":                     {"application/json", ""},
		"no preference":            {"*/*", ""},
		"XHR even asking for html": {"text/html", "XMLHttpRequest"},
	} {
		t.Run("POST "+name+" keeps JSON", func(t *testing.T) {
			resp := post(h[0], h[1])
			if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
				t.Fatalf("a program's POST must not be redirected: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
			}
		})
	}
}

// Content negotiation must not become an open redirect: a browser asking for HTML
// with an UNREGISTERED post_logout_redirect_uri still lands on our own page.
func TestLogout_BrowserRedirectStillGuarded(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	q := url.Values{
		"post_logout_redirect_uri": {"https://evil.example/x"},
		"id_token_hint":            {idTokenHint(t, app)},
	}.Encode()
	requireSignedOut(t, logout(t, app, signIn(t, app, "conf"), "text/html", q), "conf")
}

// idTokenHint runs the confidential flow and returns a verifiable id_token.
func idTokenHint(t *testing.T, app *zip.App) string {
	t.Helper()
	code, _, _ := loginForCode(t, app, loginParams("conf", "openid"))
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	idt, _ := tok["id_token"].(string)
	if idt == "" {
		t.Fatal("no id_token issued")
	}
	return idt
}

// Logout only redirects to a post_logout_redirect_uri that is registered by the
// client named in a signature-verified id_token_hint — never an open redirect.
func TestLogout_RedirectSafety(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	t.Run("no redirect param lands on the sign-in page", func(t *testing.T) {
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout))
		requireSignedOut(t, resp, "")
	})

	t.Run("redirect without hint is refused (no open redirect)", func(t *testing.T) {
		q := url.Values{"post_logout_redirect_uri": {"https://evil.example/x"}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		requireSignedOut(t, resp, "")
	})

	t.Run("verified hint but unregistered redirect is refused", func(t *testing.T) {
		q := url.Values{"post_logout_redirect_uri": {"https://evil.example/x"}, "id_token_hint": {idTokenHint(t, app)}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		requireSignedOut(t, resp, "conf")
	})

	// What a relying party that returns people to its own front page sends: its
	// origin, which it never registered. The person lands on the sign-in page for
	// that application, not on a JSON body.
	t.Run("client_id with an unregistered return lands on its sign-in page", func(t *testing.T) {
		q := url.Values{"client_id": {"conf"}, "post_logout_redirect_uri": {"https://app.example/"}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		requireSignedOut(t, resp, "conf")
	})

	t.Run("client_id with a registered return is honored", func(t *testing.T) {
		q := url.Values{"client_id": {"conf"}, "post_logout_redirect_uri": {testRedirect}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		if loc := resp.Header.Get("Location"); resp.StatusCode != 302 || loc != testRedirect {
			t.Fatalf("status=%d loc=%q, want 302 to %q", resp.StatusCode, loc, testRedirect)
		}
	})

	t.Run("verified hint + registered redirect is honored", func(t *testing.T) {
		q := url.Values{"post_logout_redirect_uri": {testRedirect}, "id_token_hint": {idTokenHint(t, app)}, "state": {"s-9"}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		loc := requireRedirect(t, resp, testRedirect)
		if !strings.Contains(loc, "state=s-9") {
			t.Fatalf("state not echoed: %q", loc)
		}
	})

	// The hint a relying party actually holds. An id token is short next to the
	// session it describes — a refresh renews the access token and leaves the id
	// token as first issued — so a browser signed in for any length of time sends
	// an expired one. It still names the application, which is all the redirect
	// asks of it, and the signature is still what makes it trustworthy.
	t.Run("expired hint still names the application", func(t *testing.T) {
		q := url.Values{
			"post_logout_redirect_uri": {testRedirect},
			"id_token_hint":            {idTokenFor(t, db, "hanzo", "alice", "conf", -time.Hour)},
		}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		requireRedirect(t, resp, testRedirect)
	})
}
