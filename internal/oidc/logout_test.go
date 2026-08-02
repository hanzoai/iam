// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/zap-proto/zip"
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
	if !strings.HasPrefix(cookie, "hanzo_session=") || len(cookie) < len("hanzo_session=")+8 {
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
	if resp.StatusCode != 200 {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}

	// The load-bearing half: the session is dead SERVER-side.
	if sessionLives(t, app, stolen) {
		t.Fatal("logout reported success but the session still authenticates — nothing was revoked")
	}

	// And the browser is told to drop it.
	if sc := resp.Header.Get("Set-Cookie"); !strings.Contains(sc, "hanzo_session=;") {
		t.Errorf("logout did not expire the session cookie: %q", sc)
	}
}

// Logging out twice, or with no session at all, is a no-op that still answers
// success — revocation is idempotent and must never error.
func TestLogout_IdempotentAndAnonymousSafe(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	if resp := logout(t, app, "", "", ""); resp.StatusCode != 200 {
		t.Fatalf("anonymous logout status = %d", resp.StatusCode)
	}
	cookie := signIn(t, app, "conf")
	if resp := logout(t, app, cookie, "", ""); resp.StatusCode != 200 {
		t.Fatalf("first logout status = %d", resp.StatusCode)
	}
	if resp := logout(t, app, cookie, "", ""); resp.StatusCode != 200 {
		t.Fatalf("second logout status = %d", resp.StatusCode)
	}
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
	if resp := logout(t, app, cookie, "", q); resp.StatusCode != 200 {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}

	status, out = refresh(t, app, "conf", live, url.Values{"client_secret": {"s3cret"}})
	if status == 200 {
		t.Fatalf("refresh token still mints after logout — the grant was not revoked: %v", out)
	}
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

// A browser navigating to logout gets a page it can read; an API caller keeps the
// JSON envelope it parses. The old handler returned raw JSON to everyone, so a
// person who clicked "sign out" saw {"status":"ok"} on a blank page and could not
// tell whether it had worked.
func TestLogout_ContentNegotiation(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	t.Run("browser navigation lands on a page", func(t *testing.T) {
		resp := logout(t, app, signIn(t, app, "conf"), "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "")
		loc := resp.Header.Get("Location")
		if resp.StatusCode != 302 || !strings.Contains(loc, PathSignedOut) {
			t.Fatalf("browser logout must land on a signed-out page: status=%d loc=%q", resp.StatusCode, loc)
		}
	})

	t.Run("API caller keeps JSON", func(t *testing.T) {
		resp := logout(t, app, signIn(t, app, "conf"), "application/json", "")
		if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
			t.Fatalf("json caller must not be redirected: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("XHR keeps JSON even asking for html", func(t *testing.T) {
		req := formReqNoBody("GET", PathLogout)
		req.Header.Set("Cookie", signIn(t, app, "conf"))
		req.Header.Set("Accept", "text/html")
		req.Header.Set("X-Requested-With", "XMLHttpRequest")
		resp, _ := do(t, app, req)
		if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
			t.Fatalf("XHR must not be redirected: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("no preference keeps JSON (the existing contract)", func(t *testing.T) {
		resp := logout(t, app, signIn(t, app, "conf"), "*/*", "")
		if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
			t.Fatalf("default must stay JSON: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})
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
	resp := logout(t, app, signIn(t, app, "conf"), "text/html", q)
	loc := resp.Header.Get("Location")
	if strings.Contains(loc, "evil.example") {
		t.Fatalf("browser logout followed an unregistered redirect: %q", loc)
	}
	if resp.StatusCode != 302 || !strings.Contains(loc, PathSignedOut) {
		t.Fatalf("expected the signed-out page, got status=%d loc=%q", resp.StatusCode, loc)
	}
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

	t.Run("no redirect param → 200", func(t *testing.T) {
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout))
		if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
			t.Fatalf("status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("redirect without hint is refused (no open redirect)", func(t *testing.T) {
		q := url.Values{"post_logout_redirect_uri": {"https://evil.example/x"}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
			t.Fatalf("must not redirect without a verified hint: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("verified hint but unregistered redirect is refused", func(t *testing.T) {
		q := url.Values{"post_logout_redirect_uri": {"https://evil.example/x"}, "id_token_hint": {idTokenHint(t, app)}}
		resp, _ := do(t, app, formReqNoBody("GET", PathLogout+"?"+q.Encode()))
		if resp.StatusCode != 200 || resp.Header.Get("Location") != "" {
			t.Fatalf("unregistered redirect must be refused: status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
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
}
