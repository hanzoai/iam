// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// A write the session cookie authorizes is made only on a request no other page
// could have sent (sessions.Forgeable): the issuer's own page, as JSON. The cookie
// is SameSite=Lax, so once the identity host shares a site with other hosts, any
// page on that site can post a form here and the browser attaches it.

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/store"
)

// A device approval needs no answer read, so a form is the whole attack: a page on
// any host of the identity host's site approves the attacker's `hanzo login` code
// and the attacker's terminal is signed in as the victim.
func TestDevice_ApprovalIsMadeOnlyFromTheIssuersOwnPage(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	seedDeviceApp(t, db, "hanzo-app")
	_, da := requestDevice(t, app, "hanzo-app", "openid profile")
	deviceCode, userCode := da["device_code"].(string), da["user_code"].(string)
	cookie := sessionCookieFor(t, app)

	form := func() *http.Request {
		return formReq("POST", PathLogin, url.Values{"type": {"device"}, "userCode": {userCode}})
	}
	plain := func() *http.Request {
		req := jsonReq("POST", PathLogin, map[string]string{"type": "device", "userCode": userCode})
		req.Header.Set("Content-Type", "text/plain")
		return req
	}
	json := func() *http.Request {
		return jsonReq("POST", PathLogin, map[string]string{"type": "device", "userCode": userCode})
	}
	approve := func(req *http.Request, site string) int {
		req.Header.Set("Cookie", cookie)
		switch {
		case strings.HasPrefix(site, "origin "):
			req.Header.Set("Origin", strings.TrimPrefix(site, "origin "))
		case site != "":
			req.Header.Set("Sec-Fetch-Site", site)
		}
		resp, _ := do(t, app, req)
		return resp.StatusCode
	}
	approver := func() string {
		row, err := store.GetTokenByCode(tctx(), db, deviceCode)
		if err != nil || row == nil {
			t.Fatalf("the pending device code is gone: %v", err)
		}
		return row.User
	}

	// A text/plain body is one no binder reads, so it is refused (400) before the
	// cookie is reached; every other shape reaches the cookie and is refused 403.
	for _, tc := range []struct {
		name   string
		req    func() *http.Request
		site   string
		status int
	}{
		{"a form posted from another site", form, "cross-site", http.StatusForbidden},
		{"a form posted from a sibling host", form, "same-site", http.StatusForbidden},
		{"a form on the issuer's own page", form, "same-origin", http.StatusForbidden},
		{"JSON from a sibling host", json, "same-site", http.StatusForbidden},
		{"JSON from a sibling host with no fetch metadata", json, "origin https://chat.hanzo.id", http.StatusForbidden},
		{"a form from the issuer's own page with no fetch metadata", form, "origin https://hanzo.id", http.StatusForbidden},
		{"a text/plain form carrying JSON", plain, "same-site", http.StatusBadRequest},
		{"a text/plain body from the issuer's own page", plain, "same-origin", http.StatusBadRequest},
	} {
		if status := approve(tc.req(), tc.site); status != tc.status || approver() != "" {
			t.Fatalf("%s: status=%d approver=%q, want %d and the device still pending", tc.name, status, approver(), tc.status)
		}
	}
	if status := approve(json(), "same-origin"); status != 200 || approver() != "hanzo/alice" {
		t.Fatalf("the approval page: status=%d approver=%q, want 200 and hanzo/alice", status, approver())
	}
}

// A browser that sends no Fetch Metadata (Safari before 16.4, Firefox before 90,
// a proxy that strips it) is judged by Origin, so the issuer's own page still
// approves a device.
func TestDevice_ApprovalWithoutFetchMetadata(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	seedDeviceApp(t, db, "hanzo-app")
	_, da := requestDevice(t, app, "hanzo-app", "openid profile")
	req := jsonReq("POST", PathLogin, map[string]string{"type": "device", "userCode": da["user_code"].(string)})
	req.Header.Set("Cookie", sessionCookieFor(t, app))
	req.Header.Set("Origin", "https://hanzo.id")
	if resp, body := do(t, app, req); resp.StatusCode != 200 {
		t.Fatalf("the approval page on an old browser: status=%d %s, want 200", resp.StatusCode, body)
	}
	if row, _ := store.GetTokenByCode(tctx(), db, da["device_code"].(string)); row == nil || row.User != "hanzo/alice" {
		t.Fatalf("the device was not approved: %+v", row)
	}
}

// Every other write on the cookie's authority asks the same rule: a sibling host's
// JSON and the issuer's own page's form are both refused, before the handler reads
// anything.
func TestCookieWrites_AllAskTheSameRule(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := sessionCookieFor(t, app)

	for _, w := range []struct{ method, path, body string }{
		{"PUT", PathAccount, `{"displayName":"Mallory"}`},
		{"PUT", PathPassword, `{"oldPassword":"pw","password":"N3w-passw0rd-long"}`},
		{"PUT", PathTerms, `{"terms":"t2","aup":"a2"}`},
		{"PUT", PathConsent, `{"insights":true}`},
		{"POST", PathPreferences, `{"theme":"dark"}`},
		{"POST", PathOnboard, `{"name":"Mallory Inc"}`},
		{"POST", PathLink, `{"provider":"provider-github","clientId":"conf","returnUri":"` + testRedirect + `"}`},
		{"POST", PathUnlink, `{"providerType":"github","user":{"owner":"hanzo","name":"alice"}}`},
		{"POST", PathWebauthnRegisterFinish, `{}`},
		{"POST", PathInvitationsAccept, `{"owner":"acme","code":"LINKCODE22"}`},
	} {
		for _, sent := range []struct{ site, origin, contentType string }{
			{"same-site", "", "application/json"},
			{"same-origin", "", "application/x-www-form-urlencoded"},
			{"", "https://chat.hanzo.id", "application/json"},
			{"", "https://hanzo.id", "application/x-www-form-urlencoded"},
		} {
			req := httptest.NewRequest(w.method, w.path, strings.NewReader(w.body))
			req.Host = "hanzo.id"
			req.Header.Set("Content-Type", sent.contentType)
			req.Header.Set("Cookie", cookie)
			if sent.site != "" {
				req.Header.Set("Sec-Fetch-Site", sent.site)
			}
			if sent.origin != "" {
				req.Header.Set("Origin", sent.origin)
			}
			resp, body := do(t, app, req)
			if resp.StatusCode != http.StatusForbidden || !strings.Contains(string(body), sessions.ErrForgeable.Error()) {
				t.Errorf("%s %s (site %q, origin %q, %s): status=%d %s, want 403", w.method, w.path, sent.site, sent.origin, sent.contentType, resp.StatusCode, body)
			}
		}
	}

	// A GET carries no body, so the passkey ceremony's start is judged by the site.
	req := formReqNoBody("GET", PathWebauthnRegisterBegin)
	req.Header.Set("Cookie", cookie)
	req.Header.Set("Sec-Fetch-Site", "same-site")
	if resp, body := do(t, app, req); resp.StatusCode != http.StatusForbidden {
		t.Errorf("a sibling host began a passkey enrollment: status=%d %s, want 403", resp.StatusCode, body)
	}
	if u, _ := store.GetUserByName(tctx(), db, "hanzo", "alice"); u == nil || u.DisplayName == "Mallory" {
		t.Fatalf("a refused write still changed the account: %+v", u)
	}
}

// A client that is not a browser sends no fetch metadata and authenticates with a
// bearer, which no page can make a browser attach. It is untouched — with or
// without a cookie riding along.
func TestCookieWrites_ABearerNeedsNoFetchMetadata(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	access := accessTokenFor(t, app, "openid")
	cookie := sessionCookieFor(t, app)

	for _, withCookie := range []bool{false, true} {
		req := jsonReq("PUT", PathConsent, map[string]any{"insights": withCookie})
		req.Header.Set("Authorization", "Bearer "+access)
		if withCookie {
			req.Header.Set("Cookie", cookie)
		}
		resp, body := do(t, app, req)
		if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
			t.Fatalf("a bearer client (cookie %v) was refused: status=%d %s", withCookie, resp.StatusCode, body)
		}
	}
	if got := consentOnRow(t, db); !got.Insights {
		t.Fatalf("the bearer's consent did not land: %+v", got)
	}
}

// Signing out ends sessions, so it is a write too, judged by its own rule: only
// what the browser says another page sent without navigating here — an image, a
// frame, a script's fetch — ends nothing.
func TestLogout_OnlyANavigationOrTheIssuersPageSignsOut(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := signIn(t, app, "conf")

	image := formReqNoBody("GET", PathLogout)
	image.Header.Set("Sec-Fetch-Site", "same-site")
	image.Header.Set("Sec-Fetch-Mode", "no-cors")
	image.Header.Set("Sec-Fetch-Dest", "image")
	frame := navigate(formReqNoBody("GET", PathLogout))
	frame.Header.Set("Sec-Fetch-Dest", "iframe")
	fetch := formReq("POST", PathLogout, url.Values{})
	fetch.Header.Set("Sec-Fetch-Site", "same-site")
	fetch.Header.Set("Sec-Fetch-Mode", "no-cors")
	fetch.Header.Set("Sec-Fetch-Dest", "empty")
	for name, req := range map[string]*http.Request{"an image": image, "a frame": frame, "a sibling's fetch": fetch} {
		req.Header.Set("Cookie", cookie)
		if resp, _ := do(t, app, req); resp.StatusCode != http.StatusForbidden || !sessionLives(t, app, cookie) {
			t.Fatalf("%s: status=%d, want 403 and the session alive", name, resp.StatusCode)
		}
	}

	requireSignedOut(t, logout(t, app, cookie, "", ""), "")
	if sessionLives(t, app, cookie) {
		t.Fatal("a relying party's sign-out navigation left the session alive")
	}
}

// Every way a person actually signs out ends the session: the SDKs' sign-out
// (@hanzo/iam end(), iam-sdk logout()) posts a form, or nothing, from the issuer's
// own page; a relying party posts its sign-out form (RP-Initiated Logout 1.0 §2);
// and a browser with no Fetch Metadata cannot say which it is, so it is believed.
func TestLogout_EverySignOutEndsTheSession(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	end := func() *http.Request {
		req := formReq("POST", PathLogout, url.Values{"client_id": {"conf"}})
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		return req
	}
	bodyless := func() *http.Request {
		req := formReqNoBody("POST", PathLogout)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.Header.Set("Sec-Fetch-Mode", "cors")
		req.Header.Set("Sec-Fetch-Dest", "empty")
		return req
	}
	rpForm := func() *http.Request {
		req := formReq("POST", PathLogout, url.Values{"client_id": {"conf"}})
		req.Header.Set("Sec-Fetch-Site", "same-site")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Dest", "document")
		return req
	}
	oldBrowser := func() *http.Request {
		req := formReq("POST", PathLogout, url.Values{"client_id": {"conf"}})
		req.Header.Set("Origin", "https://hanzo.id")
		return req
	}
	oldNavigation := func() *http.Request { return formReqNoBody("GET", PathLogout) }

	for name, req := range map[string]func() *http.Request{
		"@hanzo/iam end()":                 end,
		"a bodyless POST from the page":    bodyless,
		"a sibling relying party's form":   rpForm,
		"a browser with no fetch metadata": oldBrowser,
		"an old browser's sign-out link":   oldNavigation,
	} {
		t.Run(name, func(t *testing.T) {
			cookie := signIn(t, app, "conf")
			r := req()
			r.Header.Set("Cookie", cookie)
			resp, body := do(t, app, r)
			if resp.StatusCode >= 400 {
				t.Fatalf("status=%d %s, want the session ended", resp.StatusCode, body)
			}
			if sessionLives(t, app, cookie) {
				t.Fatal("the session still authenticates")
			}
			if sc := resp.Header.Get("Set-Cookie"); !strings.Contains(sc, sessions.CookieName+"=;") {
				t.Errorf("the session cookie was not expired: %q", sc)
			}
		})
	}
}

// SameSite=Lax keeps the session cookie off a form another site posts, so a
// relying party's cross-site sign-out form reaches here with no cookie. It is sent
// back as a GET with its parameters, which the cookie rides on, and that GET ends
// the session and returns to the registered address.
func TestLogout_ACrossSiteFormComesBackAsANavigation(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	cookie := signIn(t, app, "conf")

	form := url.Values{"client_id": {"conf"}, "post_logout_redirect_uri": {testRedirect}, "state": {"s1"}}
	req := formReq("POST", PathLogout, form)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	resp, _ := do(t, app, req)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(loc, PathLogout+"?") {
		t.Fatalf("a cookieless cross-site form: status=%d Location=%q, want 303 back to %s", resp.StatusCode, loc, PathLogout)
	}
	if got, _ := url.Parse(loc); got.Query().Encode() != form.Encode() {
		t.Fatalf("the GET dropped parameters: %q, want %q", got.RawQuery, form.Encode())
	}
	if !sessionLives(t, app, cookie) {
		t.Fatal("precondition: nothing is ended before the browser comes back")
	}
	framed := formReq("POST", PathLogout, form)
	framed.Header.Set("Sec-Fetch-Site", "cross-site")
	framed.Header.Set("Sec-Fetch-Mode", "navigate")
	framed.Header.Set("Sec-Fetch-Dest", "iframe")
	if resp, _ := do(t, app, framed); resp.StatusCode == http.StatusSeeOther {
		t.Fatal("a form posted into a frame was sent back, where no cookie rides either")
	}

	again := navigate(formReqNoBody("GET", loc))
	again.Header.Set("Cookie", cookie)
	resp, _ = do(t, app, again)
	if resp.StatusCode != 302 || !strings.HasPrefix(resp.Header.Get("Location"), testRedirect) {
		t.Fatalf("the navigation back: status=%d Location=%q, want 302 to %s", resp.StatusCode, resp.Header.Get("Location"), testRedirect)
	}
	if sessionLives(t, app, cookie) {
		t.Fatal("the relying party's sign-out left the session alive")
	}
}
