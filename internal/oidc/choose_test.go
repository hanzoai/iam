// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
)

// Which account a sign-in is for is the person's choice whenever more than one
// is signed in on the browser: authorize, the session branch of the login
// endpoint, the account switch and the sign-out of one account.

// subOf is the subject GET /v1/iam/accounts names username by on this browser.
func subOf(t *testing.T, app *zip.App, cookie, username string) string {
	t.Helper()
	for _, a := range accountsOn(t, app, cookie) {
		if a["name"] == username {
			return a["sub"].(string)
		}
	}
	t.Fatalf("%s is not signed in on this browser", username)
	return ""
}

// names lists the usernames GET /v1/iam/accounts answers, in order.
func namesOn(t *testing.T, app *zip.App, cookie string) string {
	t.Helper()
	var out []string
	for _, a := range accountsOn(t, app, cookie) {
		out = append(out, a["name"].(string))
	}
	return strings.Join(out, ",")
}

// With two people signed in and nothing naming one, authorize answers nobody: the
// hosted page is asked for the chooser, and no code is minted.
func TestChoose_TwoAccountsAndNoHintAskTheChooser(t *testing.T) {
	app, _, cookie := twoPeople(t)

	loc := requireRedirect(t, authorizeWith(t, app, silentQuery("verifier-choose-two-0123456789012345678901234567"), cookie, nil), hostedLoginPath)
	page, _ := url.Parse(loc)
	if page.Query().Get("code") != "" {
		t.Fatalf("a code was minted with two accounts and no choice: %q", loc)
	}
	if got := page.Query().Get("prompt"); got != promptSelectAccount {
		t.Fatalf("prompt on the page = %q, want %s so it draws the chooser", got, promptSelectAccount)
	}
}

// prompt=none allows no page, so two accounts and no hint is the spec's error
// (OIDC Core §3.1.2.6), on the client's redirect_uri, with its state.
func TestChoose_PromptNoneWithTwoAccountsIsAccountSelectionRequired(t *testing.T) {
	app, _, cookie := twoPeople(t)

	q := silentQuery("verifier-choose-none-012345678901234567890123456")
	q.Set("prompt", "none")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
	u, _ := url.Parse(loc)
	if u.Query().Get("error") != errAccountSelectionRequired || u.Query().Get("state") != "st-42" || u.Query().Get("code") != "" {
		t.Fatalf("prompt=none with two accounts = %q, want error=%s with the state", loc, errAccountSelectionRequired)
	}

	// A hint that names one of them is an answer, prompt=none or not.
	q.Set("login_hint", "alice@hanzo.ai")
	codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect))
}

// One account signed in still answers a plain authorize silently — single sign-on
// is unchanged — and select_account still asks, chooser and all.
func TestChoose_OneAccountIsSilentUnlessAskedToChoose(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signInOn(t, app, "", "alice")

	codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, silentQuery("verifier-choose-one-0123456789012345678901234567"), cookie, nil), secondRedirect))

	q := silentQuery("verifier-choose-one-select-012345678901234567890123")
	q.Set("prompt", promptSelectAccount)
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), hostedLoginPath)
	if u, _ := url.Parse(loc); u.Query().Get("code") != "" || u.Query().Get("prompt") != promptSelectAccount {
		t.Fatalf("select_account with one account = %q, want the chooser", loc)
	}
}

// sessionLogin posts the login endpoint's session branch as the issuer's own page
// does: no credential, the authorize request, and the chooser's answer.
func sessionLogin(t *testing.T, app *zip.App, cookie string, extra map[string]string) map[string]any {
	t.Helper()
	body := map[string]string{
		"type": "code", "clientId": "second", "redirectUri": secondRedirect, "state": "st-42", "scope": "openid profile email",
		"codeChallenge": pkce.Challenge("verifier-session-branch-012345678901234567890123"), "codeChallengeMethod": "S256",
	}
	for k, v := range extra {
		body[k] = v
	}
	req := fromPage(jsonReq("POST", PathLogin, body))
	req.Header.Set("Cookie", cookie)
	_, raw := do(t, app, req)
	return decode(t, raw)
}

// The session branch never guesses among several accounts, never answers a
// request that asked for a fresh credential or for a choice, and answers the
// account the page names.
func TestChoose_SessionBranchAnswersOnlyTheNamedAccount(t *testing.T) {
	app, db, cookie := twoPeople(t)
	alice := subOf(t, app, cookie, "alice")

	if env := sessionLogin(t, app, cookie, nil); env["status"] != "error" || env["code"] != CodeAccountSelectionRequired {
		t.Fatalf("two accounts and no hint = %v, want code %s", env, CodeAccountSelectionRequired)
	}
	if env := sessionLogin(t, app, cookie, map[string]string{"prompt": promptLogin, "loginHint": alice}); env["code"] != CodeLoginRequired {
		t.Fatalf("prompt=login answered from a session: %v", env)
	}
	if env := sessionLogin(t, app, cookie, map[string]string{"loginHint": "carol@hanzo.ai"}); env["code"] != CodeLoginRequired {
		t.Fatalf("a hint naming nobody here = %v, want code %s", env, CodeLoginRequired)
	}

	env := sessionLogin(t, app, cookie, map[string]string{"loginHint": alice, "prompt": promptSelectAccount})
	code, _ := env["data"].(string)
	if env["status"] != "ok" || code == "" {
		t.Fatalf("the chosen account was not answered: %v", env)
	}
	resp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"second"}, "redirect_uri": {secondRedirect},
		"code_verifier": {"verifier-session-branch-012345678901234567890123"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("exchange: %d %v", resp.StatusCode, tok)
	}
	if got := verifiedClaims(t, db, tok["id_token"].(string)).Name; got != "alice" {
		t.Fatalf("the code is for %q, want the chosen alice (bob signed in last)", got)
	}
}

// select_account with ONE account signed in is still owed the person's choice:
// the page's resume without a chosen account is refused, not answered silently.
func TestChoose_SessionBranchSelectAccountWithOneAccount(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signInOn(t, app, "", "alice")

	if env := sessionLogin(t, app, cookie, map[string]string{"prompt": promptSelectAccount}); env["code"] != CodeAccountSelectionRequired {
		t.Fatalf("select_account resumed without a choice: %v", env)
	}
	// The same request read off the query, as @hanzo/iam posts it.
	req := fromPage(jsonReq("POST", PathLogin+"?prompt=select_account&clientId=second&redirectUri="+url.QueryEscape(secondRedirect)+
		"&code_challenge="+pkce.Challenge("verifier-session-branch-012345678901234567890123"), map[string]string{"type": "code"}))
	req.Header.Set("Cookie", cookie)
	if _, raw := do(t, app, req); decode(t, raw)["code"] != CodeAccountSelectionRequired {
		t.Fatalf("prompt on the query was not read: %s", raw)
	}
	if env := sessionLogin(t, app, cookie, nil); env["status"] != "ok" {
		t.Fatalf("one account and no prompt must still be single sign-on: %v", env)
	}
}

// switchTo switches as the issuer's own page does.
func switchTo(t *testing.T, app *zip.App, cookie, sub string, headers ...string) (*http.Response, map[string]any) {
	t.Helper()
	req := fromPage(jsonReq("PUT", PathAccounts, map[string]string{"current": sub}))
	req.Header.Set("Cookie", cookie)
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	resp, raw := do(t, app, req)
	return resp, decode(t, raw)
}

// Switching makes a signed-in account current: the list leads with it and the
// account read answers it. Someone not signed in here cannot be switched to, and
// another page cannot switch for the person.
func TestAccounts_SwitchMakesASignedInAccountCurrent(t *testing.T) {
	app, _, cookie := twoPeople(t)
	alice := subOf(t, app, cookie, "alice")

	resp, env := switchTo(t, app, cookie, alice)
	if resp.StatusCode != 200 || env["status"] != "ok" {
		t.Fatalf("switch: %d %v", resp.StatusCode, env)
	}
	if list, _ := env["data"].([]any); len(list) != 2 || list[0].(map[string]any)["name"] != "alice" {
		t.Fatalf("the answer must lead with the account switched to: %v", env["data"])
	}
	switched := cookieKV(resp.Header.Get("Set-Cookie"))
	if !strings.HasPrefix(switched, sessions.CookieName+"=") {
		t.Fatal("a switch must rewrite the session cookie")
	}
	if got := namesOn(t, app, switched); got != "alice,bob" {
		t.Fatalf("accounts after the switch = %q, want alice,bob", got)
	}
	req := formReqNoBody("GET", PathAccount)
	req.Header.Set("Cookie", switched)
	if _, raw := do(t, app, req); decode(t, raw)["name"] != "alice" {
		t.Fatalf("the account read after a switch = %s, want alice", raw)
	}

	if resp, _ := switchTo(t, app, cookie, "hanzo/carol"); resp.StatusCode != 404 {
		t.Fatalf("switching to an account not signed in here: status %d, want 404", resp.StatusCode)
	}
	if resp, _ := switchTo(t, app, cookie, alice, "Sec-Fetch-Site", "same-site"); resp.StatusCode != 403 || resp.Header.Get("Set-Cookie") != "" {
		t.Fatalf("a sibling host switched the account: status %d", resp.StatusCode)
	}
	// Refused before anything is looked up, so another page cannot learn which
	// subjects are signed in here from a 404 against a 200.
	if resp, _ := switchTo(t, app, cookie, "hanzo/carol", "Sec-Fetch-Site", "same-site"); resp.StatusCode != 403 {
		t.Fatalf("a sibling host probing a subject got status %d, want 403", resp.StatusCode)
	}
}

// A SuperAdmin and a customer signed in on one browser stay two accounts. The
// switch moves which one a reader takes; it never lends the SuperAdmin's org to
// the customer: after switching to the customer, the account read says `hanzo`.
func TestAccounts_SwitchCarriesNoStandingAcross(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId, a.Organization, a.EnablePassword = "admin", "admin-portal", "admin-portal", "admin", true
	a.Cert = "cert-portal"
	a.SetId("admin/admin-portal")
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "pw")
	cookie := signInOn(t, app, "", "alice")
	form := url.Values{"organization": {"admin"}, "application": {"admin-portal"}, "username": {"root"}, "password": {"pw"}, "type": {"login"}}
	req := formReq("POST", PathLogin, form)
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("root sign-in: %s", body)
	}
	cookie = cookieKV(resp.Header.Get("Set-Cookie"))
	if got := namesOn(t, app, cookie); got != "root,alice" {
		t.Fatalf("accounts = %q, want root,alice", got)
	}

	resp, _ = switchTo(t, app, cookie, subOf(t, app, cookie, "alice"))
	switched := cookieKV(resp.Header.Get("Set-Cookie"))
	read := formReqNoBody("GET", PathAccount)
	read.Header.Set("Cookie", switched)
	_, raw := do(t, app, read)
	env := decode(t, raw)
	user, _ := env["data"].(map[string]any)
	if env["name"] != "alice" || user["owner"] != "hanzo" || user["isAdmin"] == true {
		t.Fatalf("after switching to alice the account read is %s, want hanzo/alice with no admin standing", raw)
	}
}

// Signing out one account leaves everyone else signed in on the browser.
func TestLogout_HintSignsOutOneAccount(t *testing.T) {
	app, _, cookie := twoPeople(t)

	resp := logout(t, app, cookie, "", url.Values{"logout_hint": {"alice@hanzo.ai"}}.Encode())
	if resp.StatusCode != 302 {
		t.Fatalf("logout: status %d", resp.StatusCode)
	}
	left := cookieKV(resp.Header.Get("Set-Cookie"))
	if got := namesOn(t, app, left); got != "bob" {
		t.Fatalf("after signing alice out the browser holds %q, want bob", got)
	}
	if got := namesOn(t, app, cookie); got != "bob" {
		t.Fatalf("alice's captured session still resolves: %q", got)
	}

	// A hint naming nobody here signs nobody out.
	resp = logout(t, app, left, "", url.Values{"logout_hint": {"carol@hanzo.ai"}}.Encode())
	if got := namesOn(t, app, left); got != "bob" || resp.StatusCode != 302 {
		t.Fatalf("a hint naming nobody signed out %q", got)
	}
}

// The issuer and its sign-in origin each hold their own session. A sign-out the
// browser navigates through visits the other origin, ends the same sessions there,
// and only the last hop returns the browser where the client asked.
func TestLogout_VisitsEachSigninOriginOnce(t *testing.T) {
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	app, db, cookie := twoPeople(t)
	seedApp(t, db, appOpts{clientID: "web", redirectURIs: []string{"https://web.example/bye"}})

	q := url.Values{"client_id": {"web"}, "post_logout_redirect_uri": {"https://web.example/bye"}, "state": {"s-1"}, "logout_hint": {"alice"}}
	resp := logout(t, app, cookie, "", q.Encode())
	next, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != 302 || next.Scheme+"://"+next.Host != "https://hanzo.ai" || next.Path != PathLogout {
		t.Fatalf("hanzo.id sign-out went to %q, want hanzo.ai's end-session", resp.Header.Get("Location"))
	}
	carried := next.Query()
	for _, k := range []string{"client_id", "post_logout_redirect_uri", "state", "logout_hint"} {
		if carried.Get(k) != q.Get(k) {
			t.Fatalf("%s was not carried to the next origin: %q", k, next)
		}
	}
	if !strings.HasPrefix(carried.Get("chain"), "https://hanzo.id~") {
		t.Fatalf("chain = %q, want the origin the sign-out started at, sealed", carried.Get("chain"))
	}
	if got := namesOn(t, app, cookie); got != "bob" {
		t.Fatalf("the first hop did not end alice here: %q", got)
	}

	// hanzo.ai, the last origin: it ends its own sessions and returns the browser.
	req := navigate(formReqNoBody("GET", next.RequestURI()))
	req.Host = "hanzo.ai"
	last, _ := do(t, app, req)
	if loc := last.Header.Get("Location"); last.StatusCode != 302 || loc != "https://web.example/bye?state=s-1" {
		t.Fatalf("the last hop answered %d to %q, want the registered address", last.StatusCode, loc)
	}

	// Started at hanzo.ai, it visits hanzo.id and ends there.
	req = navigate(formReqNoBody("GET", PathLogout+"?client_id=web"))
	req.Host = "hanzo.ai"
	first, _ := do(t, app, req)
	if loc := first.Header.Get("Location"); !strings.HasPrefix(loc, "https://hanzo.id"+PathLogout+"?") || !strings.Contains(loc, "chain=https%3A%2F%2Fhanzo.ai~") {
		t.Fatalf("a hanzo.ai sign-out went to %q, want hanzo.id's end-session", loc)
	}

	// A chain this server did not seal is no chain: a link naming the origin it
	// claims to have started at cannot skip that origin, nor point the walk
	// anywhere else. The walk starts over from here.
	for _, forged := range []string{"https://hanzo.ai", "https://evil.example", "https://hanzo.ai~AAAA"} {
		resp := logout(t, app, "", "", url.Values{"chain": {forged}, "client_id": {"web"}, "post_logout_redirect_uri": {"https://web.example/bye"}}.Encode())
		if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, "https://hanzo.ai"+PathLogout+"?") {
			t.Fatalf("chain %q at hanzo.id went to %q, want hanzo.ai's end-session", forged, loc)
		}
	}
	// And a program's POST is answered where it is.
	post := formReq("POST", PathLogout, url.Values{})
	post.Header.Set("Accept", "application/json")
	if resp, body := do(t, app, post); resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("a programmatic sign-out must keep its JSON answer: %d %s", resp.StatusCode, body)
	}
}

// With no sign-in origin configured there is nothing to visit: the sign-out ends
// at the issuer exactly as before.
func TestLogout_NoSigninOriginsNoWalk(t *testing.T) {
	app, _, cookie := twoPeople(t)
	requireSignedOut(t, logout(t, app, cookie, "", ""), "")
}

// An address two orgs share names both accounts, and a sign-out by it ends both:
// a SuperAdmin admin/alice beside hanzo/alice is never the one left signed in.
func TestLogout_HintEndsEveryAccountItNames(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId, a.Organization, a.EnablePassword = "admin", "admin-portal", "admin-portal", "admin", true
	a.Cert = "cert-portal"
	a.SetId("admin/admin-portal")
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	seedUserInOrg(t, db, "admin", "alice", "alice@hanzo.ai", "pw")
	seedUserInOrg(t, db, "hanzo", "bob", "bob@hanzo.ai", "pw")
	form := url.Values{"organization": {"admin"}, "application": {"admin-portal"}, "username": {"alice"}, "password": {"pw"}, "type": {"login"}}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("admin sign-in: %s", body)
	}
	cookie := signInOn(t, app, signInOn(t, app, cookieKV(resp.Header.Get("Set-Cookie")), "alice"), "bob")
	if got := len(accountsOn(t, app, cookie)); got != 3 {
		t.Fatalf("want three accounts, got %d", got)
	}

	out := logout(t, app, cookie, "", url.Values{"logout_hint": {"alice@hanzo.ai"}}.Encode())
	if got := namesOn(t, app, cookieKV(out.Header.Get("Set-Cookie"))); got != "bob" {
		t.Fatalf("after signing out alice@hanzo.ai the browser holds %q, want only bob", got)
	}
}

// One origin, however the issuer is spelled: an issuer written with :443 beside a
// map naming the same host is one stop on the walk, and the walk ends.
func TestLogout_OneSpellingPerOrigin(t *testing.T) {
	if err := bootFederation(t, "https://hanzo.id:443", "", `{"hanzo.ai":"https://hanzo.ai","hanzo.id":"https://hanzo.id"}`); err != nil {
		t.Fatalf("boot: %v", err)
	}
	if got := strings.Join(signoutOrigins("https://hanzo.id:443"), ","); got != "https://hanzo.ai,https://hanzo.id" {
		t.Fatalf("origins = %q, want each host once", got)
	}
	app, _, cookie := twoPeople(t)
	host, path := "hanzo.id", PathLogout
	for hops := 0; ; hops++ {
		if hops > 2 {
			t.Fatal("the sign-out walk does not end")
		}
		req := navigate(formReqNoBody("GET", path))
		req.Host = host
		req.Header.Set("Cookie", cookie)
		resp, _ := do(t, app, req)
		u, err := url.Parse(resp.Header.Get("Location"))
		if err != nil || u.Path != PathLogout {
			return
		}
		host, path = u.Host, u.RequestURI()
	}
}

// A device is approved as the account its page showed and named, not whoever
// happens to be current when the approval arrives.
func TestDevice_ApprovesTheAccountThePageNamed(t *testing.T) {
	app, db, cookie := twoPeople(t) // bob current
	seedApp(t, db, appOpts{clientID: "cli", grants: deviceGrants})
	_, dev := requestDevice(t, app, "cli", "openid")
	req := fromPage(jsonReq("POST", PathLogin, map[string]string{"type": "device", "userCode": dev["user_code"].(string), "loginHint": subOf(t, app, cookie, "alice")}))
	req.Header.Set("Cookie", cookie)
	if _, raw := do(t, app, req); decode(t, raw)["status"] != "ok" {
		t.Fatalf("approve: %s", raw)
	}
	_, tok := pollDevice(t, app, "cli", dev["device_code"].(string))
	at, _ := tok["access_token"].(string)
	if at == "" {
		t.Fatalf("poll: %v", tok)
	}
	if got := verifiedClaims(t, db, at).Name; got != "alice" {
		t.Fatalf("the page named alice and the device was approved as %q", got)
	}
}

// demandedThenResumed sends the authorize request q from a browser holding
// cookie — so IAM records what it demands and hands it to the page — and then
// resumes it from the session the way a page that forwards nothing does: the
// same request, no prompt, no max_age.
func demandedThenResumed(t *testing.T, app *zip.App, cookie string, q url.Values, extra map[string]string) map[string]any {
	t.Helper()
	requireRedirect(t, authorizeWith(t, app, q, cookie, nil), hostedLoginPath)
	body := map[string]string{
		"type": "code", "clientId": q.Get("client_id"), "redirectUri": q.Get("redirect_uri"), "state": q.Get("state"),
		"scope": q.Get("scope"), "nonce": q.Get("nonce"), "codeChallenge": q.Get("code_challenge"), "codeChallengeMethod": "S256",
	}
	for k, v := range extra {
		body[k] = v
	}
	req := fromPage(jsonReq("POST", PathLogin, body))
	req.Header.Set("Cookie", cookie)
	_, raw := do(t, app, req)
	return decode(t, raw)
}

// What the authorize request demanded holds however the page resumes it. A page
// that drops prompt=login, prompt=select_account or max_age — as hanzo.ai's resume
// did for the CLI — does not get a code from the session it found.
func TestDemand_HoldsWhenThePageForwardsNothing(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signInOn(t, app, "", "alice")
	alice := subOf(t, app, cookie, "alice")
	base := silentQuery("verifier-demand-holds-0123456789012345678901234567")

	login := url.Values{}
	for k, v := range base {
		login[k] = v
	}
	login.Set("prompt", "login")
	if env := demandedThenResumed(t, app, cookie, login, map[string]string{"loginHint": alice}); env["code"] != CodeLoginRequired {
		t.Fatalf("prompt=login answered from the old session: %v", env)
	}

	choose := url.Values{}
	for k, v := range base {
		choose[k] = v
	}
	choose.Set("state", "st-choose")
	choose.Set("prompt", "select_account")
	if env := demandedThenResumed(t, app, cookie, choose, nil); env["code"] != CodeAccountSelectionRequired {
		t.Fatalf("select_account answered without a choice: %v", env)
	}
	if env := demandedThenResumed(t, app, cookie, choose, map[string]string{"loginHint": alice}); env["status"] != "ok" {
		t.Fatalf("the chosen account must be answered: %v", env)
	}

	aged := url.Values{}
	for k, v := range base {
		aged[k] = v
	}
	aged.Set("state", "st-aged")
	aged.Set("max_age", "0")
	if env := demandedThenResumed(t, app, cookie, aged, nil); env["code"] != CodeLoginRequired {
		t.Fatalf("max_age=0 answered from the old session: %v", env)
	}

	// The same request re-entering authorize without its prompt is held too.
	login.Del("prompt")
	if loc := requireRedirect(t, authorizeWith(t, app, login, cookie, nil), hostedLoginPath); strings.Contains(loc, "code=") {
		t.Fatalf("prompt=login re-entered without it was answered: %q", loc)
	}
	// A request that demanded nothing is single sign-on, as before.
	plain := silentQuery("verifier-demand-plain-012345678901234567890123456")
	plain.Set("state", "st-plain")
	codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, plain, cookie, nil), secondRedirect))
}

// prompt=login is met by a sign-in made after the request: the person types the
// password on the page, and the request then completes.
func TestDemand_LoginIsMetByAFreshSignIn(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signInOn(t, app, "", "alice")
	q := silentQuery("verifier-demand-fresh-0123456789012345678901234567")
	q.Set("prompt", "login")
	// The request is made two seconds before the person signs in again.
	prior := nowFunc
	nowFunc = func() time.Time { return prior().Add(-2 * time.Second) }
	requireRedirect(t, authorizeWith(t, app, q, cookie, nil), hostedLoginPath)
	nowFunc = prior
	fresh := signInOn(t, app, cookie, "alice")

	q.Del("prompt")
	q.Set("login_hint", "alice")
	codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, fresh, nil), secondRedirect))
}

// A demand lives as long as a sign-in screen stays open, and no longer.
func TestDemand_Expires(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signInOn(t, app, "", "alice")
	q := silentQuery("verifier-demand-expires-01234567890123456789012345")
	q.Set("prompt", "select_account")
	if env := demandedThenResumed(t, app, cookie, q, nil); env["code"] != CodeAccountSelectionRequired {
		t.Fatalf("select_account answered without a choice: %v", env)
	}
	prior := nowFunc
	nowFunc = func() time.Time { return prior().Add(demandTTL + time.Minute) }
	t.Cleanup(func() { nowFunc = prior })
	q.Del("prompt")
	codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect))
}

// A resume from the session is no new sign-in: it mints, and the session keeps
// the auth_time of the sign-in it records, so it cannot pass a later max_age.
func TestDemand_AResumeIsNoNewSignIn(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signInOn(t, app, "", "alice")
	req := fromPage(jsonReq("POST", PathLogin, map[string]string{
		"type": "code", "clientId": "second", "redirectUri": secondRedirect, "state": "st-resume",
		"codeChallenge": pkce.Challenge("verifier-resume-no-new-signin-0123456789012345678"), "codeChallengeMethod": "S256",
	}))
	req.Header.Set("Cookie", cookie)
	resp, raw := do(t, app, req)
	if decode(t, raw)["status"] != "ok" {
		t.Fatalf("resume: %s", raw)
	}
	if set := resp.Header.Get("Set-Cookie"); set != "" {
		t.Fatalf("a resume re-issued the session, which would restamp its auth_time: %q", set)
	}
}
