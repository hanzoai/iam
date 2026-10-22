// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Connecting a provider to an account you already hold. Unlink existed with no
// counterpart, so the only way a link was ever made was the address coincidence in
// linkOrProvision — and once unlinked, that coincidence was the only way back.

// beginLink drives POST /v1/iam/link with a bearer, the issuer's session cookie
// sent from the issuer's own page, or both, and returns the envelope and response.
func beginLink(t *testing.T, app *zip.App, bearer, cookie, provider, clientID, returnUri string) (map[string]any, *http.Response) {
	t.Helper()
	req := jsonReq("POST", PathLink, map[string]any{
		"provider": provider, "clientId": clientID, "returnUri": returnUri,
	})
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if cookie != "" {
		fromPage(req).Header.Set("Cookie", cookie)
	}
	resp, body := do(t, app, req)
	return decode(t, body), resp
}

// visit opens the address a begun link answered, as the browser does: a
// top-level navigation carrying cookie.
func visit(t *testing.T, app *zip.App, address, cookie string) *http.Response {
	t.Helper()
	u, err := url.Parse(address)
	if err != nil || u.Path != PathLink {
		t.Fatalf("a begun link must answer an address of %s, got %q", PathLink, address)
	}
	req := formReqNoBody("GET", u.RequestURI())
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, _ := do(t, app, req)
	return resp
}

// start begins a link and opens it in the browser holding session, and returns
// the IdP-authorize query and the binding the navigation set. The POST's answer
// sets no cookie: the binding exists only in the browser that opened the link.
func start(t *testing.T, app *zip.App, m *mockOIDC, bearer, session string) (url.Values, string) {
	t.Helper()
	env, begun := beginLink(t, app, bearer, session, fedProvGoogle, "conf", testRedirect)
	if env["status"] != "ok" {
		t.Fatalf("link did not start: %v", env["msg"])
	}
	if got := begun.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("starting a link set a cookie: %q", got)
	}
	address, _ := env["data"].(string)
	resp := visit(t, app, address, session)
	idpURL := requireRedirect(t, resp, m.URL)
	bind := cookieKV(resp.Header.Get("Set-Cookie"))
	if !strings.HasPrefix(bind, fedCookieName+"=") {
		t.Fatalf("opening the link set no binding: %q", bind)
	}
	q := mustQuery(t, idpURL)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	return q, bind
}

// linkable declares an OIDC provider on the "conf" app the caller signs in
// through, and makes "conf" one of the platform's own applications, as the
// issuer's account page client is.
func linkable(t *testing.T, db orm.DB, m *mockOIDC) {
	t.Helper()
	seedOIDCProvider(t, db, "conf", m)
	a, err := orm.Get[schema.Application](db, "admin/conf")
	if err != nil {
		t.Fatalf("load app: %v", err)
	}
	a.Platform = true
	if err := a.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("mark conf the platform's: %v", err)
	}
}

// through signs alice in through client and returns its access token.
func through(t *testing.T, app *zip.App, client string) string {
	t.Helper()
	code, _, _ := loginForCode(t, app, loginParams(client, "openid"))
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {client}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token issued through %s", client)
	}
	return access
}

// states counts the federation transactions the store holds.
func states(t *testing.T, db orm.DB) int64 {
	t.Helper()
	n, err := orm.TypedQuery[schema.FederationState](db).Count(context.Background())
	if err != nil {
		t.Fatalf("count states: %v", err)
	}
	return int64(n)
}

// The happy path: a signed-in person names a provider, follows it, and comes back
// with the identity attached to the account they were already holding.
func TestLink_AttachesToTheCallerAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)
	// The IdP's address is NOT alice's — the whole point: the coincidence is absent,
	// and the link happens anyway because she asked for it.
	m.email = "someone-else@gmail.com"

	// The issuer's account page: the session cookie, sent from its own page.
	q, bind := start(t, app, m, "", sessionCookieFor(t, app))

	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-link", bind), testRedirect)
	if got := mustQuery(t, loc).Get("linked"); got != fedProvGoogle {
		t.Fatalf("the return must name what was connected, got %q (%s)", got, loc)
	}
	// A link is not a sign-in: no code was minted for it.
	if mustQuery(t, loc).Get("code") != "" {
		t.Fatalf("a link minted an authorization code: %s", loc)
	}
	if got := userRow(t, db, "alice").Google; got != m.sub {
		t.Fatalf("the provider subject was not attached: %q", got)
	}
	// And no second account was created for the IdP's own address.
	if u, _ := store.GetUserByEmail(tctx(), db, "hanzo", "someone-else@gmail.com"); u != nil {
		t.Fatalf("linking created an account for the provider's address: %s/%s", u.Owner, u.Name)
	}
}

// The account is fixed at BEGIN, from the caller's proven identity — so a body
// naming another account changes nothing. The form has no such field; this asserts
// there is nothing to add one to.
func TestLink_RequiresAuthentication(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkable(t, db, newMockOIDC(t, fedGoogleCID))

	env, _ := beginLink(t, app, "", "", fedProvGoogle, "conf", testRedirect)
	if env["status"] != "error" {
		t.Fatalf("an unauthenticated link must be refused, got %v", env)
	}
	if userRow(t, db, "alice").Google != "" {
		t.Fatal("an unauthenticated request attached a provider")
	}
}

// A provider identity belongs to ONE account. A second person who signs in at the
// same provider cannot take it: the attach is refused and the first link survives.
func TestLink_SubjectAlreadyOnAnotherAccountRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)

	// Bob already holds this provider identity.
	seedUserInOrg(t, db, "hanzo", "bob", "bob@hanzo.ai", "pw")
	bob := userRow(t, db, "bob")
	bob.Google = m.sub
	if err := bob.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("seed bob's link: %v", err)
	}

	q, bind := start(t, app, m, accessTokenFor(t, app, "openid"), sessionCookieFor(t, app)) // alice

	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-steal", bind), testRedirect)
	if mustQuery(t, loc).Get("error") != "access_denied" {
		t.Fatalf("taking another account's identity must be refused, got %s", loc)
	}
	if userRow(t, db, "alice").Google != "" {
		t.Fatal("alice took an identity that belonged to bob")
	}
	if got := userRow(t, db, "bob").Google; got != m.sub {
		t.Fatalf("bob's link was disturbed: %q", got)
	}
}

// The return target is validated against the application's registered list, so the
// endpoint cannot be turned into an open redirector by the page that calls it.
func TestLink_UnregisteredReturnUriRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkable(t, db, newMockOIDC(t, fedGoogleCID))

	env, _ := beginLink(t, app, "", sessionCookieFor(t, app), fedProvGoogle, "conf", "https://attacker.example/collect")
	if env["status"] != "error" {
		t.Fatalf("an unregistered returnUri must be refused, got %v", env)
	}
	// No transaction was minted for it.
	if n := states(t, db); n != 0 {
		t.Fatalf("a refused link left %d transactions behind", n)
	}
}

// A provider already connected is said so up front, rather than after a round-trip
// to the IdP that could only end the same way.
func TestLink_AlreadyConnectedRefusedBeforeTheRoundTrip(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkable(t, db, newMockOIDC(t, fedGoogleCID))
	u := userRow(t, db, "alice")
	u.Google = "already-here"
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("seed link: %v", err)
	}

	env, _ := beginLink(t, app, accessTokenFor(t, app, "openid"), "", fedProvGoogle, "conf", testRedirect)
	if env["status"] != "error" {
		t.Fatalf("an already-connected provider must be refused, got %v", env)
	}
	if got := userRow(t, db, "alice").Google; got != "already-here" {
		t.Fatalf("the existing link was disturbed: %q", got)
	}
}

// A link transaction is single-use and browser-bound, exactly as a sign-in's is:
// the callback needs the cookie the begin leg set, and a replay attaches nothing.
func TestLink_TransactionIsBoundAndSingleUse(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)

	q, cookie := start(t, app, m, "", sessionCookieFor(t, app))
	state := q.Get("state")

	// Without the browser binding the callback attaches nothing — this is the
	// login-CSRF defense the sign-in flow relies on, and a link needs it more: the
	// prize is somebody else's account.
	resp := callback(t, app, state, "idp-code-1", "")
	if resp.StatusCode == 302 {
		t.Fatalf("a callback with no bind cookie was redirected: %s", resp.Header.Get("Location"))
	}
	if userRow(t, db, "alice").Google != "" {
		t.Fatal("a callback with no bind cookie attached a provider")
	}

	// The real browser completes it once.
	loc := requireRedirect(t, callback(t, app, state, "idp-code-1", cookie), testRedirect)
	if mustQuery(t, loc).Get("linked") == "" {
		t.Fatalf("the link did not complete: %s", loc)
	}
	// A replay finds the transaction spent.
	replay := callback(t, app, state, "idp-code-1", cookie)
	if replay.StatusCode == 302 {
		t.Fatalf("a replayed link was accepted: %s", replay.Header.Get("Location"))
	}
}

// Link and unlink are inverses, and the loop closes: what unlink removes, link puts
// back — which is the whole point, since re-linking used to need an address
// coincidence a person cannot arrange.
func TestLink_ClosesTheLoopWithUnlink(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)
	// The app permits disconnecting, which is the tenant policy unlink honours, and
	// alice signed up through it — the row unlink resolves that policy from.
	permitUnlink(t, db, "conf", fedProvGoogle)
	alice := userRow(t, db, "alice")
	alice.SignupApplication = "conf"
	if err := alice.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("set signup application: %v", err)
	}
	access := accessTokenFor(t, app, "openid")
	session := sessionCookieFor(t, app)

	// Link.
	q, cookie := start(t, app, m, access, session)
	requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-1", cookie), testRedirect)
	if userRow(t, db, "alice").Google == "" {
		t.Fatal("link did not attach")
	}

	// Unlink. Alice keeps her password, so the last-credential check permits it.
	req := jsonReq("POST", PathUnlink, map[string]any{
		"providerType": "Google",
		"user":         map[string]string{"owner": "hanzo", "name": "alice"},
	})
	req.Header.Set("Authorization", "Bearer "+access)
	_, body := do(t, app, req)
	if m2 := decode(t, body); m2["status"] != "ok" {
		t.Fatalf("unlink failed: %v", m2["msg"])
	}
	if got := userRow(t, db, "alice").Google; got != "" {
		t.Fatalf("unlink left the connector set: %q", got)
	}

	// And link again — the state the coincidence could never reach.
	q, cookie = start(t, app, m, access, session)
	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-2", cookie), testRedirect)
	if mustQuery(t, loc).Get("linked") != fedProvGoogle {
		t.Fatalf("re-linking did not complete: %s", loc)
	}
	if userRow(t, db, "alice").Google != m.sub {
		t.Fatal("re-linking did not attach")
	}
}

// Linking an identity requires the person on the issuer or a first-party client.
// An access token alice handed another application starts nothing: refused as
// every platform-only act refuses it, with no transaction, no address and no
// cookie in the answer.
func TestLink_AnotherApplicationsBearerStartsNothing(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedApp(t, db, appOpts{clientID: "rp2", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkable(t, db, newMockOIDC(t, fedGoogleCID))

	env, resp := beginLink(t, app, through(t, app, "rp2"), "", fedProvGoogle, "conf", testRedirect)
	if resp.StatusCode != http.StatusForbidden || env["msg"] != ErrNotPlatform.Error() {
		t.Fatalf("another application's bearer: status=%d %v, want 403 %q", resp.StatusCode, env, ErrNotPlatform.Error())
	}
	if env["data"] != nil {
		t.Fatalf("a refused link answered data: %v", env["data"])
	}
	if got := resp.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("a refused link set a cookie: %q", got)
	}
	if n := states(t, db); n != 0 {
		t.Fatalf("a refused link left %d transactions behind", n)
	}
}

// A first-party client starts a link with its bearer alone, and the person
// carries it through in the browser where they are signed in here.
func TestLink_PlatformBearerLinksInThePersonsBrowser(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)

	env, _ := beginLink(t, app, accessTokenFor(t, app, "openid"), "", fedProvGoogle, "conf", testRedirect)
	if env["status"] != "ok" {
		t.Fatalf("a first-party bearer did not start a link: %v", env["msg"])
	}
	resp := visit(t, app, env["data"].(string), sessionCookieFor(t, app))
	q := mustQuery(t, requireRedirect(t, resp, m.URL))
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-1", cookieKV(resp.Header.Get("Set-Cookie"))), testRedirect)
	if mustQuery(t, loc).Get("linked") != fedProvGoogle || userRow(t, db, "alice").Google != m.sub {
		t.Fatalf("the link did not complete: %s", loc)
	}
}

// A link begun by a client with no browser completes nowhere but in the browser
// where the person is signed in. Its answer is an address on the issuer, not the
// provider's: the provider-leg state and the binding never leave that browser. A
// client opening the address itself, a browser signed in as somebody else, and a
// request that is not a navigation are all refused without spending it; the
// callback refuses the begun transaction outright.
func TestLink_StartedWithoutABrowserCompletesOnlyInThePersons(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	seedUser(t, db, "mallory", "mallory@hanzo.ai", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	linkable(t, db, m)

	env, begun := beginLink(t, app, accessTokenFor(t, app, "openid"), "", fedProvGoogle, "conf", testRedirect)
	if env["status"] != "ok" {
		t.Fatalf("link did not start: %v", env["msg"])
	}
	if got := begun.Header.Values("Set-Cookie"); len(got) != 0 {
		t.Fatalf("starting a link handed out a cookie: %q", got)
	}
	address := env["data"].(string)
	if strings.HasPrefix(address, m.URL) || mustQuery(t, address).Get("nonce") != "" {
		t.Fatalf("starting a link answered the provider leg: %q", address)
	}

	refused := func(what string, resp *http.Response) {
		t.Helper()
		if resp.StatusCode == 302 || len(resp.Header.Values("Set-Cookie")) != 0 {
			t.Fatalf("%s: status=%d Location=%q Set-Cookie=%q", what, resp.StatusCode, resp.Header.Get("Location"), resp.Header.Values("Set-Cookie"))
		}
	}
	refused("opened with no session", visit(t, app, address, ""))
	refused("opened by another person's browser", visit(t, app, address, sessionCookieForNamed(t, app, "mallory")))
	alice := sessionCookieFor(t, app)
	fetched := func() *http.Response {
		u, _ := url.Parse(address)
		req := formReqNoBody("GET", u.RequestURI())
		req.Header.Set("Sec-Fetch-Dest", "empty")
		req.Header.Set("Cookie", alice)
		resp, _ := do(t, app, req)
		return resp
	}
	refused("fetched rather than navigated", fetched())
	state := mustQuery(t, address).Get("state")
	refused("the begun transaction at the callback", callback(t, app, state, "idp-code-1", ""))
	refused("the begun transaction at the callback with a made-up binding", callback(t, app, state, "idp-code-1", fedCookieName+"=made-up"))
	if got := userRow(t, db, "alice").Google; got != "" {
		t.Fatalf("a link completed outside alice's browser: %q", got)
	}

	// Nothing above spent it: alice's own browser carries it through.
	resp := visit(t, app, address, alice)
	q := mustQuery(t, requireRedirect(t, resp, m.URL))
	if q.Get("state") == state {
		t.Fatal("the provider leg reused the begun transaction's state")
	}
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-1", cookieKV(resp.Header.Get("Set-Cookie"))), testRedirect)
	if userRow(t, db, "alice").Google != m.sub {
		t.Fatal("alice's own browser did not complete the link")
	}
	// And the address is single-use.
	refused("opened a second time", visit(t, app, address, alice))
}

// permitUnlink turns on the application's CanUnlink flag for one provider item —
// the tenant policy unlink consults before letting a holder disconnect.
func permitUnlink(t *testing.T, db orm.DB, appClientID, providerName string) {
	t.Helper()
	a, err := orm.Get[schema.Application](db, "admin/"+appClientID)
	if err != nil {
		t.Fatalf("load app: %v", err)
	}
	for _, it := range a.Providers {
		if it != nil && it.Name == providerName {
			it.CanUnlink = true
		}
	}
	if err := a.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("permit unlink: %v", err)
	}
}
