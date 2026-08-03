// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/pkce"
)

// TWO IDENTITIES AT ONCE, driven over the real HTTP surface.
//
// z@ and a@ signed in together in ONE browser, switchable, with a downstream
// application resolving whichever is active. Every assertion below is made
// through the router a browser talks to — real cookies, real redirects, real
// token exchanges — because the property being claimed is a property of the wire,
// not of a struct.

// twoHumans seeds the portal, a second independent application, and the two
// people this lane exists for: hanzo/z and hanzo/a, distinct rows, same org.
func twoHumans(t *testing.T, db orm.DB) {
	t.Helper()
	seedApp(t, db, appOpts{clientID: "portal", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedApp(t, db, appOpts{clientID: "second", redirectURIs: []string{secondRedirect}})
	seedUser(t, db, "z", "z@hanzo.ai", "pw")
	seedUser(t, db, "a", "a@hanzo.ai", "pw")
}

// signInAs drives a bare portal sign-in for one username, PRESENTING whatever
// session the browser already holds, and returns the session cookie afterwards.
// Carrying the cookie in is what makes this "add an account" rather than "start
// over": the server must fold the new identity into the existing set.
func signInAs(t *testing.T, app *zip.App, username, cookie string) string {
	t.Helper()
	req := formReq("POST", PathLogin, url.Values{
		"organization": {"hanzo"}, "application": {"portal"},
		"username": {username}, "password": {"pw"}, "type": {"login"},
	})
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, body := do(t, app, req)
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("sign-in as %s failed: status=%d body=%s", username, resp.StatusCode, body)
	}
	got := cookieKV(resp.Header.Get("Set-Cookie"))
	if !strings.HasPrefix(got, sessions.CookieName+"=") {
		t.Fatalf("sign-in as %s set no session cookie: %q", username, got)
	}
	return got
}

// identities reads GET /v1/iam/identities — `hanzo auth list`, in a browser.
func identities(t *testing.T, app *zip.App, cookie string) identitiesResponse {
	t.Helper()
	req := formReqNoBody("GET", PathIdentities)
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, body := do(t, app, req)
	if resp.StatusCode != 200 {
		t.Fatalf("GET %s = %d: %s", PathIdentities, resp.StatusCode, body)
	}
	var out identitiesResponse
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %s: %v (%s)", PathIdentities, err, body)
	}
	return out
}

// held renders the list the way the CLI prints it, for readable failures.
func held(list identitiesResponse) string {
	var b strings.Builder
	for _, id := range list.Data {
		mark := " "
		if id.Active {
			mark = "*"
		}
		b.WriteString("\n  " + mark + " " + id.Identity + "  <" + id.Email + ">")
	}
	if b.Len() == 0 {
		return "\n  (none)"
	}
	return b.String()
}

// useIdentity posts the chooser's answer: no credential, just the `owner/name`
// selector. Returns the response and the (possibly re-issued) session cookie.
func useIdentity(t *testing.T, app *zip.App, cookie, identity string) (*http.Response, []byte, string) {
	t.Helper()
	req := jsonReq("POST", PathLogin, map[string]string{"type": "login", "identity": identity})
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, body := do(t, app, req)
	next := cookieKV(resp.Header.Get("Set-Cookie"))
	if !strings.HasPrefix(next, sessions.CookieName+"=") {
		next = cookie // no re-issue: the selection was refused
	}
	return resp, body, next
}

// accountName is who GET /v1/iam/account says this browser is — the read the
// portal and the gateway admin-guard both make.
func accountName(t *testing.T, app *zip.App, cookie string) string {
	t.Helper()
	req := formReqNoBody("GET", PathAccount)
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	m := decode(t, body)
	if m["status"] != "ok" {
		return ""
	}
	name, _ := m["name"].(string)
	return name
}

// carried decodes the session payload the browser is holding WITHOUT verifying
// it — a white-box read, used only to assert that a SELECTION changed nothing it
// had no business changing (a switch is not an authentication, so neither the
// sid nor the auth_time may move).
func carried(t *testing.T, cookie string) sessions.Cookie {
	t.Helper()
	value := strings.TrimPrefix(cookie, sessions.CookieName+"=")
	payload, _, ok := strings.Cut(value, ".")
	if !ok {
		t.Fatalf("not a session cookie: %q", cookie)
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		t.Fatalf("session payload is not base64url: %v", err)
	}
	var sc sessions.Cookie
	if err := json.Unmarshal(raw, &sc); err != nil {
		t.Fatalf("session payload: %v (%s)", err, raw)
	}
	return sc
}

// THE HEADLINE. Signing in as a@ while z@ is present yields TWO live identities,
// with a@ active — not a replacement. This is the whole lane in one test.
func TestTwoIdentities_SecondSignInKeepsTheFirst(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)

	cookie := signInAs(t, app, "z", "")
	if got := accountName(t, app, cookie); got != "z" {
		t.Fatalf("after signing in as z@, the browser is %q", got)
	}

	// Add the second identity, carrying the first browser session along.
	cookie = signInAs(t, app, "a", cookie)

	list := identities(t, app, cookie)
	if len(list.Data) != 2 {
		t.Fatalf("both identities must be held, got %d:%s", len(list.Data), held(list))
	}
	if list.Active != "hanzo/a" {
		t.Fatalf("the identity that just signed in is active, got %q:%s", list.Active, held(list))
	}
	if got := accountName(t, app, cookie); got != "a" {
		t.Fatalf("the browser must act as a@, got %q", got)
	}

	// z@ is not merely listed — it is LIVE. Selecting it makes it the caller.
	seen := map[string]string{}
	for _, id := range list.Data {
		seen[id.Identity] = id.Email
	}
	if seen["hanzo/z"] != "z@hanzo.ai" || seen["hanzo/a"] != "a@hanzo.ai" {
		t.Fatalf("each identity must carry its OWN profile, got %v", seen)
	}
}

// SWITCHING. `hanzo auth use`, in a browser: the selector names an identity the
// session already holds, and every subsequent request is that person.
func TestTwoIdentities_SwitchChangesWhoTheBrowserIs(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)

	cookie := signInAs(t, app, "z", "")
	cookie = signInAs(t, app, "a", cookie)

	resp, body, cookie := useIdentity(t, app, cookie, "hanzo/z")
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("selecting hanzo/z failed: status=%d body=%s", resp.StatusCode, body)
	}
	if got := accountName(t, app, cookie); got != "z" {
		t.Fatalf("after switching, the browser must be z@, got %q", got)
	}

	list := identities(t, app, cookie)
	if list.Active != "hanzo/z" || len(list.Data) != 2 {
		t.Fatalf("switching selects, it does not sign anyone out:%s", held(list))
	}

	// …and back again, without a password either way.
	_, _, cookie = useIdentity(t, app, cookie, "hanzo/a")
	if got := accountName(t, app, cookie); got != "a" {
		t.Fatalf("switching back must reach a@, got %q", got)
	}
}

// THE SWITCH ANSWERS AS THE IDENTITY IT SELECTED — in the SAME response.
//
// This is the defect only a live drive found. A cookie mutation is written to the
// RESPONSE, so re-reading the session inside the same handler still sees the
// session the browser ARRIVED with: the switch replied for the previously-active
// identity while the cookie it set said otherwise, and the next page load agreed
// with the cookie. Clicking "z@" in the chooser therefore handed the application
// a code for a@ — an identity swap with nothing on screen to notice — and every
// assertion made one request later still passed.
//
// Both shapes are checked, because the bare switch is where it was seen and the
// code grant is where it would have been catastrophic.
func TestTwoIdentities_SwitchAnswersAsTheSelectedIdentity(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)
	seedRSACert(t, db, "cert-switch")

	cookie := signInAs(t, app, "z", "")
	cookie = signInAs(t, app, "a", cookie)

	// A bare switch reports the identity it selected, not the one it left.
	_, body, cookie := useIdentity(t, app, cookie, "hanzo/z")
	if got, _ := decode(t, body)["data"].(string); got != "hanzo/z" {
		t.Fatalf("the switch answered for %q, want hanzo/z — the response is minted for the identity it LEFT", got)
	}

	// And a switch carrying an OAuth request hands back a code for the selected
	// identity: the chooser's whole job.
	_, _, cookie = useIdentity(t, app, cookie, "hanzo/a")
	verifier := "verifier-switch-code-0123456789012345678901234567"
	req := jsonReq("POST", PathLogin+"?"+url.Values{
		"clientId":              {"second"},
		"redirectUri":           {secondRedirect},
		"scope":                 {"openid profile email"},
		"code_challenge":        {pkce.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}.Encode(), map[string]string{"type": "code", "identity": "hanzo/z", "application": "second"})
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	code, _ := decode(t, body)["data"].(string)
	if resp.StatusCode != 200 || code == "" {
		t.Fatalf("the chooser must mint a code: status=%d body=%s", resp.StatusCode, body)
	}
	tokResp, env := exchangeCode(t, app, url.Values{
		"code":          {code},
		"client_id":     {"second"},
		"redirect_uri":  {secondRedirect},
		"code_verifier": {verifier},
	})
	if tokResp.StatusCode != 200 {
		t.Fatalf("token exchange failed: %d %v", tokResp.StatusCode, env)
	}
	access, _ := env["access_token"].(string)
	ui := formReqNoBody("GET", PathUserInfo)
	ui.Header.Set("Authorization", "Bearer "+access)
	_, uiBody := do(t, app, ui)
	if who, _ := decode(t, uiBody)["preferred_username"].(string); who != "z" {
		t.Fatalf("the chooser picked z@ and the app was signed in as %q — an identity swap", who)
	}
}

// A SELECTION IS NOT AN AUTHENTICATION. Switching must not mint a new sid or
// stamp a fresh auth_time: doing either would let a switch launder a months-old
// sign-in past a relying party's max_age.
func TestTwoIdentities_SelectingIsNotAuthenticating(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)

	cookie := signInAs(t, app, "z", "")
	cookie = signInAs(t, app, "a", cookie)

	held0 := carried(t, cookie)
	before := held0.Find("hanzo", "z")
	if before == nil {
		t.Fatal("z@ must be held before the switch")
	}

	_, _, cookie = useIdentity(t, app, cookie, "hanzo/z")

	held1 := carried(t, cookie)
	after := held1.Find("hanzo", "z")
	if after == nil {
		t.Fatal("z@ must still be held after the switch")
	}
	if after.SID != before.SID {
		t.Errorf("a switch minted a new session id — it authenticated nobody: %q → %q", before.SID, after.SID)
	}
	if after.AuthTime != before.AuthTime {
		t.Errorf("a switch refreshed auth_time (%d → %d): a stale sign-in must not pass for a fresh one",
			before.AuthTime, after.AuthTime)
	}
}

// THE CHOOSER CANNOT INTRODUCE A PRINCIPAL. A selector is looked up inside the
// SIGNED set; naming somebody who never signed in on this browser selects
// nothing, and — critically — leaves the identity already active untouched.
func TestTwoIdentities_SelectorCannotNameAStranger(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)
	seedUser(t, db, "mallory", "mallory@evil.example", "pw")

	cookie := signInAs(t, app, "z", "")

	for _, stranger := range []string{"hanzo/mallory", "admin/root", "hanzo/a"} {
		resp, body, next := useIdentity(t, app, cookie, stranger)
		m := decode(t, body)
		if resp.StatusCode == 200 && m["status"] == "ok" {
			t.Fatalf("selecting %q must be refused, got %s", stranger, body)
		}
		if got := accountName(t, app, next); got != "z" {
			t.Fatalf("a refused selection must leave z@ active, got %q after %q", got, stranger)
		}
	}

	// And with no session at all there is nothing to select from.
	resp, body, _ := useIdentity(t, app, "", "hanzo/z")
	if resp.StatusCode == 200 && decode(t, body)["status"] == "ok" {
		t.Fatalf("a selector must not authenticate an anonymous browser: %s", body)
	}
}

// A credential and a selector are two different answers to "who is signing in".
// Sending both is refused rather than ranked.
func TestTwoIdentities_CredentialAndSelectorTogetherRefused(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)

	cookie := signInAs(t, app, "z", "")
	req := jsonReq("POST", PathLogin, map[string]string{
		"type": "login", "identity": "hanzo/z",
		"organization": "hanzo", "application": "portal",
		"username": "a", "password": "pw",
	})
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	if resp.StatusCode == 200 && decode(t, body)["status"] == "ok" {
		t.Fatalf("a credential plus a selector must be refused: %s", body)
	}
	if got := accountName(t, app, cookie); got != "z" {
		t.Fatalf("the refused request must have changed nothing, got %q", got)
	}
}

// A DOWNSTREAM APPLICATION SEES WHICHEVER IDENTITY IS ACTIVE.
//
// The second app never shows a login screen (silent SSO) and the code it lands
// with exchanges for tokens naming the ACTIVE identity — so switching at the
// issuer and re-entering the app is the whole "jump to any app with whichever
// identity" story, with nothing asked of the app but a standard OIDC sign-in.
func TestTwoIdentities_DownstreamAppFollowsTheActiveIdentity(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)
	seedRSACert(t, db, "cert-multi")

	cookie := signInAs(t, app, "z", "")
	cookie = signInAs(t, app, "a", cookie)

	if who := silentSubject(t, app, cookie, "verifier-active-a-0123456789012345678901234567"); who != "a" {
		t.Fatalf("the second app must see the ACTIVE identity a@, got %q", who)
	}

	_, _, cookie = useIdentity(t, app, cookie, "hanzo/z")

	if who := silentSubject(t, app, cookie, "verifier-active-z-0123456789012345678901234567"); who != "z" {
		t.Fatalf("after switching, the same app must see z@, got %q", who)
	}

	// Both identities are still held: the app changed who it sees, nobody was
	// signed out to make that happen.
	list := identities(t, app, cookie)
	if len(list.Data) != 2 {
		t.Fatalf("switching must not sign anyone out:%s", held(list))
	}
}

// silentSubject drives the second application's silent authorize, exchanges the
// code, and reports the username the resulting tokens name — i.e. who that
// application believes the browser is.
func silentSubject(t *testing.T, app *zip.App, cookie, verifier string) string {
	t.Helper()
	q := silentQuery(verifier)
	q.Set("prompt", "none")
	resp := authorizeWith(t, app, q, cookie, nil)
	loc := requireRedirect(t, resp, secondRedirect)
	code := codeFromLocation(t, loc)

	tokResp, env := exchangeCode(t, app, url.Values{
		"code":          {code},
		"client_id":     {"second"},
		"redirect_uri":  {secondRedirect},
		"code_verifier": {verifier},
	})
	if tokResp.StatusCode != 200 {
		t.Fatalf("token exchange failed: %d %v", tokResp.StatusCode, env)
	}
	access, _ := env["access_token"].(string)
	if access == "" {
		t.Fatalf("no access token: %v", env)
	}
	// userinfo is what an application actually calls to render "you are signed in
	// as…", so it is the honest place to read the answer from.
	req := formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+access)
	uiResp, body := do(t, app, req)
	if uiResp.StatusCode != 200 {
		t.Fatalf("userinfo = %d: %s", uiResp.StatusCode, body)
	}
	name, _ := decode(t, body)["preferred_username"].(string)
	return name
}

// THE IDENTITY HEADER CONTRACT CARRIES THE ACTIVE IDENTITY.
//
// Downstream, the gateway writes X-User-Id / X-Org-Id / X-User-Email from the
// claims of a JWT it validated (HIP-0026), and hanzoai/cloud re-derives them
// from that same validated principal before any handler reads them — a client's
// own copy of those headers is deleted on ingress and never a source. So the
// question this lane has to answer is not "does the edge write the right
// header", it is "does the TOKEN this issuer mints after a switch name the
// identity that is now active". Everything downstream is a function of that.
//
// `owner` is the field to watch, because it is three things at once — the home
// org, the billing anchor, and the input to the SuperAdmin predicate — and
// because this estate already has the same human living as two rows in two
// orgs. A switcher that carried the wrong `owner` would bill the wrong org and,
// for an identity in the reserved org, hand out platform authority.
func TestTwoIdentities_MintedClaimsFollowTheActiveIdentity(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "portal", secret: "s3cret", redirectURIs: []string{testRedirect}})
	// Shared, so BOTH orgs' identities may grant into it — otherwise the tenant
	// rule (asserted separately below) refuses the cross-org one before any
	// claim is minted and this test would measure nothing.
	seedApp(t, db, appOpts{clientID: "second", redirectURIs: []string{secondRedirect}, shared: true})
	seedRSACert(t, db, "cert-claims")
	// Two identities of the SAME human in DIFFERENT orgs — the collision this
	// estate actually has, and the one a chooser must not blur.
	seedUser(t, db, "z", "z@hanzo.ai", "pw")
	seedUserInOrg(t, db, "acme", "z", "z@acme.example", "pw")

	cookie := signInAs(t, app, "z", "")
	req := formReq("POST", PathLogin, url.Values{
		"organization": {"acme"}, "application": {"portal"},
		"username": {"z"}, "password": {"pw"}, "type": {"login"},
	})
	req.Header.Set("Cookie", cookie)
	resp, body := do(t, app, req)
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("signing in as acme/z failed: %s", body)
	}
	cookie = cookieKV(resp.Header.Get("Set-Cookie"))

	subs := map[string]string{}
	owners := map[string]string{}
	for _, want := range []struct{ identity, owner, email string }{
		{"acme/z", "acme", "z@acme.example"},
		{"hanzo/z", "hanzo", "z@hanzo.ai"},
	} {
		_, _, cookie = useIdentity(t, app, cookie, want.identity)
		verifier := "verifier-claims-" + want.owner + "-0123456789012345678901"
		q := silentQuery(verifier)
		q.Set("prompt", "none")
		loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
		tokResp, env := exchangeCode(t, app, url.Values{
			"code":          {codeFromLocation(t, loc)},
			"client_id":     {"second"},
			"redirect_uri":  {secondRedirect},
			"code_verifier": {verifier},
		})
		if tokResp.StatusCode != 200 {
			t.Fatalf("%s: token exchange failed: %d %v", want.identity, tokResp.StatusCode, env)
		}
		access, _ := env["access_token"].(string)
		claims := claimsOf(t, access)
		if got, _ := claims["preferred_username"].(string); got != "z" {
			t.Errorf("%s: token username = %q, want z", want.identity, got)
		}
		// X-User-Email is written from this claim, and it is what a console
		// greets you by. Two rows of the same human differ here, so it is the
		// claim that proves the switch reached the right ROW and not merely the
		// right username.
		if got, _ := claims["email"].(string); got != want.email {
			t.Errorf("%s: token email = %q, want %q — X-User-Email is written from this",
				want.identity, got, want.email)
		}
		subs[want.identity], _ = claims["sub"].(string)
		owners[want.identity], _ = claims["owner"].(string)
	}

	// THE COLLISION, ASSERTED. The same human in two orgs is two DISTINCT
	// principals, and `sub` is what keeps them apart end to end: it is the value
	// a relying party stores, the value X-User-Id is written from, and the value
	// id_token_hint compares. If a switch left them equal, every downstream would
	// believe the two identities were one account.
	if subs["acme/z"] == subs["hanzo/z"] || subs["acme/z"] == "" {
		t.Fatalf("the two identities of one human must have distinct subjects, got %q and %q",
			subs["acme/z"], subs["hanzo/z"])
	}

	// AND THE PART THAT IS NOT RIGHT YET, PINNED SO IT CANNOT DRIFT SILENTLY.
	//
	// `owner` is minted as the APPLICATION's organization (jwt.go passes
	// app.Organization into Signer.claims), NOT the identity's home org. That is
	// pre-existing and platform-wide — it is equally true of a single identity
	// signing into a shared cross-org app — and it is NOT this lane's to change:
	// `owner` is simultaneously the billing anchor, the SuperAdmin predicate the
	// gateway admin-guard derives, and what hanzoai/cloud documents as the HOME
	// org. Redefining it would ripple through every consumer at once, and in the
	// escalating direction (a human whose home org is the reserved admin org
	// would begin carrying owner=admin into applications that never granted it).
	//
	// So this asserts the CURRENT truth rather than the desired one. When the
	// contract is fixed platform-wide, this test fails loudly and is the place
	// the change gets re-decided — which is the entire reason it is written down
	// as an assertion instead of a comment.
	for id, got := range owners {
		if got != "hanzo" {
			t.Fatalf("%s: token owner = %q; today every token carries the APPLICATION's "+
				"org (hanzo). If this changed, the billing anchor and the SuperAdmin "+
				"predicate changed with it — re-decide deliberately, do not adjust this test.",
				id, got)
		}
	}
}

// claimsOf decodes a JWT payload WITHOUT verifying it. The signature is the
// server's own and is checked everywhere it matters; here the only question is
// which values it put in.
func claimsOf(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("claims are not base64url: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("claims: %v (%s)", err, raw)
	}
	return m
}

// AN APP THAT ALREADY KNOWS WHO IT HAS IS NOT SWAPPED UNDERNEATH THE USER.
//
// This is the failure mode two live identities create: an application holding a
// session for z@ does a silent renew, the browser's active identity is now a@,
// and a code for a DIFFERENT human arrives through the callback the app already
// trusts — with nothing on screen to notice. id_token_hint is the defence OIDC
// specifies, and it must actually be enforced.
func TestTwoIdentities_IdTokenHintRefusesASwap(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)
	seedRSACert(t, db, "cert-hint")

	// The app signs z@ in and keeps the id_token.
	cookie := signInAs(t, app, "z", "")
	verifier := "verifier-hint-z-01234567890123456789012345678901"
	q := silentQuery(verifier)
	q.Set("prompt", "none")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
	_, env := exchangeCode(t, app, url.Values{
		"code":          {codeFromLocation(t, loc)},
		"client_id":     {"second"},
		"redirect_uri":  {secondRedirect},
		"code_verifier": {verifier},
	})
	idToken, _ := env["id_token"].(string)
	if idToken == "" {
		t.Fatalf("no id_token to hint with: %v", env)
	}

	// The human adds a@ and it becomes active. The app renews silently, still
	// naming z@.
	cookie = signInAs(t, app, "a", cookie)
	renew := silentQuery("verifier-hint-renew-012345678901234567890123456")
	renew.Set("prompt", "none")
	renew.Set("id_token_hint", idToken)
	loc = requireRedirect(t, authorizeWith(t, app, renew, cookie, nil), secondRedirect)

	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("error"); got != errLoginRequired {
		t.Fatalf("a renewal for z@ answered while a@ is active must be %s, got error=%q code=%q",
			errLoginRequired, got, u.Query().Get("code"))
	}
}

// SIGNING OUT OF ONE IDENTITY KEEPS THE OTHER — and promotes nobody. A browser
// that quietly became "whoever is left" would act as a principal nobody chose.
func TestTwoIdentities_SignOutOfOneKeepsTheOtherAndPromotesNobody(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)

	cookie := signInAs(t, app, "z", "")
	cookie = signInAs(t, app, "a", cookie)

	req := formReqNoBody("GET", PathLogout+"?logout_hint="+url.QueryEscape("hanzo/a"))
	req.Header.Set("Cookie", cookie)
	resp, _ := do(t, app, req)
	if next := cookieKV(resp.Header.Get("Set-Cookie")); strings.HasPrefix(next, sessions.CookieName+"=") {
		cookie = next
	}

	list := identities(t, app, cookie)
	if len(list.Data) != 1 || list.Data[0].Identity != "hanzo/z" {
		t.Fatalf("only a@ was signed out:%s", held(list))
	}
	if list.Active != "" {
		t.Fatalf("signing out the ACTIVE identity must promote nobody, got active=%q", list.Active)
	}
	if got := accountName(t, app, cookie); got != "" {
		t.Fatalf("no identity is active, so the browser is nobody — got %q", got)
	}

	// The survivor is real: choosing it works, without a password.
	_, _, cookie = useIdentity(t, app, cookie, "hanzo/z")
	if got := accountName(t, app, cookie); got != "z" {
		t.Fatalf("the remaining identity must be selectable, got %q", got)
	}
}

// A BARE SIGN-OUT IS COMPLETE. No hint means no qualifier, which on a shared
// machine means "everything" — a logout that left a second identity live because
// it merely was not the active one would report success while a session survived.
func TestTwoIdentities_BareLogoutEndsEveryIdentity(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)

	cookie := signInAs(t, app, "z", "")
	cookie = signInAs(t, app, "a", cookie)

	req := formReqNoBody("GET", PathLogout)
	req.Header.Set("Cookie", cookie)
	resp, _ := do(t, app, req)
	if sc := resp.Header.Get("Set-Cookie"); !strings.Contains(sc, sessions.CookieName+"=;") {
		t.Fatalf("the session cookie must be expired, got %q", sc)
	}

	// The CAPTURED cookie must be dead server-side too — expiring it in the
	// browser is the half an attacker holding a copy does not care about.
	if list := identities(t, app, cookie); len(list.Data) != 0 {
		t.Fatalf("every identity must be revoked, still held:%s", held(list))
	}
	if got := accountName(t, app, cookie); got != "" {
		t.Fatalf("a captured cookie must not still resolve, got %q", got)
	}
}

// The identity list is scoped to the BROWSER's own session and takes no
// parameters, so there is nothing to point it at anyone else. Anonymous is an
// empty list, not an error: the chooser draws itself from it.
func TestIdentities_AnonymousIsEmptyNotAnError(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)

	list := identities(t, app, "")
	if list.Status != "ok" || len(list.Data) != 0 || list.Active != "" {
		t.Fatalf("an anonymous browser holds no identities, got %+v", list)
	}

	// A forged cookie is not a session either.
	forged := identities(t, app, sessions.CookieName+"=eyJpZHMiOlt7Im8iOiJhZG1pbiIsIm4iOiJyb290In1dfQ.deadbeef")
	if len(forged.Data) != 0 {
		t.Fatalf("a forged session must hold nothing:%s", held(forged))
	}
}

// PKCE is unaffected by any of this: the silent grant still binds the code to
// the verifier, so a code observed on the callback is useless without it.
func TestTwoIdentities_SilentCodeStillNeedsThePKCEVerifier(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)
	seedRSACert(t, db, "cert-pkce")

	cookie := signInAs(t, app, "z", "")
	verifier := "verifier-pkce-bound-0123456789012345678901234567"
	q := silentQuery(verifier)
	q.Set("prompt", "none")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)

	resp, _ := exchangeCode(t, app, url.Values{
		"code":          {codeFromLocation(t, loc)},
		"client_id":     {"second"},
		"redirect_uri":  {secondRedirect},
		"code_verifier": {"wrong-verifier-0123456789012345678901234567890"},
	})
	if resp.StatusCode == 200 {
		t.Fatal("a silent code must not redeem under the wrong PKCE verifier")
	}
	_ = pkce.Challenge(verifier)
}

// A CROSS-ORG SWITCH IS STILL SUBJECT TO THE TENANT RULE.
//
// Selecting an identity is not a way around anything. The chooser runs through
// the ONE mint path, so an identity belonging to a different organization
// cannot grant into an org-scoped application merely because a human picked it —
// the refusal is the same one a password post would get, and it is a refusal to
// GRANT, not a partial one.
func TestTwoIdentities_SwitchDoesNotBypassTheTenantRule(t *testing.T) {
	app, db := newServer(t)
	twoHumans(t, db)
	seedRSACert(t, db, "cert-tenant")
	seedUserInOrg(t, db, "acme", "z", "z@acme.example", "pw")

	cookie := signInAs(t, app, "z", "")
	req := formReq("POST", PathLogin, url.Values{
		"organization": {"acme"}, "application": {"portal"},
		"username": {"z"}, "password": {"pw"}, "type": {"login"},
	})
	req.Header.Set("Cookie", cookie)
	resp, _ := do(t, app, req)
	cookie = cookieKV(resp.Header.Get("Set-Cookie"))

	// `second` belongs to org hanzo and is not shared; acme/z is active.
	q := silentQuery("verifier-tenant-gate-01234567890123456789012345")
	q.Set("prompt", "none")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	if got := u.Query().Get("error"); got == "" {
		t.Fatalf("a cross-org identity must not be granted into an org-scoped app, got code=%q",
			u.Query().Get("code"))
	}
}
