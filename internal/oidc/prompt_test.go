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

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
)

// SILENT RE-AUTHENTICATION. Sign in once at the issuer, then a SECOND
// application reaches the person already signed in with no interaction at all —
// and a client that asks for no interaction gets a machine-readable answer at
// its own callback rather than a login page.

const secondRedirect = "https://second.example/callback"

// silentQuery is a well-formed authorize request for the second application.
func silentQuery(verifier string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {"second"},
		"redirect_uri":          {secondRedirect},
		"scope":                 {"openid profile email"},
		"state":                 {"st-42"},
		"nonce":                 {"n-1"},
		"code_challenge":        {pkce.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
}

// twoApps seeds the portal the human signs in at plus a SECOND, independent
// public client — the app that must not show a login screen.
func twoApps(t *testing.T, db orm.DB) {
	t.Helper()
	seedApp(t, db, appOpts{clientID: "portal", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedApp(t, db, appOpts{clientID: "second", redirectURIs: []string{secondRedirect}})
	seedRichUser(t, db) // hanzo/alice, password "pw"
}

// authorizeWith drives GET /authorize carrying an optional session cookie and
// optional extra headers.
func authorizeWith(t *testing.T, app *zip.App, q url.Values, cookie string, headers map[string]string) *http.Response {
	t.Helper()
	req := formReqNoBody("GET", authorizeURL(q))
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	// A real browser navigation. Absent, the handler cannot tell a navigation
	// from a frame; present and truthful is what production looks like.
	req.Header.Set("Sec-Fetch-Dest", "document")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, _ := do(t, app, req)
	return resp
}

// codeFromLocation extracts the authorization code a successful silent grant
// returned on the client's callback, failing if the redirect carried an error.
func codeFromLocation(t *testing.T, loc string) string {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location %q is not a URL: %v", loc, err)
	}
	q := u.Query()
	if e := q.Get("error"); e != "" {
		t.Fatalf("silent grant refused: error=%s desc=%s", e, q.Get("error_description"))
	}
	code := q.Get("code")
	if code == "" {
		t.Fatalf("no code on the callback: %q", loc)
	}
	return code
}

// THE REQUIREMENT: one sign-in at the issuer, and the second application is
// reached signed in with ZERO further interaction — the browser never sees a
// login page, and the code it lands with really does exchange for tokens naming
// the person who signed in.
func TestSilent_SecondAppNeverSeesALoginScreen(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)

	// ONE interactive sign-in, at the portal.
	cookie := signIn(t, app, "portal")

	// The second application sends the browser to authorize. No prompt at all —
	// the ordinary case a relying party generates.
	verifier := "verifier-second-app-0123456789012345678901234567890123"
	resp := authorizeWith(t, app, silentQuery(verifier), cookie, nil)

	// It lands straight back on ITS OWN callback. Not the login page.
	loc := requireRedirect(t, resp, secondRedirect)
	if strings.Contains(loc, hostedLoginPath) {
		t.Fatalf("the second app was sent to a login screen: %q", loc)
	}
	if !strings.Contains(loc, "state=st-42") {
		t.Errorf("state was not echoed: %q", loc)
	}
	code := codeFromLocation(t, loc)

	// And the code is real: it exchanges for tokens naming alice.
	resp2, env := exchangeCode(t, app, url.Values{
		"code":          {code},
		"client_id":     {"second"},
		"redirect_uri":  {secondRedirect},
		"code_verifier": {verifier},
	})
	if resp2.StatusCode != 200 {
		t.Fatalf("silent code did not exchange: status=%d body=%v", resp2.StatusCode, env)
	}
	if env["id_token"] == nil || env["access_token"] == nil {
		t.Fatalf("exchange returned no tokens: %v", env)
	}
	claims := verifiedClaims(t, db, env["id_token"].(string))
	if claims.Name != "alice" {
		t.Fatalf("silent grant named the wrong principal: %q", claims.Name)
	}
	if claims.Nonce != "n-1" {
		t.Errorf("nonce not bound through the silent code: %q", claims.Nonce)
	}
}

// prompt=none WITHOUT a session returns login_required TO THE REDIRECT URI. It
// does not render, and it does not bounce to the interactive page — which is
// exactly what it used to do, and what made silent SSO impossible: a client had
// no way to ask "is anyone signed in?" without showing a login screen to someone
// who already was.
func TestSilent_PromptNoneWithoutSessionReturnsLoginRequired(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)

	q := silentQuery("verifier-no-session-012345678901234567890123456789")
	q.Set("prompt", "none")
	resp := authorizeWith(t, app, q, "", nil)

	loc := requireRedirect(t, resp, secondRedirect)
	u, _ := url.Parse(loc)
	if got := u.Query().Get("error"); got != errLoginRequired {
		t.Fatalf("error = %q, want %q (Location %q)", got, errLoginRequired, loc)
	}
	if u.Query().Get("state") != "st-42" {
		t.Errorf("state not echoed on the error: %q", loc)
	}
	if u.Query().Get("code") != "" {
		t.Fatal("an error redirect must carry no code")
	}
}

// The session is CLEARED, and prompt=none goes back to answering
// login_required — the revocation is server-side, so a captured copy of the
// cookie stops being an answer immediately.
func TestSilent_AfterLogoutPromptNoneIsLoginRequired(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	// Before: silent works.
	q := silentQuery("verifier-before-logout-0123456789012345678901234567")
	q.Set("prompt", "none")
	codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect))

	// Sign out.
	logout := formReqNoBody("GET", PathLogout)
	logout.Header.Set("Cookie", cookie)
	if resp, _ := do(t, app, logout); resp.StatusCode != 200 && resp.StatusCode != 302 {
		t.Fatalf("logout status = %d", resp.StatusCode)
	}

	// After: the SAME cookie value no longer answers.
	q2 := silentQuery("verifier-after-logout-01234567890123456789012345678")
	q2.Set("prompt", "none")
	loc := requireRedirect(t, authorizeWith(t, app, q2, cookie, nil), secondRedirect)
	u, _ := url.Parse(loc)
	if got := u.Query().Get("error"); got != errLoginRequired {
		t.Fatalf("a revoked session still answered: error=%q Location=%q", got, loc)
	}
}

// prompt=login is a relying party demanding a FRESH credential. An existing
// session is exactly what must not be spent, so the browser is sent to the login
// page even though the person is signed in.
func TestSilent_PromptLoginForcesTheScreen(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	q := silentQuery("verifier-prompt-login-01234567890123456789012345678")
	q.Set("prompt", "login")
	resp := authorizeWith(t, app, q, cookie, nil)

	loc := requireRedirect(t, resp, hostedLoginPath)
	if strings.Contains(loc, "code=") {
		t.Fatalf("prompt=login spent the session anyway: %q", loc)
	}
	if !strings.Contains(loc, "prompt=login") {
		t.Errorf("the page was not told which prompt it is serving: %q", loc)
	}
}

// prompt=select_account asks the human WHICH identity to use — a question only
// they can answer, so it is never answered from the ambient session. The value
// is carried to the page, which is what lets a chooser be rendered there.
func TestSilent_PromptSelectAccountReachesThePage(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	q := silentQuery("verifier-select-account-012345678901234567890123456")
	q.Set("prompt", "select_account")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), hostedLoginPath)
	if strings.Contains(loc, "code=") {
		t.Fatalf("select_account spent the session: %q", loc)
	}
	if !strings.Contains(loc, "prompt=select_account") {
		t.Fatalf("select_account was not forwarded to the page: %q", loc)
	}
}

// `none` together with any other value is a contradiction, and the spec makes it
// an error rather than a preference (OIDC Core §3.1.2.1).
func TestSilent_PromptNoneCombinedIsInvalidRequest(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	q := silentQuery("verifier-combined-prompt-01234567890123456789012345")
	q.Set("prompt", "none login")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
	u, _ := url.Parse(loc)
	if got := u.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request (%q)", got, loc)
	}
	if u.Query().Get("code") != "" {
		t.Fatal("a contradictory request must not be granted")
	}
}

// A prompt value this server does not implement forces INTERACTION rather than
// being ignored. An unknown directive might be the one asking for a stronger
// check; the fail-safe reading is to ask the human, never to hand out a grant.
func TestSilent_UnknownPromptFallsBackToInteraction(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	q := silentQuery("verifier-unknown-prompt-012345678901234567890123456")
	q.Set("prompt", "consent")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), hostedLoginPath)
	if strings.Contains(loc, "code=") {
		t.Fatalf("an unrecognized prompt was silently granted: %q", loc)
	}
}

// A FRAMED or FETCHED request may not spend the session, even with a live
// cookie. Silent SSO is a top-level redirect and nothing else, so a page that
// merely embeds the authorize endpoint cannot harvest a code for its visitor.
func TestSilent_FramedRequestCannotSpendTheSession(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	for _, dest := range []string{"iframe", "frame", "empty", "image", "object"} {
		t.Run(dest, func(t *testing.T) {
			q := silentQuery("verifier-framed-" + dest + "-0123456789012345678901234")
			q.Set("prompt", "none")
			resp := authorizeWith(t, app, q, cookie, map[string]string{"Sec-Fetch-Dest": dest})
			loc := requireRedirect(t, resp, secondRedirect)
			u, _ := url.Parse(loc)
			if u.Query().Get("code") != "" {
				t.Fatalf("a %s request harvested a code: %q", dest, loc)
			}
			if got := u.Query().Get("error"); got != errInteractionRequired {
				t.Fatalf("error = %q, want %q", got, errInteractionRequired)
			}
		})
	}
}

// max_age is honoured. A client asking for a sign-in no older than N seconds
// must not be answered silently from an older one — the specific lie it asks the
// question to avoid.
func TestSilent_MaxAgeRefusesAStaleSession(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	t.Run("max_age=0 can never be satisfied by an existing session", func(t *testing.T) {
		q := silentQuery("verifier-maxage-zero-0123456789012345678901234567")
		q.Set("prompt", "none")
		q.Set("max_age", "0")
		loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
		u, _ := url.Parse(loc)
		if u.Query().Get("code") != "" {
			t.Fatalf("max_age=0 was answered from an existing session: %q", loc)
		}
		if got := u.Query().Get("error"); got != errLoginRequired {
			t.Fatalf("error = %q, want %q", got, errLoginRequired)
		}
	})

	t.Run("a generous max_age is satisfied", func(t *testing.T) {
		q := silentQuery("verifier-maxage-wide-0123456789012345678901234567")
		q.Set("prompt", "none")
		q.Set("max_age", "86400")
		codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect))
	})

	t.Run("the clock is what decides, not the wording", func(t *testing.T) {
		// Ten minutes pass; a five-minute max_age no longer holds.
		nowFuncSet(t, time.Now().Add(10*time.Minute))
		q := silentQuery("verifier-maxage-elapsed-01234567890123456789012345")
		q.Set("prompt", "none")
		q.Set("max_age", "300")
		loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
		u, _ := url.Parse(loc)
		if u.Query().Get("code") != "" {
			t.Fatalf("a session older than max_age was spent: %q", loc)
		}
	})
}

// id_token_hint names the person the client believes is signed in. When somebody
// ELSE is, the client is told login_required rather than handed a grant for a
// different human — the identity-swap a silent renewal would otherwise perform
// with nothing on screen to notice.
func TestSilent_IdTokenHintBindsTheSubject(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	seedUserInOrg(t, db, "hanzo", "bob", "bob@hanzo.ai", "pw")
	cookie := signIn(t, app, "portal") // alice

	t.Run("a hint naming somebody else is refused", func(t *testing.T) {
		q := silentQuery("verifier-hint-other-01234567890123456789012345678")
		q.Set("prompt", "none")
		q.Set("id_token_hint", idTokenFor(t, db, "hanzo", "bob", "second", -time.Hour))
		loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
		u, _ := url.Parse(loc)
		if u.Query().Get("code") != "" {
			t.Fatalf("a grant was issued for a subject the client did not ask for: %q", loc)
		}
		if got := u.Query().Get("error"); got != errLoginRequired {
			t.Fatalf("error = %q, want %q", got, errLoginRequired)
		}
	})

	t.Run("an EXPIRED hint naming the right person still works", func(t *testing.T) {
		// This is the normal case: a relying party sends its LAST id_token to ask
		// whether the same person is still signed in, which one does precisely
		// when it has run out.
		q := silentQuery("verifier-hint-expired-012345678901234567890123456")
		q.Set("prompt", "none")
		q.Set("id_token_hint", idTokenFor(t, db, "hanzo", "alice", "second", -time.Hour))
		codeFromLocation(t, requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect))
	})

	t.Run("an unsigned hint is refused", func(t *testing.T) {
		q := silentQuery("verifier-hint-forged-0123456789012345678901234567")
		q.Set("prompt", "none")
		q.Set("id_token_hint", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJoYW56by9hbGljZSJ9.")
		loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
		if u, _ := url.Parse(loc); u.Query().Get("code") != "" {
			t.Fatalf("a forged hint was accepted: %q", loc)
		}
	})
}

// THE ALLOW-LIST IS NOT WEAKENED TO MAKE THIS WORK. An unregistered redirect_uri
// is still answered in place, with no redirect and no code — even for a browser
// carrying a perfectly good session, and even when it asks for no interaction.
// This is the check that made a wrong client fail correctly rather than silently
// succeed, and silent SSO runs entirely BEHIND it.
func TestSilent_UnregisteredRedirectStillRefusedInPlace(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	q := silentQuery("verifier-bad-redirect-012345678901234567890123456")
	q.Set("prompt", "none")
	q.Set("redirect_uri", "https://evil.example/steal")
	resp := authorizeWith(t, app, q, cookie, nil)

	if resp.StatusCode != 400 {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); loc != "" {
		t.Fatalf("an unregistered redirect_uri was redirected to: %q", loc)
	}
}

// A public client still cannot skip PKCE by going silent — the downgrade is
// refused before any session is consulted.
func TestSilent_PublicClientStillNeedsPKCE(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	q := silentQuery("unused")
	q.Del("code_challenge")
	q.Del("code_challenge_method")
	q.Set("prompt", "none")
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
	u, _ := url.Parse(loc)
	if u.Query().Get("code") != "" {
		t.Fatalf("a public client got a silent code with no PKCE: %q", loc)
	}
	if got := u.Query().Get("error"); got != "invalid_request" {
		t.Fatalf("error = %q, want invalid_request", got)
	}
}

// An account forbidden or deleted SINCE it signed in does not ride its old
// session into a new application. The row is re-read on every silent grant.
func TestSilent_ForbiddenAccountCannotRideItsSession(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(*schema.User)
	}{
		{"forbidden", func(u *schema.User) { u.IsForbidden = true }},
		{"deleted", func(u *schema.User) { u.IsDeleted = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			twoApps(t, db)
			cookie := signIn(t, app, "portal")

			u, err := orm.Get[schema.User](db, "hanzo/alice")
			if err != nil || u == nil {
				t.Fatalf("load user: %v", err)
			}
			tc.set(u)
			if err := u.Update(); err != nil {
				t.Fatalf("update user: %v", err)
			}

			q := silentQuery("verifier-forbidden-" + tc.name + "-012345678901234567890")
			q.Set("prompt", "none")
			loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
			if pu, _ := url.Parse(loc); pu.Query().Get("code") != "" {
				t.Fatalf("a %s account was silently granted: %q", tc.name, loc)
			}
		})
	}
}

// RESERVED-ORG CONFINEMENT holds on the silent path. A SuperAdmin session must
// not be spendable through a SHARED application — the app kind whose tenant rule
// accepts every org by design — or an ambient admin session would mint a real
// admin grant for any shared app with no interaction at all.
func TestSilent_ReservedOrgConfinedOnTheSilentPath(t *testing.T) {
	app, db := newServer(t)
	// A shared app in org "hanzo": its tenant rule admits every organization.
	seedApp(t, db, appOpts{clientID: "shared", redirectURIs: []string{secondRedirect}, shared: true})
	// The admin console, serving the reserved org, is where an admin may sign in.
	console := seedApp(t, db, appOpts{clientID: "console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	console.Organization = "admin"
	if err := console.Update(); err != nil {
		t.Fatalf("retarget console: %v", err)
	}
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "pw")

	// Sign the admin in at their own console.
	form := url.Values{
		"organization": {"admin"}, "application": {"console"},
		"username": {"root"}, "password": {"pw"}, "type": {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("admin sign-in failed: status=%d body=%s", resp.StatusCode, body)
	}
	cookie := cookieKV(resp.Header.Get("Set-Cookie"))

	// Now try to spend that session on the SHARED app, silently.
	verifier := "verifier-reserved-shared-01234567890123456789012345"
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"shared"},
		"redirect_uri":          {secondRedirect},
		"scope":                 {"openid"},
		"state":                 {"st-adm"},
		"prompt":                {"none"},
		"code_challenge":        {pkce.Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), secondRedirect)
	u, _ := url.Parse(loc)
	if u.Query().Get("code") != "" {
		t.Fatalf("a reserved-org session was silently granted through a shared app: %q", loc)
	}
	if got := u.Query().Get("error"); got != errAccessDenied {
		t.Fatalf("error = %q, want %q", got, errAccessDenied)
	}
}

// Discovery advertises exactly the prompt values that are honoured — a relying
// party cannot discover them by trying, because an ignored prompt=none is
// indistinguishable from a honoured one that found no session.
func TestSilent_DiscoveryAdvertisesThePromptValues(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)

	_, body := do(t, app, formReqNoBody("GET", PathDiscovery))
	doc := decode(t, body)
	raw, ok := doc["prompt_values_supported"].([]any)
	if !ok {
		t.Fatalf("discovery advertises no prompt_values_supported: %s", body)
	}
	got := map[string]bool{}
	for _, v := range raw {
		got[v.(string)] = true
	}
	for _, want := range promptValues {
		if !got[want] {
			t.Errorf("prompt_values_supported is missing %q: %v", want, raw)
		}
	}
	if len(raw) != len(promptValues) {
		t.Errorf("advertised %v, but only %v are implemented", raw, promptValues)
	}
}

// idTokenFor mints a signed id_token for (org/name) at the named client with the
// given lifetime — a NEGATIVE ttl produces the already-expired token a relying
// party actually sends as id_token_hint.
func idTokenFor(t *testing.T, db orm.DB, org, name, clientID string, ttl time.Duration) string {
	t.Helper()
	ctx := context.Background()
	a, err := ResolveApp(ctx, db, clientID, "")
	if err != nil || a == nil {
		t.Fatalf("resolve app %s: %v", clientID, err)
	}
	signer, err := signerFor(ctx, db, a, "https://hanzo.id")
	if err != nil {
		t.Fatalf("signer for %s: %v", clientID, err)
	}
	u, err := orm.Get[schema.User](db, org+"/"+name)
	if err != nil || u == nil {
		t.Fatalf("load %s/%s: %v", org, name, err)
	}
	tok, err := signer.SignID(a, identityOf(ctx, db, u), "openid", "", ttl, time.Now())
	if err != nil {
		t.Fatalf("mint id_token: %v", err)
	}
	return tok
}

// verifiedClaims verifies a signed token and returns its claims.
func verifiedClaims(t *testing.T, db orm.DB, tok string) *Claims {
	t.Helper()
	claims, err := verifyToken(context.Background(), db, tok)
	if err != nil {
		t.Fatalf("verify id_token: %v", err)
	}
	return claims
}

// The prompt handed to the hosted login page is RE-SERIALIZED from the values
// this server recognizes, never passed through. The authorize endpoint rebuilds
// the whole request from known parameters so nothing unexpected travels to a
// page it sends people to, and client-controlled text in `prompt` would have
// been the exception.
func TestSilent_ForwardedPromptIsReserialized(t *testing.T) {
	app, db := newServer(t)
	twoApps(t, db)
	cookie := signIn(t, app, "portal")

	q := silentQuery("verifier-prompt-injection-0123456789012345678901234")
	q.Set("prompt", `login "><script>alert(1)</script>`)
	loc := requireRedirect(t, authorizeWith(t, app, q, cookie, nil), hostedLoginPath)

	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("Location %q is not a URL: %v", loc, err)
	}
	if got := u.Query().Get("prompt"); got != promptLogin {
		t.Fatalf("prompt = %q, want exactly %q — the raw value must not survive", got, promptLogin)
	}
	if strings.Contains(loc, "script") {
		t.Fatalf("client-controlled text reached the login page: %q", loc)
	}
}
