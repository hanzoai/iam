// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/store"
)

// The /oauth/authorize SSO fast path — the browser mint the programmatic gate MISSED.
//
// Three cutovers were rolled back because the gate minted its codes via POST
// /v1/iam/login (type=code, challenge in the JSON body) and every variant went 200,
// while real browsers drove GET /oauth/authorize (challenge in the URL query) and got
// 401 invalid_client at redeem. The two endpoints minted codes that behaved DIFFERENTLY
// at the SAME token handler: /oauth/authorize never minted server-side at all — it 302'd
// to the hosted login — so the SSO browser's code came back non-PKCE (tok.CodeChallenge
// == "") and fell into the confidential branch, 401'ing a public secret-less redeem.
//
// The fix routes /oauth/authorize (authenticated session) through the SAME MintFor the
// credential login uses, persisting the query code_challenge onto the row server-side —
// matching the fork's fastAutoSignin. Every test below mints via /oauth/authorize, the
// path the gate never exercised. Each asserts a fail-before (v1.33.4 302'd to the hosted
// login, minting no server-side code → codeFromRedirect fails / the redeem 401'd).

// establishSession drives a bare (type=login) sign-in and returns the "hanzo_session=…"
// cookie to replay — the SSO precondition the /oauth/authorize fast path reads.
func establishSession(t *testing.T, app *zip.App, org, application, username, password string) string {
	t.Helper()
	form := url.Values{
		"organization": {org},
		"application":  {application},
		"username":     {username},
		"password":     {password},
		"type":         {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("establish session: status=%d body=%s", resp.StatusCode, body)
	}
	cookie := resp.Header.Get("Set-Cookie")
	if !strings.HasPrefix(cookie, "hanzo_session=") {
		t.Fatalf("login did not set the session cookie: %q", cookie)
	}
	return cookieKV(cookie)
}

// authorizeSSO drives GET /oauth/authorize WITH a session cookie and returns the 302
// Location. With the fix the fast path mints the code and redirects to the client's
// redirect_uri; on v1.33.4 (no fast path) it 302'd to the hosted login instead.
func authorizeSSO(t *testing.T, app *zip.App, cookie string, q url.Values) string {
	t.Helper()
	req := formReqNoBody("GET", authorizeURL(q))
	req.Header.Set("Cookie", cookie)
	resp, _ := do(t, app, req)
	if resp.StatusCode != 302 {
		t.Fatalf("authorize (SSO) status=%d, want 302", resp.StatusCode)
	}
	return resp.Header.Get("Location")
}

// codeFromRedirect asserts loc is a redirect BACK to the registered redirect_uri (NOT
// the hosted login) and returns the authorization code on it. THE FAIL-BEFORE lives
// here: v1.33.4 had no SSO fast path, so authorize 302'd to hostedLoginPath and minted
// no server-side code — this helper fails there.
func codeFromRedirect(t *testing.T, loc string) string {
	t.Helper()
	if !strings.HasPrefix(loc, testRedirect) {
		t.Fatalf("authorize did not redirect to the client redirect_uri with a code; Location=%q "+
			"(FAIL-BEFORE: v1.33.4 302'd to the hosted login %q, minting no server-side code)", loc, hostedLoginPath)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse redirect %q: %v", loc, err)
	}
	code := u.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code on the redirect: %q", loc)
	}
	return code
}

// (1) THE BROKEN CASE. A public secret-less client drives /oauth/authorize with an S256
// challenge from an authenticated session → the fast path mints a PKCE-bound code and
// 302s back → the code redeems with ONLY a code_verifier (NO secret) → 200. On v1.33.4
// authorize minted no server-side code (302 to the hosted login), so the SSO browser's
// code came back non-PKCE and its secret-less redeem 401'd invalid_client.
func TestAuthorizeSSO_PublicPKCE_RedeemsWithoutSecret(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, autosignin: true})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	cookie := establishSession(t, app, "hanzo", "pub", "alice", "pw")

	q := url.Values{
		"response_type":  {"code"},
		"client_id":      {"pub"},
		"redirect_uri":   {testRedirect},
		"scope":          {"openid"},
		"state":          {"st-1"},
		"code_challenge": {ComputeS256Challenge(pkceVerifier)},
	}
	loc := authorizeSSO(t, app, cookie, q)
	if !strings.Contains(loc, "state=st-1") {
		t.Fatalf("state not echoed on the SSO redirect: %q", loc)
	}
	code := codeFromRedirect(t, loc)

	resp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"pub"}, "redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
		// no client_secret — a public browser client has none
	})
	if resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("authorize-minted PKCE code redeemed without secret: status=%d body=%v; want 200 "+
			"(FAIL-BEFORE: authorize minted no PKCE code from the session → the non-PKCE redeem 401'd)", resp.StatusCode, tok)
	}
}

// (2) THE REGRESSION SHAPE. A migrated dual-use record (stored secret) authorized via the
// SSO fast path with PKCE, then redeemed while ALSO echoing a STALE client_secret — via
// the FORM and via HTTP Basic — → 200 both ways. PKCE authenticates; the presented secret
// is ignored. This is the exact in-browser shape (the SPA echoes a configured stale
// secret) the prior programmatic gate never reproduced because it sent no secret.
func TestAuthorizeSSO_PublicPKCE_IgnoresStaleSecret(t *testing.T) {
	newAuthorizedCode := func(t *testing.T) (*zip.App, string) {
		t.Helper()
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "pub", secret: migratedSecret, redirectURIs: []string{testRedirect}, autosignin: true})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
		cookie := establishSession(t, app, "hanzo", "pub", "alice", "pw")
		q := url.Values{
			"response_type": {"code"}, "client_id": {"pub"}, "redirect_uri": {testRedirect},
			"scope": {"openid"}, "code_challenge": {ComputeS256Challenge(pkceVerifier)},
		}
		return app, codeFromRedirect(t, authorizeSSO(t, app, cookie, q))
	}

	t.Run("stale_form_secret_200", func(t *testing.T) {
		app, code := newAuthorizedCode(t)
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"pub"}, "client_secret": {"STALE-secret-from-the-SPA"},
			"redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
		})
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("authorize PKCE redeem with a stale FORM secret: status=%d body=%v; want 200", resp.StatusCode, tok)
		}
	})

	t.Run("stale_basic_secret_200", func(t *testing.T) {
		app, code := newAuthorizedCode(t)
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"pub"},
			"redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
		}
		req := formReq("POST", PathToken, form)
		req.SetBasicAuth("pub", "STALE-secret-from-the-SPA")
		resp, body := do(t, app, req)
		tok := decode(t, body)
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("authorize PKCE redeem with a stale BASIC secret: status=%d body=%v; want 200", resp.StatusCode, tok)
		}
	})
}

// (3) CONFIDENTIAL, UNCHANGED. A confidential client (registered secret) authorizes via
// the SSO fast path WITHOUT PKCE (allowed — it has a secret) and mints a non-PKCE code:
// the correct secret redeems 200; a wrong OR absent secret 401s. The confidential path
// is exactly as strict as before — the browser fix never downgrades it.
func TestAuthorizeSSO_Confidential_NonPKCE(t *testing.T) {
	newAuthorizedCode := func(t *testing.T) (*zip.App, string) {
		t.Helper()
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, autosignin: true})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
		cookie := establishSession(t, app, "hanzo", "conf", "alice", "pw")
		// No code_challenge — a confidential client may authorize without PKCE.
		q := url.Values{"response_type": {"code"}, "client_id": {"conf"}, "redirect_uri": {testRedirect}, "scope": {"openid"}}
		return app, codeFromRedirect(t, authorizeSSO(t, app, cookie, q))
	}

	t.Run("correct_secret_200", func(t *testing.T) {
		app, code := newAuthorizedCode(t)
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
		})
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("confidential authorize redeem with correct secret: status=%d body=%v; want 200", resp.StatusCode, tok)
		}
	})

	t.Run("wrong_secret_401", func(t *testing.T) {
		app, code := newAuthorizedCode(t)
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"conf"}, "client_secret": {"WRONG"}, "redirect_uri": {testRedirect},
		})
		requireError(t, resp, tok, 401, "invalid_client")
	})

	t.Run("no_secret_401", func(t *testing.T) {
		app, code := newAuthorizedCode(t)
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"conf"}, "redirect_uri": {testRedirect},
		})
		requireError(t, resp, tok, 401, "invalid_client")
	})
}

// (4) THE UNIFICATION PROOF. The SAME client + SAME PKCE challenge, minted BOTH ways —
// via /oauth/authorize (challenge from the URL query) and via /v1/iam/login (challenge
// from the JSON body) — persist byte-IDENTICAL redeem-deciding fields (CodeChallenge,
// method, owner-pinned user, app + redirect binding) and both redeem 200 with the same
// verifier and no secret. This is what "one and only one mint routine" guarantees: a code
// can no longer diverge by which endpoint minted it.
func TestAuthorizeSSO_UnificationParity(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, autosignin: true})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	ctx := context.Background()
	challenge := ComputeS256Challenge(pkceVerifier)

	// (a) authorize-minted (SSO fast path, challenge from the QUERY)
	cookie := establishSession(t, app, "hanzo", "pub", "alice", "pw")
	authCode := codeFromRedirect(t, authorizeSSO(t, app, cookie, url.Values{
		"response_type": {"code"}, "client_id": {"pub"}, "redirect_uri": {testRedirect},
		"scope": {"openid"}, "code_challenge": {challenge},
	}))

	// (b) login-minted (POST /v1/iam/login type=code, challenge from the BODY)
	loginCode, _, _ := loginForCode(t, app, loginPKCE("pub", "openid"))

	authTok, err := store.GetTokenByCode(ctx, db, authCode)
	if err != nil || authTok == nil {
		t.Fatalf("load authorize-minted code row: %v", err)
	}
	loginTok, err := store.GetTokenByCode(ctx, db, loginCode)
	if err != nil || loginTok == nil {
		t.Fatalf("load login-minted code row: %v", err)
	}

	// The redeem-deciding PKCE binding must be IDENTICAL — the crux the fix unifies.
	if authTok.CodeChallenge != challenge || loginTok.CodeChallenge != challenge {
		t.Fatalf("CodeChallenge not persisted identically: authorize=%q login=%q want=%q",
			authTok.CodeChallenge, loginTok.CodeChallenge, challenge)
	}
	if authTok.CodeChallengeMethod != "S256" || loginTok.CodeChallengeMethod != "S256" {
		t.Fatalf("CodeChallengeMethod diverged: authorize=%q login=%q", authTok.CodeChallengeMethod, loginTok.CodeChallengeMethod)
	}
	// Owner-pinned identity, app binding, and redirect binding match too.
	if authTok.User != loginTok.User || authTok.User != "hanzo/alice" {
		t.Fatalf("User (owner-pinned) diverged: authorize=%q login=%q", authTok.User, loginTok.User)
	}
	if authTok.Application != loginTok.Application || authTok.RedirectUri != loginTok.RedirectUri {
		t.Fatalf("app/redirect binding diverged: authorize=(%q,%q) login=(%q,%q)",
			authTok.Application, authTok.RedirectUri, loginTok.Application, loginTok.RedirectUri)
	}

	// Behaviorally identical: both redeem 200 with the same verifier and NO secret.
	for _, code := range []string{authCode, loginCode} {
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"pub"}, "redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
		})
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("code %q did not redeem identically: status=%d body=%v", code, resp.StatusCode, tok)
		}
	}
}

// (5) SECURITY — the SSO fast path must NOT bypass the reserved-org gate (F-D2). A
// SuperAdmin (org "admin") holding a valid session who hits /oauth/authorize for a SHARED
// or ORG-CHOICE autosignin app must NOT get a code minted: it would be a real SuperAdmin
// authorization code granted on the session alone, cross-tenant. Because the fast path
// mints through MintFor, MintFor carries the reserved-org gate — the SAME refuse login.go,
// signup.go and the ROPC grant enforce — so authorize refuses and falls through to the
// hosted login. Every front door that mints is bound identically; none can be the one
// that omits the gate.
func TestAuthorizeSSO_reservedOrg_refusedThroughSharedApp(t *testing.T) {
	for _, tc := range []struct {
		name string
		app  fullApp
	}{
		{"shared", fullApp{clientID: "shared-portal", secret: "s3cret", org: "hanzo", shared: true, autosignin: true, redirects: []string{testRedirect}}},
		{"orgChoice", fullApp{clientID: "choice-portal", secret: "s3cret", org: "hanzo", orgChoice: "user", autosignin: true, redirects: []string{testRedirect}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			// The dedicated admin-console (serves the admin org) — the ONLY app that may
			// establish a SuperAdmin session.
			seedAppFull(t, db, fullApp{clientID: "admin-console", secret: "s3cret", org: "admin", redirects: []string{testRedirect}})
			seedAppFull(t, db, tc.app) // the cross-tenant SSO target
			seedOrg(t, db, "admin")
			seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "correct horse") // the SuperAdmin

			cookie := establishSession(t, app, "admin", "admin-console", "root", "correct horse")

			loc := authorizeSSO(t, app, cookie, url.Values{
				"response_type": {"code"}, "client_id": {tc.app.clientID}, "redirect_uri": {testRedirect}, "scope": {"openid"},
			})
			// It must NOT mint a code back to the client — no SuperAdmin code may exist to
			// redeem. It falls through to the hosted login instead.
			if strings.HasPrefix(loc, testRedirect) {
				t.Fatalf("F-D2 REOPENED: the SSO fast path minted a SuperAdmin code for a reserved-org "+
					"principal through a %s app; Location=%q", tc.name, loc)
			}
			if !strings.HasPrefix(loc, hostedLoginPath) {
				t.Fatalf("expected fall-through to the hosted login; Location=%q", loc)
			}
		})
	}
}
