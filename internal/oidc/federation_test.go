// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Federation is driven through the REAL registered routes (authorize → IdP → callback
// → code → token). The external IdP is an httptest server — a real HTTP RP round
// trip with a real OIDC discovery document, a real JWKS, and a real RS256-signed
// id_token whose signature/issuer/audience/nonce iam actually verifies (Google
// dialect), plus a real GitHub userinfo + verified-email exchange. No live
// Google/GitHub is contacted.

const (
	fedAppState   = "app-state-xyz"
	fedVerifier   = "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	fedGoogleCID  = "google-oauth-client"
	fedGitHubCID  = "github-oauth-client"
	fedProvGoogle = "provider-google"
	fedProvGitHub = "provider-github"
)

// ---------------------------------------------------------------------------
// Mock OIDC IdP (Google-shaped): discovery + JWKS + RS256 id_token.
// ---------------------------------------------------------------------------

type mockOIDC struct {
	*httptest.Server
	key      *rsa.PrivateKey
	wrongKey *rsa.PrivateKey
	kid      string
	clientID string

	mu             sync.Mutex
	sub            string
	email          string
	name           string
	emailVerified  bool
	nonce          string // baked into the id_token; bound from the authorize redirect
	signWrong      bool   // sign with wrongKey → signature must fail
	noneAlg        bool   // emit an alg=none (unsigned) id_token → must be rejected
	issuerOverride string // override id_token iss (issuer-confusion test)
	audOverride    string // override id_token aud (audience test)
	tokenForm      url.Values
}

// allowPrivateFederationDial hands the IdP calls a plain client for the test's
// duration so the httptest mock IdPs (bound to 127.0.0.1) are reachable — the same
// package-var test-injection pattern as nowFuncSet. It follows no redirect, like
// the production client; the address rule itself is outbound's and is pinned by
// TestFederationClientRefusesNonPublicAddresses.
func allowPrivateFederationDial(t *testing.T) {
	t.Helper()
	prev := federationHTTPClient
	federationHTTPClient = &http.Client{
		Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("federation: an idp endpoint does not redirect")
		},
	}
	t.Cleanup(func() { federationHTTPClient = prev })
}

func newMockOIDC(t *testing.T, clientID string) *mockOIDC {
	t.Helper()
	allowPrivateFederationDial(t)
	m := &mockOIDC{
		key:           mustGenRSA(t),
		wrongKey:      mustGenRSA(t),
		kid:           "mock-oidc-kid",
		clientID:      clientID,
		sub:           "google-sub-1001",
		email:         "alice@example.com",
		name:          "Alice Example",
		emailVerified: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, map[string]any{
			"issuer":                 m.URL,
			"authorization_endpoint": m.URL + "/authorize",
			"token_endpoint":         m.URL + "/token",
			"userinfo_endpoint":      m.URL + "/userinfo",
			"jwks_uri":               m.URL + "/jwks",
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		pub := m.key.PublicKey
		writeJSON(w, map[string]any{"keys": []map[string]any{{
			"kty": "RSA", "use": "sig", "alg": "RS256", "kid": m.kid,
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.mu.Lock()
		m.tokenForm = r.Form
		iss := firstNonEmpty(m.issuerOverride, m.URL)
		aud := firstNonEmpty(m.audOverride, m.clientID)
		claims := jwt.MapClaims{
			"iss": iss, "sub": m.sub, "aud": aud,
			"exp":            time.Now().Add(time.Hour).Unix(),
			"iat":            time.Now().Add(-time.Minute).Unix(),
			"nonce":          m.nonce,
			"email":          m.email,
			"email_verified": m.emailVerified,
			"name":           m.name,
		}
		signKey := m.key
		if m.signWrong {
			signKey = m.wrongKey
		}
		noneAlg := m.noneAlg
		m.mu.Unlock()
		// The alg=none forgery: an unsigned token whose header claims no signature.
		if noneAlg {
			tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
			idt, _ := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
			writeJSON(w, map[string]any{"access_token": "x", "id_token": idt, "token_type": "Bearer"})
			return
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = m.kid
		idt, err := tok.SignedString(signKey)
		if err != nil {
			http.Error(w, "sign", 500)
			return
		}
		writeJSON(w, map[string]any{"access_token": "idp-at-" + randHex(6), "id_token": idt, "token_type": "Bearer"})
	})
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Close)
	return m
}

// ---------------------------------------------------------------------------
// Mock GitHub IdP (OAuth2 + userinfo + verified emails).
// ---------------------------------------------------------------------------

type mockGitHub struct {
	*httptest.Server
	mu           sync.Mutex
	id           int64
	login        string
	name         string
	profileEmail string
	emails       []map[string]any // {email, primary, verified}
	// emailsForbidden makes /user/emails answer 403, which is what a GitHub APP
	// whose "Email addresses" permission is missing really does — GitHub Apps
	// ignore the requested `scope`, so the read fails and no address arrives.
	emailsForbidden bool
	tokenForm       url.Values
}

func newMockGitHub(t *testing.T) *mockGitHub {
	t.Helper()
	allowPrivateFederationDial(t)
	m := &mockGitHub{
		id:    424242,
		login: "octocat",
		name:  "The Octocat",
		emails: []map[string]any{
			{"email": "octo-unverified@example.com", "primary": false, "verified": false},
			{"email": "octo@example.com", "primary": true, "verified": true},
		},
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		m.mu.Lock()
		m.tokenForm = r.Form
		m.mu.Unlock()
		writeJSON(w, map[string]any{"access_token": "gho-" + randHex(6), "token_type": "bearer", "scope": "read:user,user:email"})
	})
	mux.HandleFunc("/user/emails", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if m.emailsForbidden {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		writeJSON(w, m.emails)
	})
	mux.HandleFunc("/user", func(w http.ResponseWriter, _ *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		writeJSON(w, map[string]any{"id": m.id, "login": m.login, "name": m.name, "email": m.profileEmail, "avatar_url": "https://avatars/x"})
	})
	m.Server = httptest.NewServer(mux)
	t.Cleanup(m.Close)
	return m
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// Seeds + drivers.
// ---------------------------------------------------------------------------

// seedOIDCProvider seeds a Google-dialect Provider row whose OIDC issuer points
// at the mock, and links it (sign-in enabled) onto the app.
func seedOIDCProvider(t *testing.T, db orm.DB, appClientID string, m *mockOIDC) {
	t.Helper()
	p := orm.New[schema.Provider](db)
	p.Owner, p.Name = "admin", fedProvGoogle
	p.Category, p.Type = "OAuth", "Google"
	p.ClientId, p.ClientSecret = m.clientID, "google-secret-do-not-log"
	p.IssuerUrl = m.URL
	p.SetId("admin/" + fedProvGoogle)
	if err := p.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed google provider: %v", err)
	}
	linkProvider(t, db, appClientID, fedProvGoogle)
}

// seedGitHubProvider seeds a GitHub-dialect Provider row whose endpoints point at
// the mock, and links it onto the app.
func seedGitHubProvider(t *testing.T, db orm.DB, appClientID string, m *mockGitHub) {
	t.Helper()
	p := orm.New[schema.Provider](db)
	p.Owner, p.Name = "admin", fedProvGitHub
	p.Category, p.Type = "OAuth", "GitHub"
	p.ClientId, p.ClientSecret = fedGitHubCID, "github-secret-do-not-log"
	p.CustomAuthUrl = m.URL + "/authorize"
	p.CustomTokenUrl = m.URL + "/token"
	p.CustomUserInfoUrl = m.URL + "/user"
	p.SetId("admin/" + fedProvGitHub)
	if err := p.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed github provider: %v", err)
	}
	linkProvider(t, db, appClientID, fedProvGitHub)
}

// linkProvider appends a sign-in-enabled ProviderItem to an app and persists it.
func linkProvider(t *testing.T, db orm.DB, appClientID, providerName string) {
	t.Helper()
	a, err := orm.Get[schema.Application](db, "admin/"+appClientID)
	if err != nil {
		t.Fatalf("load app: %v", err)
	}
	a.Providers = append(a.Providers, &schema.ProviderItem{Owner: "admin", Name: providerName, CanSignIn: true, CanSignUp: true})
	if err := a.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("link provider: %v", err)
	}
}

// beginAuthorize drives GET /v1/iam/oauth/authorize with a provider hint and
// returns the IdP-authorize query (from the 302 Location) and the anti-forgery
// cookie the response set. It asserts the request is a 302 to an IdP.
func beginAuthorize(t *testing.T, app *zip.App, clientID, provider string) (url.Values, string) {
	t.Helper()
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid email profile"},
		"state":                 {fedAppState},
		"code_challenge":        {pkce.Challenge(fedVerifier)},
		"code_challenge_method": {"S256"},
		"provider":              {provider},
	}
	resp, _ := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+q.Encode()))
	if resp.StatusCode != 302 {
		t.Fatalf("authorize(provider) status = %d, want 302", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP authorize location: %v", err)
	}
	// A federation kickoff redirects to an ABSOLUTE external IdP URL, never to the
	// relative hosted-login path a credential flow uses.
	if !loc.IsAbs() || loc.Host == "" {
		t.Fatalf("authorize(provider) must redirect to an external IdP; got %q", loc.String())
	}
	return loc.Query(), cookieKV(resp.Header.Get("Set-Cookie"))
}

// callback drives GET /v1/iam/oauth/callback with the given state/code and the
// anti-forgery cookie.
func callback(t *testing.T, app *zip.App, state, code, cookie string) *http.Response {
	t.Helper()
	q := url.Values{"state": {state}, "code": {code}}
	req := formReqNoBody("GET", PathFederationCallback+"?"+q.Encode())
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, _ := do(t, app, req)
	return resp
}

// countUsers returns the number of users in the hanzo org.
func countUsers(t *testing.T, db orm.DB) int {
	t.Helper()
	n, err := orm.TypedQuery[schema.User](db).Filter("Owner=", "hanzo").Count(context.Background())
	if err != nil {
		t.Fatalf("count users: %v", err)
	}
	return n
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

// The authorize endpoint, given a provider hint, redirects the browser to the
// external IdP with response_type=code, our callback, a single-use state, S256
// PKCE, and (OIDC) a nonce — and sets the HttpOnly browser-binding cookie. The
// client_secret is NEVER on this browser-facing redirect.
func TestFederation_AuthorizeRedirectsToOIDCWithStatePKCENonce(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)

	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q", q.Get("response_type"))
	}
	if q.Get("client_id") != fedGoogleCID {
		t.Errorf("client_id = %q, want the provider's IdP client id", q.Get("client_id"))
	}
	if !strings.HasSuffix(q.Get("redirect_uri"), PathFederationCallback) {
		t.Errorf("redirect_uri = %q, want our callback", q.Get("redirect_uri"))
	}
	if q.Get("state") == "" {
		t.Error("state must be present (single-use CSRF token)")
	}
	if q.Get("nonce") == "" {
		t.Error("OIDC nonce must be present")
	}
	if q.Get("code_challenge") == "" || q.Get("code_challenge_method") != "S256" {
		t.Errorf("IdP-leg PKCE missing: challenge=%q method=%q", q.Get("code_challenge"), q.Get("code_challenge_method"))
	}
	if cookie == "" || !strings.HasPrefix(cookie, fedCookieName+"=") {
		t.Errorf("anti-forgery cookie missing: %q", cookie)
	}
	// The provider secret must never cross to the browser.
	if strings.Contains(q.Encode(), "google-secret-do-not-log") {
		t.Fatal("client_secret leaked into the browser-facing IdP redirect")
	}
	// State is server-side single-use.
	if st, _ := store.GetFederationState(context.Background(), db, q.Get("state")); st == nil {
		t.Fatal("federation state row was not persisted")
	}
}

// GitHub authorize carries state (its CSRF defense) but no nonce (OAuth2, no
// id_token) and no PKCE by default.
func TestFederation_AuthorizeRedirectsToGitHub(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockGitHub(t)
	seedGitHubProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGitHub)
	if q.Get("state") == "" {
		t.Error("GitHub authorize must carry state")
	}
	if q.Get("nonce") != "" {
		t.Error("GitHub (OAuth2) must not carry an OIDC nonce")
	}
	if cookie == "" {
		t.Error("anti-forgery cookie must be set")
	}
}

// Full OIDC round-trip: a first-time login PROVISIONS a user (no password, not
// admin) and mints an iam authorization code; the relying party's existing PKCE
// code→token exchange then completes unchanged and carries the new user's sub.
func TestFederation_OIDCCallbackProvisionsUserAndIssuesCode(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce") // bind the transaction's real IdP nonce into the id_token
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	cb, _ := url.Parse(loc)
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatalf("callback must redirect with an iam code; got %q", loc)
	}
	if cb.Query().Get("state") != fedAppState {
		t.Errorf("app state not echoed: %q", cb.Query().Get("state"))
	}

	// A user was provisioned, linked by the Google subject, no password, no admin.
	u, err := store.GetUserByConnector(context.Background(), db, "hanzo", "google", m.sub)
	if err != nil || u == nil {
		t.Fatalf("provisioned user not found by connector subject: %v", err)
	}
	if u.PasswordHash != "" {
		t.Error("federated user must have NO password hash")
	}
	if u.IsAdmin {
		t.Fatal("federation must NEVER set isAdmin")
	}
	if !u.EmailVerified || u.Email != m.email {
		t.Errorf("verified email not carried: verified=%v email=%q", u.EmailVerified, u.Email)
	}
	if countUsers(t, db) != before+1 {
		t.Fatalf("expected exactly one new user")
	}

	// The iam code redeems through the ordinary PKCE token exchange, unchanged.
	tokResp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"webapp"}, "redirect_uri": {testRedirect}, "code_verifier": {fedVerifier},
	})
	if tokResp.StatusCode != 200 {
		t.Fatalf("iam code exchange failed: %d %v", tokResp.StatusCode, tok)
	}
	if tok["access_token"] == nil {
		t.Fatal("no access_token from the iam code exchange")
	}
	// The token subject is the provisioned user; no IdP token leaks into it.
	if body := tokenBody(tok); strings.Contains(body, "idp-at-") || strings.Contains(body, "google-secret-do-not-log") {
		t.Fatal("IdP access token / client secret leaked into the iam token response")
	}
}

// A brand that signs people in on its own site runs the WHOLE browser leg there —
// begin, cookie, IdP callback — and the tokens it ends in still carry the issuer.
// This is hanzo.ai under IAM_FEDERATION_ORIGIN_MAP={"hanzo.ai":"https://hanzo.ai"}:
// Google is handed https://hanzo.ai/v1/iam/oauth/callback (so its account chooser
// names hanzo.ai), and `iss` stays https://hanzo.id for every verifier that pins it.
func TestFederation_SigninHostRunsTheLegAndKeepsTheIssuer(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	const callbackURL = "https://hanzo.ai" + PathFederationCallback

	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {"webapp"},
		"redirect_uri":          {testRedirect},
		"scope":                 {"openid email profile"},
		"state":                 {fedAppState},
		"code_challenge":        {pkce.Challenge(fedVerifier)},
		"code_challenge_method": {"S256"},
		"provider":              {fedProvGoogle},
	}
	req := formReqNoBody("GET", PathAuthorize+"?"+q.Encode())
	req.Host = "hanzo.ai"
	resp, _ := do(t, app, req)
	if resp.StatusCode != 302 {
		t.Fatalf("authorize on hanzo.ai: status %d (Location %q), want 302 to the IdP", resp.StatusCode, resp.Header.Get("Location"))
	}
	idp, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || !strings.HasPrefix(idp.String(), m.URL) {
		t.Fatalf("authorize on hanzo.ai must go to the IdP; got %q", resp.Header.Get("Location"))
	}
	if got := idp.Query().Get("redirect_uri"); got != callbackURL {
		t.Fatalf("the IdP was handed %q, want hanzo.ai's own callback %q", got, callbackURL)
	}
	cookie := cookieKV(resp.Header.Get("Set-Cookie"))
	if !strings.HasPrefix(cookie, "__Host-hanzo_fed=") {
		t.Fatalf("the begin on hanzo.ai must set the browser binding there; Set-Cookie %q", resp.Header.Get("Set-Cookie"))
	}
	// hanzo.ai has sibling hosts, so the binding is one no sibling can set: a
	// `__Host-` cookie, which a browser keeps only Secure, at Path=/, with no Domain.
	set := strings.ToLower(resp.Header.Get("Set-Cookie"))
	for _, want := range []string{"path=/;", "secure", "httponly", "samesite=lax"} {
		if !strings.Contains(set+";", want) {
			t.Errorf("binding cookie %q lacks %q", resp.Header.Get("Set-Cookie"), want)
		}
	}
	if strings.Contains(set, "domain=") {
		t.Errorf("binding cookie %q names a Domain; a __Host- cookie with one is dropped by the browser", resp.Header.Get("Set-Cookie"))
	}
	m.mu.Lock()
	m.nonce = idp.Query().Get("nonce")
	m.mu.Unlock()

	cq := url.Values{"state": {idp.Query().Get("state")}, "code": {"idp-code-1"}}
	cb := formReqNoBody("GET", PathFederationCallback+"?"+cq.Encode())
	cb.Host = "hanzo.ai"
	cb.Header.Set("Cookie", cookie)
	resp, _ = do(t, app, cb)
	ret, _ := url.Parse(requireRedirect(t, resp, testRedirect))
	code := ret.Query().Get("code")
	if code == "" {
		t.Fatalf("the callback on hanzo.ai must mint a code; got %q", ret.String())
	}
	m.mu.Lock()
	presented := m.tokenForm.Get("redirect_uri")
	m.mu.Unlock()
	if presented != callbackURL {
		t.Errorf("the IdP token exchange re-presented %q, want %q", presented, callbackURL)
	}

	// The code is redeemed ON hanzo.ai, the host the whole leg ran on, so nothing
	// but the issuer resolver can be what puts https://hanzo.id in the tokens.
	form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"webapp"},
		"redirect_uri": {testRedirect}, "code_verifier": {fedVerifier}}
	treq := formReq("POST", PathToken, form)
	treq.Host = "hanzo.ai"
	tokResp, body := do(t, app, treq)
	tok := decode(t, body)
	if tokResp.StatusCode != 200 {
		t.Fatalf("code exchange: %d %v", tokResp.StatusCode, tok)
	}
	for _, kind := range []string{"access_token", "id_token"} {
		raw, _ := tok[kind].(string)
		var claims jwt.MapClaims
		if _, _, err := jwt.NewParser().ParseUnverified(raw, &claims); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if claims["iss"] != "https://hanzo.id" {
			t.Errorf("%s iss = %v; signing in on hanzo.ai must leave the issuer at https://hanzo.id", kind, claims["iss"])
		}
	}
	// And discovery asked on hanzo.ai names the same issuer.
	dreq := formReqNoBody("GET", PathDiscovery)
	dreq.Host = "hanzo.ai"
	_, dbody := do(t, app, dreq)
	if iss := decode(t, dbody)["issuer"]; iss != "https://hanzo.id" {
		t.Errorf("discovery on hanzo.ai names issuer %v, want https://hanzo.id", iss)
	}
}

// The GitHub dialect: token exchange + /user + /user/emails, provisioning by the
// primary VERIFIED email.
func TestFederation_GitHubCallbackProvisionsViaVerifiedEmail(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockGitHub(t)
	seedGitHubProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGitHub)
	resp := callback(t, app, q.Get("state"), "gh-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	if code := mustQuery(t, loc).Get("code"); code == "" {
		t.Fatalf("GitHub federation did not mint an iam code: %q", loc)
	}
	u, err := store.GetUserByConnector(context.Background(), db, "hanzo", "github", "424242")
	if err != nil || u == nil {
		t.Fatalf("GitHub user not provisioned by subject: %v", err)
	}
	if u.Email != "octo@example.com" || !u.EmailVerified {
		t.Errorf("expected the primary verified email; got %q verified=%v", u.Email, u.EmailVerified)
	}
	// The GitHub client secret only ever went to the token endpoint (server-side).
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tokenForm.Get("client_secret") != "github-secret-do-not-log" {
		t.Errorf("expected the secret at the token endpoint, form=%v", m.tokenForm)
	}
}

// A returning federated user (same subject) is matched by subject — no duplicate
// account is created on the second login.
func TestFederation_ReloginBySubjectIsStable(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	runOIDCLogin(t, app, db, m, "webapp", nil)
	after1 := countUsers(t, db)
	runOIDCLogin(t, app, db, m, "webapp", nil)
	if countUsers(t, db) != after1 {
		t.Fatalf("second login by the same subject must not create a new user")
	}
}

// A verified IdP email that matches an EXISTING account whose address is verified
// too LINKS to it (sets the connector column) instead of creating a duplicate, and
// leaves its password as it was.
func TestFederation_LinksExistingAccountByVerifiedEmail(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@example.com", "pw") // pre-existing password account, same email
	u := userRow(t, db, "alice")
	u.EmailVerified = true
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	runOIDCLogin(t, app, db, m, "webapp", nil)
	if countUsers(t, db) != before {
		t.Fatalf("verified-email login must link, not create a duplicate")
	}
	// The Google subject is now linked onto the pre-existing account.
	linked, _ := store.GetUserByName(context.Background(), db, "hanzo", "alice")
	if linked == nil || linked.Google != m.sub {
		t.Fatalf("connector subject not linked onto the existing account: %+v", linked)
	}
	if linked.PasswordHash != u.PasswordHash {
		t.Fatal("the link rewrote the account's password")
	}
}

// An account with no password and an unverified address links the same way, and
// is left with no password.
func TestFederation_LinksAPasswordlessAccountByVerifiedEmail(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@example.com", "") // invited, never set a password
	u := userRow(t, db, "alice")
	u.PasswordHash, u.PasswordType = "", ""
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	runOIDCLogin(t, app, db, m, "webapp", nil)
	if countUsers(t, db) != before {
		t.Fatalf("a passwordless account must be linked, not duplicated")
	}
	linked, _ := store.GetUserByName(context.Background(), db, "hanzo", "alice")
	if linked == nil || linked.Google != m.sub || !linked.EmailVerified {
		t.Fatalf("connector not linked onto the passwordless account: %+v", linked)
	}
	if linked.PasswordHash != "" {
		t.Fatal("the link gave a passwordless account a password")
	}
}

// A verified IdP address that matches an account made with a password, whose own
// address was never verified, signs in AS that account: the same row, the
// provider subject linked, the address now verified. The password keeps signing
// in, the session the account already held stays live, and the link is audited
// with the provider subject and no credential.
func TestFederation_LinksAnUnverifiedAccountWithAPassword(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@example.com", "pw")
	before := userRow(t, db, "alice")
	if before.EmailVerified || before.PasswordHash == "" {
		t.Fatalf("premise: a password and an unverified address: %+v", before)
	}
	session := signIn(t, app, "webapp")
	m := newMockOIDC(t, fedGoogleCID) // emailVerified: true, alice@example.com
	seedOIDCProvider(t, db, "webapp", m)
	count := countUsers(t, db)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-link", cookie), testRedirect)
	code := mustQuery(t, loc).Get("code")
	if code == "" {
		t.Fatalf("a verified address did not sign in to the account that holds it: %q", loc)
	}
	resp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"webapp"}, "redirect_uri": {testRedirect}, "code_verifier": {fedVerifier},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("code exchange: %d %v", resp.StatusCode, tok)
	}
	raw, _ := tok["access_token"].(string)
	var claims jwt.MapClaims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &claims); err != nil {
		t.Fatal(err)
	}
	if claims["owner"] != "hanzo" || claims["name"] != "alice" {
		t.Fatalf("signed in as %v/%v, want hanzo/alice", claims["owner"], claims["name"])
	}

	after := userRow(t, db, "alice")
	if after.Id != before.Id {
		t.Fatalf("the account's id changed: %q -> %q", before.Id, after.Id)
	}
	if after.Google != m.sub || !after.EmailVerified {
		t.Fatalf("subject %q verified=%v, want %q verified", after.Google, after.EmailVerified, m.sub)
	}
	if after.PasswordHash != before.PasswordHash || after.IsAdmin != before.IsAdmin {
		t.Fatal("the link changed the account's password or admin bit")
	}
	if countUsers(t, db) != count {
		t.Fatalf("a second account appeared on the address (%d -> %d)", count, countUsers(t, db))
	}
	if !sessionLives(t, app, session) {
		t.Fatal("the link ended a session the account already held")
	}
	signIn(t, app, "webapp") // the password still signs in

	rows, err := orm.TypedQuery[schema.AuditLog](db).Filter("Action=", schema.ActionFederationLink).GetAll(tctx())
	if err != nil || len(rows) != 1 {
		t.Fatalf("link audit rows = %d (%v), want 1", len(rows), err)
	}
	row := rows[0]
	if row.Owner != "hanzo" || row.Organization != "hanzo" || row.User != "hanzo/alice" {
		t.Fatalf("audit row filed as %s, %s, %s; want hanzo, hanzo, hanzo/alice", row.Owner, row.Organization, row.User)
	}
	for _, want := range []string{`"subject":"` + m.sub + `"`, `"provider":"` + fedProvGoogle + `"`, `"client":"webapp"`, `"emailVerified":false`} {
		if !strings.Contains(row.Object, want) {
			t.Errorf("audit object %s lacks %s", row.Object, want)
		}
	}
	if strings.Contains(row.Object, before.PasswordHash) {
		t.Fatal("the audit row carries the password digest")
	}
	if !schema.PlatformWritten(row.Action) {
		t.Fatal("the link audit action is writable by a request")
	}
}

// An account a founding application made from a password signup — moved into an
// org of its own, made its admin, its address never verified — is the account a
// later sign-in with the same verified address reaches.
func TestFederation_LinksAFoundedPasswordAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")
	m := newMockOIDC(t, fedGoogleCID)
	const pw = "correct horse battery staple"
	if _, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo", "password": pw, "email": m.email,
	}); env["status"] != "ok" {
		t.Fatalf("signup: %v", env)
	}
	founded, err := store.GetUserByName(tctx(), db, "alice", "alice")
	if err != nil || founded == nil || founded.EmailVerified || founded.PasswordHash == "" || !founded.IsAdmin {
		t.Fatalf("premise: a founded admin with a password and an unverified address: %+v %v", founded, err)
	}
	seedOIDCProvider(t, db, "hanzo-cloud", m)

	runOIDCLogin(t, app, db, m, "hanzo-cloud", nil)
	after, _ := store.GetUserByName(tctx(), db, "alice", "alice")
	if after == nil || after.Id != founded.Id || after.Google != m.sub || !after.EmailVerified {
		t.Fatalf("the founded account was not the one linked: %+v", after)
	}
	if countUsersIn(t, db, "alice") != 1 || countUsers(t, db) != 0 {
		t.Fatal("the sign-in made a second account")
	}
	_, body := do(t, app, formReq("POST", PathLogin, url.Values{
		"organization": {"hanzo"}, "application": {"hanzo-cloud"},
		"username": {m.email}, "password": {pw}, "type": {"login"},
	}))
	if decode(t, body)["status"] != "ok" {
		t.Fatalf("the password no longer signs in: %s", body)
	}
}

// Two accounts on one address name nobody, so a verified address is refused
// rather than linked onto either, and no third account is made.
func TestFederation_AmbiguousAddressIsRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@example.com", "pw")
	seedUser(t, db, "alice2", "alice@example.com", "pw2")
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	qs := mustQuery(t, requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-two", cookie), testRedirect))
	if qs.Get("code") != "" || qs.Get("error") != "access_denied" || !strings.Contains(qs.Get("error_description"), "more than one account") {
		t.Fatalf("want access_denied naming the duplicate address, got %v", qs)
	}
	for _, name := range []string{"alice", "alice2"} {
		if u := userRow(t, db, name); u.Google != "" || u.EmailVerified {
			t.Fatalf("%s was linked: %+v", name, u)
		}
	}
	if countUsers(t, db) != before {
		t.Fatal("a third account was made on the address")
	}
}

// An account in the reserved admin org is never reached by an address: the
// lookups read the application's org and the accounts registered in it, and
// neither includes a reserved org. The admin account keeps its state, and the
// sign-in resolves to an ordinary account in the application's org.
func TestFederation_NeverLinksAnAdminOrgAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedUserInOrg(t, db, "admin", "root", m.email, "pw")
	root, err := orm.Get[schema.User](db, "admin/root")
	if err != nil {
		t.Fatal(err)
	}
	root.IsAdmin = true
	root.SignupApplication = "webapp" // registered through this application, as far as the row says
	if err := root.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	seedOIDCProvider(t, db, "webapp", m)

	runOIDCLogin(t, app, db, m, "webapp", nil)
	after, err := orm.Get[schema.User](db, "admin/root")
	if err != nil {
		t.Fatal(err)
	}
	if after.Google != "" || after.EmailVerified || after.PasswordHash != root.PasswordHash {
		t.Fatalf("the admin-org account was changed by a social sign-in: %+v", after)
	}
	u, err := store.GetUserByConnector(tctx(), db, "hanzo", "google", m.sub)
	if err != nil || u == nil || u.Owner != "hanzo" || u.IsAdmin {
		t.Fatalf("the sign-in resolved to %+v (%v), want an ordinary account in hanzo", u, err)
	}
}

// email_verified:false must NOT auto-link by email, so an unproven address can
// never take over an existing one — and must not provision alongside it either.
// A second row on one address is what made GetUserByEmail pick arbitrarily between
// two people, so "don't link" and "don't duplicate" are one rule: the address is
// held, and only proving it gets you in.
func TestFederation_UnverifiedEmailNeitherLinksNorDuplicates(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "victim", "victim@example.com", "pw")
	m := newMockOIDC(t, fedGoogleCID)
	m.email = "victim@example.com"
	m.emailVerified = false
	m.sub = "attacker-sub-9"
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	resp := callback(t, app, q.Get("state"), "idp-code-unverified", cookie)
	qs := mustQuery(t, requireRedirect(t, resp, testRedirect))
	if qs.Get("code") != "" {
		t.Fatalf("an unproven address minted a code: %v", qs)
	}
	if qs.Get("error") != "access_denied" {
		t.Fatalf("error = %q, want access_denied", qs.Get("error"))
	}

	// The victim account was NOT linked.
	victim, _ := store.GetUserByName(context.Background(), db, "hanzo", "victim")
	if victim == nil || victim.Google != "" {
		t.Fatalf("unverified email must not link onto the victim account: %+v", victim)
	}
	// And no second row now claims the victim's address.
	if countUsers(t, db) != before {
		t.Fatalf("a duplicate account was provisioned on the victim's address (%d -> %d)", before, countUsers(t, db))
	}
	if u, _ := store.GetUserByConnector(context.Background(), db, "hanzo", "google", "attacker-sub-9"); u != nil {
		t.Fatalf("the unproven identity was provisioned an account anyway: %s", u.Name)
	}
	// The victim's address still resolves to the victim, unambiguously.
	got, err := store.GetUserByEmail(context.Background(), db, "hanzo", "victim@example.com")
	if err != nil || got == nil || got.Name != "victim" {
		t.Fatalf("victim@example.com = %v, %v; want the victim's own row", got, err)
	}
}

// An unknown/forged state is answered in place (no trusted redirect target) and
// never completes.
func TestFederation_UnknownStateRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	// A cookie alone cannot substitute for a real server-side state row.
	resp := callback(t, app, "totally-made-up-state", "idp-code", fedCookieName+"=whatever")
	if resp.StatusCode != 400 {
		t.Fatalf("unknown state status = %d, want 400", resp.StatusCode)
	}
	if resp.Header.Get("Location") != "" {
		t.Fatalf("unknown state must NOT redirect anywhere; got %q", resp.Header.Get("Location"))
	}
}

// A consumed state cannot be replayed — the second callback mints nothing.
func TestFederation_ReplayedStateRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	first := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	requireRedirect(t, first, testRedirect) // success

	replay := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	if replay.StatusCode != 400 || replay.Header.Get("Location") != "" {
		t.Fatalf("replayed state must be refused in place; status=%d loc=%q", replay.StatusCode, replay.Header.Get("Location"))
	}
}

// Without the browser-binding cookie the callback is refused (login-CSRF /
// session-fixation defense): a state injected into another browser cannot land.
func TestFederation_MissingOrWrongBindCookieRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	// No cookie.
	noCookie := callback(t, app, q.Get("state"), "idp-code-1", "")
	if noCookie.StatusCode != 400 || noCookie.Header.Get("Location") != "" {
		t.Fatalf("callback without the bind cookie must be refused; status=%d", noCookie.StatusCode)
	}
	// Wrong cookie value.
	wrong := callback(t, app, q.Get("state"), "idp-code-1", fedCookieName+"=not-the-secret")
	if wrong.StatusCode != 400 || wrong.Header.Get("Location") != "" {
		t.Fatalf("callback with a wrong bind cookie must be refused; status=%d", wrong.StatusCode)
	}
	// The right value under the unprefixed name, which any sibling host can set:
	// only the __Host- cookie is read.
	if !strings.HasPrefix(cookie, "__Host-hanzo_fed=") {
		t.Fatalf("the binding is %q, want the __Host-hanzo_fed cookie", cookie)
	}
	planted := callback(t, app, q.Get("state"), "idp-code-1", strings.TrimPrefix(cookie, "__Host-"))
	if planted.StatusCode != 400 || planted.Header.Get("Location") != "" {
		t.Fatalf("callback with the binding under the bare hanzo_fed name must be refused; status=%d", planted.StatusCode)
	}
	// The state was not consumed by the failed attempts — the legit browser still works.
	if resp := callback(t, app, q.Get("state"), "idp-code-1", cookie); resp.StatusCode != 302 {
		t.Fatalf("the browser holding the binding was refused after the failed attempts; status=%d", resp.StatusCode)
	}
}

// An id_token whose nonce does not match the transaction's nonce is rejected —
// the login does not complete and no account is created/linked.
func TestFederation_OIDCNonceMismatchRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = "a-different-nonce-than-issued" // tamper: id_token nonce != state.IdpNonce
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	if q2 := mustQuery(t, loc); q2.Get("error") == "" || q2.Get("code") != "" {
		t.Fatalf("nonce mismatch must fail closed (error, no code); got %q", loc)
	}
	if countUsers(t, db) != before {
		t.Fatal("a nonce-mismatched login must not provision an account")
	}
}

// An id_token whose signature does not verify against the published JWKS is
// rejected — proving the signature check is real, not stubbed.
func TestFederation_OIDCBadSignatureRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	m.signWrong = true // sign with a key NOT in the JWKS
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	if q2 := mustQuery(t, loc); q2.Get("error") == "" || q2.Get("code") != "" {
		t.Fatalf("bad signature must fail closed; got %q", loc)
	}
	if countUsers(t, db) != before {
		t.Fatal("a signature-invalid login must not provision an account")
	}
}

// An alg=none (unsigned) id_token is rejected — the signing method is pinned to
// the asymmetric set, so the classic JWT downgrade never authenticates anyone.
func TestFederation_OIDCAlgNoneRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	m.noneAlg = true
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	if q2 := mustQuery(t, loc); q2.Get("error") == "" || q2.Get("code") != "" {
		t.Fatalf("alg=none must fail closed; got %q", loc)
	}
	if countUsers(t, db) != before {
		t.Fatal("an unsigned id_token must not provision an account")
	}
}

// An id_token minted for a different audience (not our client id) is rejected.
func TestFederation_OIDCWrongAudienceRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	m.audOverride = "some-other-client"
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	if q2 := mustQuery(t, loc); q2.Get("error") == "" || q2.Get("code") != "" {
		t.Fatalf("wrong audience must fail closed; got %q", loc)
	}
}

// A non-allow-listed redirect_uri is refused at the authorize leg IN PLACE (never
// redirected), and no federation transaction is created for it.
func TestFederation_NonAllowlistedRedirectUriRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q := url.Values{
		"response_type": {"code"}, "client_id": {"webapp"},
		"redirect_uri":   {"https://evil.example/steal"},
		"code_challenge": {pkce.Challenge(fedVerifier)},
		"provider":       {fedProvGoogle},
	}
	resp, _ := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+q.Encode()))
	if resp.StatusCode != 400 || resp.Header.Get("Location") != "" {
		t.Fatalf("bad redirect_uri must be answered in place; status=%d loc=%q", resp.StatusCode, resp.Header.Get("Location"))
	}
}

// runOIDCLogin drives a full successful OIDC federation login (authorize →
// callback) and asserts it lands an iam code. mutate may tweak the mock after
// the nonce is bound.
func runOIDCLogin(t *testing.T, app *zip.App, db orm.DB, m *mockOIDC, clientID string, mutate func()) {
	t.Helper()
	q, cookie := beginAuthorize(t, app, clientID, fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	if mutate != nil {
		mutate()
	}
	resp := callback(t, app, q.Get("state"), "idp-code-"+randHex(3), cookie)
	loc := requireRedirect(t, resp, testRedirect)
	if mustQuery(t, loc).Get("code") == "" {
		t.Fatalf("federation login did not mint an iam code: %q", loc)
	}
}

func mustQuery(t *testing.T, loc string) url.Values {
	t.Helper()
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse location %q: %v", loc, err)
	}
	return u.Query()
}

// ---------------------------------------------------------------------------
// RED-TEAM PoCs — F1: federation must never mint a SuperAdmin or cross-tenant
// identity. These reproduce the reported exploits and assert they are REFUSED.
// ---------------------------------------------------------------------------

// seedFederationTarget seeds a (possibly malicious) app — appOwner/appClientID
// pointing its Organization at `serves` — linked to a Google-dialect provider
// (owned by provOwner) whose OIDC issuer is the mock IdP.
func seedFederationTarget(t *testing.T, db orm.DB, appClientID, appOwner, serves, provOwner string, m *mockOIDC) {
	t.Helper()
	ctx := context.Background()
	p := orm.New[schema.Provider](db)
	p.Owner, p.Name = provOwner, fedProvGoogle
	p.Category, p.Type = "OAuth", "Google"
	p.ClientId, p.ClientSecret = m.clientID, "secret-do-not-log"
	p.IssuerUrl = m.URL
	p.SetId(provOwner + "/" + fedProvGoogle)
	if err := p.CreateCtx(ctx); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId = appOwner, appClientID, appClientID
	a.Organization = serves
	a.EnablePassword = true
	// Registration ON, so a refusal below can only be the ORG gate refusing — never
	// the app's own signup switch standing in for it.
	a.EnableSignUp = true
	a.ExpireInHours = 1
	a.RedirectUris = []string{testRedirect}
	a.Providers = []*schema.ProviderItem{{Owner: provOwner, Name: fedProvGoogle, CanSignIn: true}}
	a.SetId(appOwner + "/" + appClientID)
	if err := a.CreateCtx(ctx); err != nil {
		t.Fatalf("seed app: %v", err)
	}
}

func federationAuthorizeQuery(clientID string) url.Values {
	return url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {testRedirect},
		"code_challenge":        {pkce.Challenge(fedVerifier)},
		"code_challenge_method": {"S256"},
		"state":                 {fedAppState},
		"provider":              {fedProvGoogle},
	}
}

// assertFederationRefused asserts a federation kickoff was refused: bounced back
// to the relying party with an OAuth error, NEVER redirected to the IdP, NEVER a
// code.
func assertFederationRefused(t *testing.T, resp *http.Response, m *mockOIDC) {
	t.Helper()
	if resp.StatusCode != 302 {
		t.Fatalf("want a 302 refusal redirect, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, testRedirect) {
		t.Fatalf("refusal must redirect to the relying party, not the IdP: %q", loc)
	}
	if m != nil && strings.HasPrefix(loc, m.URL) {
		t.Fatal("a refused federation must never reach the IdP")
	}
	q := mustQuery(t, loc)
	if q.Get("error") == "" {
		t.Fatalf("refusal must carry an OAuth error: %q", loc)
	}
	if q.Get("code") != "" {
		t.Fatal("a refused federation must not mint a code")
	}
}

func countUsersIn(t *testing.T, db orm.DB, org string) int {
	t.Helper()
	n, err := orm.TypedQuery[schema.User](db).Filter("Owner=", org).Count(context.Background())
	if err != nil {
		t.Fatalf("count users in %q: %v", org, err)
	}
	return n
}

// PoC 1 — an attacker-owned app whose Organization names the reserved admin org
// would provision User{Owner:"admin"} = SuperAdmin. Federation must refuse it.
func TestRedTeam_FederationMintsSuperAdmin(t *testing.T) {
	app, db := newServer(t)
	m := newMockOIDC(t, fedGoogleCID) // the attacker's OWN Google account
	seedFederationTarget(t, db, "evil-app", "attackerorg", "admin", "admin", m)

	beforeAdmin := countUsersIn(t, db, "admin")

	resp, _ := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+federationAuthorizeQuery("evil-app").Encode()))
	assertFederationRefused(t, resp, m)

	if countUsersIn(t, db, "admin") != beforeAdmin {
		t.Fatal("PoC: federation provisioned a user into the admin org (SuperAdmin mint)")
	}
	// Defense in depth: the innermost mint refuses this app directly too.
	evil, _ := store.GetApplicationByClientId(tctx(), db, "evil-app")
	prov, _ := store.GetProvider(tctx(), db, "admin", fedProvGoogle)
	if _, _, err := linkOrProvision(tctx(), db, evil, prov, federatedIdentity{subject: "s1", email: "a@b.com", emailVerified: true}); err == nil {
		t.Fatal("PoC: linkOrProvision minted an identity into the admin org")
	}
}

// PoC 2 — an attacker-owned app whose Organization names a VICTIM tenant, driven
// by a tenant-owned IdP that asserts the victim's verified email, would link the
// attacker's identity onto the victim's account. Federation must refuse it.
func TestRedTeam_FederationCrossTenantTakeover(t *testing.T) {
	app, db := newServer(t)
	seedUserInOrg(t, db, "victimorg", "ceo", "ceo@victim.com", "pw")

	m := newMockOIDC(t, fedGoogleCID) // attacker's tenant-owned IdP...
	m.email = "ceo@victim.com"        // ...asserting the victim's email, "verified"
	m.emailVerified = true
	m.sub = "attacker-controlled-sub"
	seedFederationTarget(t, db, "evil-app", "attackerorg", "victimorg", "attackerorg", m)

	resp, _ := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+federationAuthorizeQuery("evil-app").Encode()))
	assertFederationRefused(t, resp, m)

	victim, _ := store.GetUserByName(tctx(), db, "victimorg", "ceo")
	if victim == nil || victim.Google != "" {
		t.Fatalf("PoC: cross-tenant identity linked onto the victim account: %+v", victim)
	}
}

// PoC 3 — the fully tenant-owned variant: the attacker's OWN app AND OWN provider
// (no platform resource referenced) still cannot point Organization at admin.
func TestRedTeam_FederationMintsSuperAdmin_TenantOwnedApp(t *testing.T) {
	app, db := newServer(t)
	m := newMockOIDC(t, fedGoogleCID)
	seedFederationTarget(t, db, "evil-app", "attackerorg", "admin", "attackerorg", m)

	beforeAdmin := countUsersIn(t, db, "admin")
	resp, _ := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+federationAuthorizeQuery("evil-app").Encode()))
	assertFederationRefused(t, resp, m)
	if countUsersIn(t, db, "admin") != beforeAdmin {
		t.Fatal("PoC: a tenant-owned app federated a user into the admin org")
	}
}

// The legitimate case still works: a platform app (admin-owned) serving a real
// tenant federates fine — proving the guard refuses only the escalation, not the
// happy path.
func TestFederation_PlatformAppLegitimateOrgAllowed(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}}) // Owner=admin, Org=hanzo
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)
	runOIDCLogin(t, app, db, m, "webapp", nil)
	if u, _ := store.GetUserByConnector(tctx(), db, "hanzo", "google", m.sub); u == nil {
		t.Fatal("a legitimate platform-app federation must still provision a user")
	}
}

// F2 — SSRF: an org-admin-writable IssuerUrl pointing at the cloud-metadata
// endpoint must be refused at DIAL time (the guard is armed; no private-dial seam
// here), so federation fails closed to the relying party and never fetches it.
func TestFederation_SSRFPrivateIssuerRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	p := orm.New[schema.Provider](db)
	p.Owner, p.Name = "admin", fedProvGoogle
	p.Category, p.Type = "OAuth", "Google"
	p.ClientId, p.ClientSecret = "cid", "secret"
	p.IssuerUrl = "https://169.254.169.254" // link-local cloud metadata over TLS
	p.SetId("admin/" + fedProvGoogle)
	if err := p.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	linkProvider(t, db, "webapp", fedProvGoogle)

	resp, _ := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+federationAuthorizeQuery("webapp").Encode()))
	if resp.StatusCode != 302 {
		t.Fatalf("want 302, got %d", resp.StatusCode)
	}
	loc := resp.Header.Get("Location")
	if !strings.HasPrefix(loc, testRedirect) || mustQuery(t, loc).Get("error") == "" {
		t.Fatalf("SSRF to metadata must fail closed to the RP with an error: %q", loc)
	}
	if strings.Contains(loc, "169.254") {
		t.Fatal("must not redirect the browser to the metadata endpoint")
	}
}

func tokenBody(tok map[string]any) string {
	b, _ := json.Marshal(tok)
	return string(b)
}
