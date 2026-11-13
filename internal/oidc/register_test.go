// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
)

// RFC 7591 dynamic client registration for MCP clients. The endpoint registers a
// public PKCE client the operator's organization holds, signs its people in on the
// brand's own site, and holds it to the identity scopes.

const registrationHanzo = `{"organization":"hanzo","signinUrl":"https://hanzo.ai/login"}`

// registrationServer is a server with registration on for hanzo, hanzo.ai a
// configured sign-in origin, and the organization's signing cert.
func registrationServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	t.Setenv(EnvRegistration, registrationHanzo)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	app, db := newServer(t)
	t.Cleanup(func() { registration.Store(nil) })
	seedRSACert(t, db, "cert-hanzo")
	return app, db
}

func register(t *testing.T, app *zip.App, body any) (*http.Response, map[string]any) {
	t.Helper()
	resp, raw := do(t, app, jsonReq("POST", PathRegister, body))
	return resp, decode(t, raw)
}

func claudeCode() map[string]any {
	return map[string]any{
		"client_name":   "Claude Code",
		"redirect_uris": []string{"http://localhost:54321/callback"},
		"grant_types":   []string{"authorization_code", "refresh_token"},
	}
}

func clientsOf(t *testing.T, db orm.DB) []*schema.Application {
	t.Helper()
	all, err := orm.TypedQuery[schema.Application](db).Filter("Owner=", "hanzo").GetAll(context.Background())
	if err != nil {
		t.Fatalf("list applications: %v", err)
	}
	return all
}

func registrations(t *testing.T, db orm.DB) int {
	t.Helper()
	n, err := orm.TypedQuery[schema.AuditLog](db).Filter("Action=", schema.ActionRegisterClient).Count(context.Background())
	if err != nil {
		t.Fatalf("count audit rows: %v", err)
	}
	return n
}

// A deployment that never named an organization serves no registration endpoint
// and does not advertise one: opening it is the operator's act.
func TestRegister_OffUnlessTheDeploymentTurnsItOn(t *testing.T) {
	t.Setenv(EnvRegistration, "")
	app, _ := newServer(t)

	resp, _ := do(t, app, jsonReq("POST", PathRegister, claudeCode()))
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST %s with registration off = %d, want 404", PathRegister, resp.StatusCode)
	}
	_, body := do(t, app, formReqNoBody("GET", PathASMetadata))
	if _, on := decode(t, body)["registration_endpoint"]; on {
		t.Error("discovery advertises a registration endpoint the deployment does not serve")
	}
}

// A value that does not read leaves registration off. A typo must not open an
// endpoint with a default nobody wrote down.
func TestRegister_AnUnreadableConfigurationIsOff(t *testing.T) {
	for _, bad := range []string{
		`{"organization":"hanzo",`,
		`{"organization":""}`,
		`{"organization":"a/b"}`,
		`{"organization":"hanzo","signinUrl":"http://hanzo.ai/login"}`,
		`{"organization":"hanzo","extra":1}`,
	} {
		t.Setenv(EnvRegistration, bad)
		if r := loadRegistrar(); r != nil {
			t.Errorf("%s read as %+v, want registration off", bad, r)
		}
	}
}

func TestRegister_AdvertisedInBothMetadataDocuments(t *testing.T) {
	app, _ := registrationServer(t)

	for _, path := range []string{PathASMetadata, PathASMetadataV1, PathDiscovery, PathDiscoveryV1} {
		_, body := do(t, app, formReqNoBody("GET", path))
		if got := decode(t, body)["registration_endpoint"]; got != "https://hanzo.id"+PathRegister {
			t.Errorf("%s: registration_endpoint = %v", path, got)
		}
	}
}

// What a registration stores is what makes it safe: a public client of the
// organization, serving any of its people, signing in on the brand's site, holding
// the identity scopes and nothing a tenant could widen.
func TestRegister_StoresAPublicPKCEClientOfTheOrganization(t *testing.T) {
	app, db := registrationServer(t)

	resp, got := register(t, app, claudeCode())
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body = %v", resp.StatusCode, got)
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", cc)
	}
	id, _ := got["client_id"].(string)
	if !strings.HasPrefix(id, "mcp-") {
		t.Fatalf("client_id = %q", id)
	}
	if _, secret := got["client_secret"]; secret {
		t.Error("a public client was issued a secret")
	}
	if got["token_endpoint_auth_method"] != "none" || got["scope"] != "openid profile email offline_access" {
		t.Errorf("answer = %v", got)
	}

	rows := clientsOf(t, db)
	var a *schema.Application
	for _, r := range rows {
		if r.ClientId == id {
			a = r
		}
	}
	if a == nil {
		t.Fatalf("client %s was not stored", id)
	}
	if !a.Dynamic() || a.ClientSecret != "" || a.Organization != "hanzo" || a.Cert != "cert-hanzo" {
		t.Errorf("stored %+v", a)
	}
	if a.Platform {
		t.Error("a registered client is a platform application")
	}
	if !a.ServesAnyOrg() {
		t.Error("a registered client serves one tenant; hanzo.id's people live in many")
	}
	if a.SigninUrl != "https://hanzo.ai/login" {
		t.Errorf("SigninUrl = %q", a.SigninUrl)
	}
	if a.DisplayName != "Claude Code (localhost)" {
		t.Errorf("DisplayName = %q: the page must say where the code goes", a.DisplayName)
	}
	if registrations(t, db) != 1 {
		t.Errorf("audit rows = %d, want 1", registrations(t, db))
	}
}

// The same metadata is the same client: a hosted client's every user registers
// the same name and callback, and that is one row, not one per user.
func TestRegister_RepeatIsTheSameClientAndCreatesNothing(t *testing.T) {
	app, db := registrationServer(t)

	_, first := register(t, app, claudeCode())
	again := claudeCode()
	again["redirect_uris"] = []string{"http://localhost:54321/callback", "http://localhost:54321/callback"}
	_, second := register(t, app, again)

	if first["client_id"] != second["client_id"] {
		t.Errorf("client_id %v then %v", first["client_id"], second["client_id"])
	}
	if n := len(clientsOf(t, db)); n != 1 {
		t.Errorf("%d applications, want 1", n)
	}
	if n := registrations(t, db); n != 1 {
		t.Errorf("audit rows = %d, want 1", n)
	}

	other := claudeCode()
	other["redirect_uris"] = []string{"http://localhost:60000/callback"}
	if _, third := register(t, app, other); third["client_id"] == first["client_id"] {
		t.Error("a different callback is a different client")
	}
}

// Only https and loopback http may receive a code; and the grants, response types
// and scopes a public PKCE client has no business with are refused.
func TestRegister_RefusesWhatAPublicClientMustNotHold(t *testing.T) {
	app, db := registrationServer(t)

	with := func(k string, v any) map[string]any {
		m := claudeCode()
		m[k] = v
		return m
	}
	cases := []struct {
		name string
		body map[string]any
		code string
	}{
		{"no redirect", with("redirect_uris", []string{}), "invalid_redirect_uri"},
		{"http on the internet", with("redirect_uris", []string{"http://evil.example/cb"}), "invalid_redirect_uri"},
		{"custom scheme", with("redirect_uris", []string{"myapp://cb"}), "invalid_redirect_uri"},
		{"javascript", with("redirect_uris", []string{"javascript:alert(1)"}), "invalid_redirect_uri"},
		{"fragment", with("redirect_uris", []string{"https://app.example/cb#x"}), "invalid_redirect_uri"},
		{"userinfo", with("redirect_uris", []string{"https://u:p@app.example/cb"}), "invalid_redirect_uri"},
		{"https ip literal", with("redirect_uris", []string{"https://203.0.113.9/cb"}), "invalid_redirect_uri"},
		{"https localhost", with("redirect_uris", []string{"https://localhost/cb"}), "invalid_redirect_uri"},
		{"wildcard", with("redirect_uris", []string{"https://*.example.com/cb"}), "invalid_redirect_uri"},
		{"one mixed in", with("redirect_uris", []string{"https://app.example/cb", "http://evil.example/cb"}), "invalid_redirect_uri"},
		{"six", with("redirect_uris", []string{"https://a.example/1", "https://a.example/2", "https://a.example/3", "https://a.example/4", "https://a.example/5", "https://a.example/6"}), "invalid_redirect_uri"},
		{"client credentials", with("grant_types", []string{"client_credentials"}), "invalid_client_metadata"},
		{"implicit", with("grant_types", []string{"implicit"}), "invalid_client_metadata"},
		{"no code grant", with("grant_types", []string{"refresh_token"}), "invalid_client_metadata"},
		{"token response", with("response_types", []string{"token"}), "invalid_client_metadata"},
		{"only a scope it may not hold", with("scope", "admin kms:write"), "invalid_client_metadata"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp, got := register(t, app, tc.body)
			if resp.StatusCode != http.StatusBadRequest || got["error"] != tc.code {
				t.Errorf("status = %d, body = %v, want 400 %s", resp.StatusCode, got, tc.code)
			}
		})
	}
	if n := len(clientsOf(t, db)); n != 0 {
		t.Errorf("%d applications stored from refused requests", n)
	}

	req := jsonReq("POST", PathRegister, nil)
	req.Body = http.NoBody
	if resp, _ := do(t, app, req); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("an empty body = %d, want 400", resp.StatusCode)
	}
}

// What is asked beyond the grant is narrowed to what a registered client may hold,
// and the answer says so (RFC 7591 §3.2.1).
func TestRegister_NarrowsScopesAndSubstitutesTheAuthMethod(t *testing.T) {
	app, _ := registrationServer(t)

	body := claudeCode()
	body["scope"] = "openid email admin offline_access"
	body["token_endpoint_auth_method"] = "client_secret_post"
	resp, got := register(t, app, body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("status = %d, body = %v", resp.StatusCode, got)
	}
	if got["scope"] != "openid email offline_access" || got["token_endpoint_auth_method"] != "none" {
		t.Errorf("answer = %v", got)
	}
}

// A name that is the client's own word for itself cannot carry markup or break the
// line, and always arrives with the host the code returns to.
func TestRegister_NamesAreClean(t *testing.T) {
	cases := map[string]string{
		"  Claude\n\tCode  ":        "Claude Code",
		"<script>alert(1)</script>": "scriptalert(1)/script",
		"":                          defaultClientName,
		"\x00\x01":                  defaultClientName,
		strings.Repeat("x", 200):    strings.Repeat("x", maxClientNameRunes),
		"Cursor ‮evil":              "Cursor evil",
	}
	for in, want := range cases {
		if got := nameOf(in); got != want {
			t.Errorf("nameOf(%q) = %q, want %q", in, got, want)
		}
	}
}

// New clients are bounded per address and per network; a repeat is free.
func TestRegister_RateLimited(t *testing.T) {
	app, db := registrationServer(t)
	was := registerCap
	registerCap.IP, registerCap.Subnet = 2, 3
	t.Cleanup(func() { registerCap = was })

	at := func(ip string, port int) *http.Response {
		body := claudeCode()
		body["redirect_uris"] = []string{"http://localhost:" + strconv.Itoa(port) + "/callback"}
		req := jsonReq("POST", PathRegister, body)
		req.Header.Set("CF-Connecting-IP", ip)
		resp, _ := do(t, app, req)
		return resp
	}
	for i := 0; i < 2; i++ {
		if resp := at("203.0.113.7", 1000+i); resp.StatusCode != http.StatusCreated {
			t.Fatalf("registration %d = %d", i, resp.StatusCode)
		}
	}
	resp := at("203.0.113.7", 2000)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("third from one address = %d (Retry-After %q), want 429", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	if resp := at("203.0.113.7", 1000); resp.StatusCode != http.StatusCreated {
		t.Errorf("a repeat from a capped address = %d, want 201", resp.StatusCode)
	}
	// The third distinct client on the /24 fills its cap; the fourth is refused
	// whatever the address.
	if resp := at("203.0.113.8", 3000); resp.StatusCode != http.StatusCreated {
		t.Errorf("another address on the network = %d", resp.StatusCode)
	}
	if resp := at("203.0.113.9", 4000); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("fourth on one /24 = %d, want 429", resp.StatusCode)
	}
	if resp := at("198.51.100.1", 5000); resp.StatusCode != http.StatusCreated {
		t.Errorf("an unrelated network = %d", resp.StatusCode)
	}
	if got, want := registrations(t, db), 4; got != want {
		t.Errorf("audit rows = %d, want %d", got, want)
	}
}

// Each registration is an audit row that names the client, where it came from and
// where it sends a code; the request cannot write or remove one.
func TestRegister_IsAudited(t *testing.T) {
	app, db := registrationServer(t)
	req := jsonReq("POST", PathRegister, claudeCode())
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	do(t, app, req)

	rows, err := orm.TypedQuery[schema.AuditLog](db).Filter("Action=", schema.ActionRegisterClient).GetAll(context.Background())
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit rows = %d, err = %v", len(rows), err)
	}
	r := rows[0]
	if r.ClientIp != "203.0.113.7" || r.Object != "203.0.113.0/24" || !strings.Contains(r.Response, "http://localhost:54321/callback") ||
		!strings.HasPrefix(r.User, "hanzo/mcp-") || r.RequestUri != PathRegister {
		t.Errorf("audit row = %+v", r)
	}
	if !schema.PlatformWritten(schema.ActionRegisterClient) {
		t.Error("a request may forge or trim the registration ledger")
	}
}

// A registration whose sign-in page authorize would not follow is refused, because
// it would send people to the issuer's page, not the brand's.
func TestRegister_RefusedWhereTheSigninOriginIsNotConfigured(t *testing.T) {
	t.Setenv(EnvRegistration, registrationHanzo)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{}`)
	app, db := newServer(t)
	t.Cleanup(func() { registration.Store(nil) })

	resp, got := register(t, app, claudeCode())
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, body = %v", resp.StatusCode, got)
	}
	if n := len(clientsOf(t, db)); n != 0 {
		t.Errorf("%d applications stored", n)
	}
}

// authorize hands a registered client's request to the brand's sign-in page with
// the request intact: never a page on hanzo.id, never a code from a session.
func TestRegister_AuthorizeLandsOnTheBrandSigninPage(t *testing.T) {
	app, db := registrationServer(t)
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	_, got := register(t, app, claudeCode())
	id := got["client_id"].(string)
	redirect := "http://localhost:54321/callback"
	challenge := pkce.Challenge("verifier-abcdefghijklmnopqrstuvwxyz-0123456789")

	q := url.Values{
		"response_type": {"code"}, "client_id": {id}, "redirect_uri": {redirect},
		"scope": {"openid profile email offline_access"}, "state": {"st-1"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"},
		"resource": {"https://api.hanzo.ai/v1/mcp"},
	}
	resp, _ := do(t, app, formReqNoBody("GET", authorizeURL(q)))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if loc.Scheme+"://"+loc.Host+loc.Path != "https://hanzo.ai/login" {
		t.Fatalf("Location = %s, want https://hanzo.ai/login", loc)
	}
	for k, want := range map[string]string{
		"client_id": id, "redirect_uri": redirect, "state": "st-1", "response_type": "code",
		"code_challenge": challenge, "code_challenge_method": "S256", "prompt": "login",
	} {
		if got := loc.Query().Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}

	// prompt=none has nothing to ask a person about, so it is refused to the
	// client; and an unregistered callback is never redirected to.
	q.Set("prompt", "none")
	resp, _ = do(t, app, formReqNoBody("GET", authorizeURL(q)))
	if loc := resp.Header.Get("Location"); !strings.HasPrefix(loc, redirect) || !strings.Contains(loc, "error=interaction_required") {
		t.Errorf("prompt=none Location = %q", loc)
	}
	q.Set("redirect_uri", "https://evil.example/cb")
	if resp, _ = do(t, app, formReqNoBody("GET", authorizeURL(q))); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("unregistered redirect_uri = %d, want 400", resp.StatusCode)
	}
}

// The whole flow a client runs after registering: sign in, exchange the code with
// the verifier, hold exactly the scopes it registered, and refresh.
func TestRegister_FullCodeFlowHoldsOnlyRegisteredScopes(t *testing.T) {
	app, db := registrationServer(t)
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	_, got := register(t, app, claudeCode())
	id := got["client_id"].(string)
	redirect := "http://localhost:54321/callback"
	verifier := "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"

	params := map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw", "clientId": id,
		"redirectUri": redirect, "scope": "openid email admin kms:write *",
		"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	}
	code, resp, body := loginForCode(t, app, params)
	if code == "" {
		t.Fatalf("no code: %d %s", resp.StatusCode, body)
	}
	resp, tok := exchangeCode(t, app, url.Values{"code": {code}, "client_id": {id}, "redirect_uri": {redirect}, "code_verifier": {verifier}})
	if resp.StatusCode != http.StatusOK || tok["access_token"] == nil || tok["refresh_token"] == nil {
		t.Fatalf("exchange = %d %v", resp.StatusCode, tok)
	}
	if tok["scope"] != "openid email" {
		t.Errorf("scope = %v, want only what the client registered and asked for", tok["scope"])
	}
	claims, err := verifyToken(context.Background(), db, tok["access_token"].(string))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" || claims.Issuer != "https://hanzo.id" {
		t.Errorf("claims = %+v", claims)
	}

	// A registration is not a way to the SuperAdmin or to an unregistered callback.
	bad := cloneParams(params)
	bad["redirectUri"] = "http://localhost:1/other"
	if code, _, _ := loginForCode(t, app, bad); code != "" {
		t.Error("a code was minted for a redirect_uri that was never registered")
	}

	// The refresh token works and the lifetime outlives the access token.
	resp, ref := postToken(t, app, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {tok["refresh_token"].(string)}, "client_id": {id}})
	if resp.StatusCode != http.StatusOK || ref["access_token"] == nil {
		t.Errorf("refresh = %d %v", resp.StatusCode, ref)
	}
}

func cloneParams(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// No page and no link gets a registered client a code from a session: a person who
// is signed in is still asked for their credential, whichever door the request came
// through. A link straight to the sign-in page never runs authorize, so nothing
// recorded there can be what stops it.
func TestRegister_ASessionNeverAnswersARegisteredClient(t *testing.T) {
	app, db := registrationServer(t)
	seedFounder(t, db, "hanzo", "alice")
	cookie := portalSession(t, app, "hanzo", "alice")
	_, got := register(t, app, claudeCode())
	id := got["client_id"].(string)
	redirect := "http://localhost:54321/callback"

	req := fromPage(jsonReq("POST", PathLogin+"?clientId="+id+"&responseType=code&redirectUri="+redirect+
		"&scope=openid&type=code&codeChallenge="+pkce.Challenge("verifier-abcdefghijklmnopqrstuvwxyz-0123456789")+
		"&codeChallengeMethod=S256", map[string]any{"type": "code", "application": id}))
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	env := decode(t, body)
	if env["status"] != "error" || env["code"] != CodeLoginRequired {
		t.Fatalf("a session answered a registered client: %s", body)
	}

	// The same session still answers an operator's own application, so the rule is
	// the registered client's and not a regression for every other.
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	req = fromPage(jsonReq("POST", PathLogin+"?clientId=conf&responseType=code&redirectUri="+testRedirect+"&type=code",
		map[string]any{"type": "code", "application": "conf"}))
	req.Header.Set("Cookie", cookie)
	_, body = do(t, app, req)
	if decode(t, body)["status"] != "ok" {
		t.Errorf("an operator's application lost single sign-on: %s", body)
	}
}

// A person who signs in with Google or GitHub on the brand's page can do so for a
// registered client: it offers the social sign-in methods of the application the
// deployment names, as sign-in only. A client anyone can register must not be a way
// to create accounts, so sign-up and unlink are off and a method that signs nobody
// in (web3 here) is not copied.
func TestRegister_OffersTheTemplatesSocialSigninNeverSignup(t *testing.T) {
	t.Setenv(EnvRegistration, `{"organization":"hanzo","signinUrl":"https://hanzo.ai/login","providers":"hanzo-app"}`)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	app, db := newServer(t)
	t.Cleanup(func() { registration.Store(nil) })
	seedRSACert(t, db, "cert-hanzo")
	tmpl := seedApp(t, db, appOpts{clientID: "hanzo-app"})
	tmpl.Providers = []*schema.ProviderItem{
		{Owner: "admin", Name: "provider-github", CanSignIn: true, CanSignUp: true, CanUnlink: true},
		{Owner: "admin", Name: "provider-google", CanSignIn: true, CanSignUp: true},
		{Owner: "admin", Name: "provider-web3", CanSignIn: false, CanSignUp: true},
	}
	if err := tmpl.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, got := register(t, app, claudeCode())
	a, err := orm.Get[schema.Application](db, "hanzo/"+got["client_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Providers) != 2 {
		t.Fatalf("providers = %+v, want github and google", a.Providers)
	}
	for _, p := range a.Providers {
		if !p.CanSignIn || p.CanSignUp || p.CanUnlink || p.Owner != "admin" {
			t.Errorf("%s offered as %+v: sign in only", p.Name, p)
		}
	}
	if a.Providers[0].Name != "provider-github" || a.Providers[1].Name != "provider-google" {
		t.Errorf("providers = %s, %s", a.Providers[0].Name, a.Providers[1].Name)
	}
}

// Every way a code row is made holds a registered client to its registered scopes,
// the federation mint included: MintCode is the one constructor.
func TestRegister_MintCodeClampsToRegisteredScopes(t *testing.T) {
	a := &schema.Application{Name: "mcp-x", Organization: "hanzo", Tags: []string{schema.TagDynamic},
		Scopes: []*schema.ScopeItem{{Name: "openid"}, {Name: "email"}}}
	row, err := MintCode(a, "hanzo/alice", "openid admin email kms:write email", "", "", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if row.Scope != "openid email" {
		t.Errorf("scope = %q, want openid email", row.Scope)
	}

	own := &schema.Application{Name: "console", Organization: "hanzo"}
	row, err = MintCode(own, "hanzo/alice", "openid admin kms:write", "", "", "", time.Now())
	if err != nil || row.Scope != "openid admin kms:write" {
		t.Errorf("an operator's application lost its scope: %q %v", row.Scope, err)
	}
}

// Any registered address may receive the code, so the name a person reads names all
// of them; a second host cannot hide behind a first-party-looking one.
func TestRegister_TheNameShowsEveryHostACodeCanReach(t *testing.T) {
	app, db := registrationServer(t)
	body := claudeCode()
	body["client_name"] = "Claude"
	body["redirect_uris"] = []string{"https://claude.ai/api/mcp/auth_callback", "https://evil.example/cb", "https://claude.ai/other"}
	_, got := register(t, app, body)
	a, err := orm.Get[schema.Application](db, "hanzo/"+got["client_id"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if a.DisplayName != "Claude (claude.ai, evil.example)" {
		t.Errorf("DisplayName = %q", a.DisplayName)
	}
}

// A host is a public DNS name in ASCII: an address in any spelling, a name written
// in look-alike letters and a single label send a code nowhere a person can read.
func TestRegister_HostsArePublicASCIINames(t *testing.T) {
	for host, ok := range map[string]bool{
		"claude.ai": true, "mcp.example.co.uk": true, "xn--clude-9ra.ai": true, "a-b.example": true,
		"localhost": false, "intranet": false, "127.1": false, "0x7f.0.0.1": false, "2130706433.0": false,
		"203.0.113.9": false, "[::1]": false, "cl\u0430ude.ai": false, "claude.ai.": false, "-.-": false, "a_b.example": false,
	} {
		if got := publicHost(host); got != ok {
			t.Errorf("publicHost(%q) = %v, want %v", host, got, ok)
		}
	}
}

// Addresses are cheap, so the cap on new clients also holds across all of them.
func TestRegister_CapsNewClientsAcrossEveryAddress(t *testing.T) {
	app, _ := registrationServer(t)
	was := registerCap
	registerCap.Global = 2
	t.Cleanup(func() { registerCap = was })

	for i, ip := range []string{"198.51.100.1", "192.0.2.1", "203.0.113.5"} {
		body := claudeCode()
		body["redirect_uris"] = []string{"http://localhost:" + strconv.Itoa(2000+i) + "/callback"}
		req := jsonReq("POST", PathRegister, body)
		req.Header.Set("CF-Connecting-IP", ip)
		resp, _ := do(t, app, req)
		want := http.StatusCreated
		if i == 2 {
			want = http.StatusTooManyRequests
		}
		if resp.StatusCode != want {
			t.Errorf("registration %d from %s = %d, want %d", i, ip, resp.StatusCode, want)
		}
	}
}

// Social sign-in for a registered client always shows the IdP's account chooser:
// a link anyone can send must not carry a browser that holds a Google or GitHub
// session through the leg without a click. An operator's own application is as
// it was.
func TestRegister_FederationAlwaysAsksTheIdPToChoose(t *testing.T) {
	t.Setenv(EnvRegistration, `{"organization":"hanzo","signinUrl":"https://hanzo.ai/login","providers":"hanzo-app"}`)
	installIssuerResolver(t, "https://hanzo.id", testIssuerMap)
	installFederationResolver(t, `{"hanzo.ai":"https://hanzo.ai"}`)
	allowPrivateFederationDial(t)
	app, db := newServer(t)
	t.Cleanup(func() { registration.Store(nil) })
	seedRSACert(t, db, "cert-hanzo")
	seedApp(t, db, appOpts{clientID: "hanzo-app", redirectURIs: []string{testRedirect}})
	m := newMockGitHub(t)
	seedGitHubProvider(t, db, "hanzo-app", m)

	_, got := register(t, app, claudeCode())
	id := got["client_id"].(string)
	redirect := "http://localhost:54321/callback"
	begin := func(client, redirectURI string) url.Values {
		q := url.Values{
			"response_type": {"code"}, "client_id": {client}, "redirect_uri": {redirectURI},
			"scope": {"openid email"}, "state": {"s"}, "provider": {"github"},
			"code_challenge": {pkce.Challenge(fedVerifier)}, "code_challenge_method": {"S256"},
		}
		resp, _ := do(t, app, formReqNoBody("GET", PathAuthorize+"?"+q.Encode()))
		loc, err := url.Parse(resp.Header.Get("Location"))
		if resp.StatusCode != http.StatusFound || err != nil || !loc.IsAbs() {
			t.Fatalf("%s: status %d, Location %q", client, resp.StatusCode, resp.Header.Get("Location"))
		}
		return loc.Query()
	}
	if got := begin(id, redirect).Get("prompt"); got != "select_account" {
		t.Errorf("a registered client's IdP leg has prompt=%q, want select_account", got)
	}
	if got := begin("hanzo-app", testRedirect).Get("prompt"); got != "" {
		t.Errorf("an operator's application's IdP leg has prompt=%q, want none", got)
	}
}
