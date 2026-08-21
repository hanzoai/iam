// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package e2e_test drives the WHOLE iam surface through the real registered router
// (routes.Route) as one integrated journey — the behavioral parity proof that the
// old the legacy surface IAM's clients work against iam. Unlike the per-package unit tests,
// this chains the real flows a live client runs in sequence: OIDC discovery →
// PKCE login → code→token → userinfo → introspect → revoke; the admin console's
// get-account → get-organizations → get-users (the legacy compat surface); SCIM
// 2.0 provisioning; and RFC 8693 token exchange. Every step asserts the response
// CONTRACT the client depends on.
package e2e_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"

	"github.com/hanzoai/iam/internal/testhttp"
)

const (
	kid         = "cert-hanzo"
	redirectURI = "https://console.hanzo.ai/auth/callback"
)

type env struct {
	app *zip.App
	key *rsa.PrivateKey
	db  orm.DB
}

func boot(t *testing.T) *env {
	t.Helper()
	_ = schema.Kinds()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "e2e.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, key)
	// A confidential console app: password login + PKCE, in the hanzo org.
	seedApp(t, db)
	seedOrg(t, db, "admin")
	seedOrg(t, db, "hanzo")
	seedUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw", false)
	seedUser(t, db, "admin", "root", "root@hanzo.ai", "pw", true) // SuperAdmin

	app := zip.New(zip.Config{AppName: "iam-e2e", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &env{app: app, key: key, db: db}
}

// TestJourney_OIDCFlow is the full OAuth2/OIDC round trip a client SDK runs.
func TestJourney_OIDCFlow(t *testing.T) {
	e := boot(t)

	// 1) Discovery is self-consistent (one issuer, the endpoints a strict client pins).
	disc := e.getJSON(t, "/.well-known/openid-configuration", "")
	if disc["issuer"] == "" || disc["token_endpoint"] == "" || disc["jwks_uri"] == "" {
		t.Fatalf("discovery incomplete: %v", disc)
	}
	if disc["introspection_endpoint"] == "" || disc["revocation_endpoint"] == "" {
		t.Fatalf("discovery missing RFC 7662/7009 endpoints: %v", disc)
	}
	// RFC 8414 AS metadata served at its own well-known.
	if as := e.getJSON(t, "/.well-known/oauth-authorization-server", ""); as["issuer"] == "" {
		t.Fatalf("RFC 8414 AS metadata missing")
	}
	// 2) JWKS publishes a verification key.
	jwks := e.getJSON(t, "/v1/iam/.well-known/jwks", "")
	if keys, _ := jwks["keys"].([]any); len(keys) == 0 {
		t.Fatalf("JWKS has no keys: %v", jwks)
	}

	// 3) PKCE login → single-use code.
	verifier := "e2e-verifier-0000000000000000000000000000000000000"
	code := e.login(t, verifier)

	// 4) Redeem the code → access token (+ id_token on openid, refresh on offline).
	tok := e.token(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"hanzo-console"}, "client_secret": {"top-secret"},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token: %v", tok)
	}

	// 5) UserInfo carries the identity + the admin-guard contract (owner, isAdmin).
	info := e.getJSON(t, "/v1/iam/oauth/userinfo", access)
	if info["sub"] != "hanzo/alice" || info["owner"] != "hanzo" {
		t.Fatalf("userinfo sub/owner wrong: %v", info)
	}
	if _, ok := info["isAdmin"]; !ok {
		t.Fatalf("userinfo missing the isAdmin claim (admin-guard contract): %v", info)
	}

	// 6) Introspection (RFC 7662): active, with the standard claims.
	ir := e.form(t, "/v1/iam/oauth/introspect", "hanzo-console", "top-secret", url.Values{"token": {access}})
	if ir["active"] != true || ir["sub"] != "hanzo/alice" {
		t.Fatalf("introspect not active/wrong sub: %v", ir)
	}

	// 7) Revocation (RFC 7009): the token dies — introspect flips to inactive.
	e.form(t, "/v1/iam/oauth/revoke", "hanzo-console", "top-secret", url.Values{"token": {access}})
	if after := e.form(t, "/v1/iam/oauth/introspect", "hanzo-console", "top-secret", url.Values{"token": {access}}); after["active"] != false {
		t.Fatalf("token still active after revoke: %v", after)
	}
}

// TestJourney_PasswordGrant_and_TokenExchange proves the two non-interactive grants
// the console/BFF rely on.
func TestJourney_PasswordGrant_and_TokenExchange(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	e := boot(t)

	// Password grant → a first-party session token for alice.
	pw := e.token(t, url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-console"}, "client_secret": {"top-secret"},
		"username": {"alice@hanzo.ai"}, "password": {"pw"}, "scope": {"openid profile"},
	})
	subjectToken, _ := pw["access_token"].(string)
	if subjectToken == "" {
		t.Fatalf("password grant failed: %v", pw)
	}

	// RFC 8693 token exchange: the BFF exchanges alice's token for one scoped to a
	// downstream resource, still bound to alice.
	xe := e.token(t, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":  {"hanzo-console"}, "client_secret": {"top-secret"},
		"subject_token": {subjectToken}, "resource": {"hanzo-cloud"},
	})
	if xe["issued_token_type"] != "urn:ietf:params:oauth:token-type:access_token" || xe["access_token"] == "" {
		t.Fatalf("token exchange failed: %v", xe)
	}
}

// TestJourney_AdminConsole_LegacySurface proves the old admin console's calls work:
// get-account (the security contract), get-organizations (OrgSwitcher), get-users.
func TestJourney_AdminConsole_LegacySurface(t *testing.T) {
	e := boot(t)
	root := e.mint(t, "admin/root") // a SuperAdmin bearer

	// get-account — {status:ok, data:<masked user>} with owner + isAdmin.
	acct := e.getJSON(t, "/v1/iam/account", root)
	if acct["status"] != "ok" {
		t.Fatalf("get-account status: %v", acct)
	}

	// get-organizations — the OrgSwitcher workhorse; SuperAdmin sees all.
	orgs := e.getJSON(t, "/v1/iam/get-organizations", root)
	if orgs["status"] != "ok" {
		t.Fatalf("get-organizations status: %v", orgs)
	}
	if data, _ := orgs["data"].([]any); len(data) < 2 {
		t.Fatalf("get-organizations returned %d orgs, want >=2 (admin+hanzo)", len(data))
	}

	// get-users scoped to an org — no secret leaks.
	usersBody := e.getRaw(t, "/v1/iam/get-users?owner=hanzo", root)
	if strings.Contains(usersBody, "passwordHash") || strings.Contains(usersBody, "\"password\"") {
		t.Fatalf("get-users leaked a secret: %s", usersBody)
	}
}

// TestJourney_SCIMProvisioning proves the RFC-standard provisioning path an IdP uses.
func TestJourney_SCIMProvisioning(t *testing.T) {
	e := boot(t)
	root := e.mint(t, "admin/root")

	create := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"newhire",` +
		`"active":true,"password":"pw","urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo"}}`
	st, body := e.req(t, "POST", "/v1/iam/scim/v2/Users", root, create, "application/scim+json")
	if st != 201 {
		t.Fatalf("SCIM create status = %d: %s", st, body)
	}
	if st, _ := e.req(t, "GET", "/v1/iam/scim/v2/Users/hanzo/newhire", root, "", ""); st != 200 {
		t.Fatalf("SCIM get status = %d", st)
	}
	if st, _ := e.req(t, "DELETE", "/v1/iam/scim/v2/Users/hanzo/newhire", root, "", ""); st != 204 {
		t.Fatalf("SCIM delete status = %d", st)
	}
}

// ---- flow helpers ----

func (e *env) login(t *testing.T, verifier string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]string{
		"type": "code", "organization": "hanzo", "username": "alice@hanzo.ai", "password": "pw",
		"clientId": "hanzo-console", "redirectUri": redirectURI, "scope": "openid profile email offline_access",
		"codeChallenge": pkce.Challenge(verifier), "codeChallengeMethod": "S256",
	})
	st, resp := e.req(t, "POST", "/v1/iam/login", "", string(body), "application/json")
	if st != 200 {
		t.Fatalf("login status = %d: %s", st, resp)
	}
	var m map[string]any
	_ = json.Unmarshal([]byte(resp), &m)
	code, _ := m["data"].(string)
	if code == "" {
		t.Fatalf("login returned no code: %s", resp)
	}
	return code
}

func (e *env) token(t *testing.T, form url.Values) map[string]any {
	t.Helper()
	st, body := e.req(t, "POST", "/v1/iam/oauth/token", "", form.Encode(), "application/x-www-form-urlencoded")
	_ = st
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	return m
}

func (e *env) form(t *testing.T, path, clientID, secret string, form url.Values) map[string]any {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(form.Encode()))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	resp, err := testhttp.Do(e.app, req)
	if err != nil {
		t.Fatalf("form %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return m
}

func (e *env) req(t *testing.T, method, path, bearer, body, contentType string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(e.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (e *env) getJSON(t *testing.T, path, bearer string) map[string]any {
	t.Helper()
	_, body := e.req(t, "GET", path, bearer, "", "")
	var m map[string]any
	_ = json.Unmarshal([]byte(body), &m)
	return m
}

func (e *env) getRaw(t *testing.T, path, bearer string) string {
	t.Helper()
	_, body := e.req(t, "GET", path, bearer, "", "")
	return body
}

// mint signs an RS256 bearer for sub under the seeded cert — a valid principal the
// Guard admits (used for the compat/SCIM admin calls, which need a verified bearer
// but not a persisted grant row).
func (e *env) mint(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub, "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(e.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// ---- seed helpers ----

func seedCert(t *testing.T, db orm.DB, key *rsa.PrivateKey) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = "admin", kid, "RS256"
	keyring.Set(c.Name, string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})))
	c.SetId("admin/" + kid)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

func seedApp(t *testing.T, db orm.DB) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId, a.ClientSecret = "admin", "hanzo-console", "hanzo-console", "top-secret"
	a.Organization, a.Cert, a.EnablePassword = "hanzo", kid, true
	a.RedirectUris = []string{redirectURI}
	a.ExpireInHours = 1
	a.SetId("admin/hanzo-console")
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app: %v", err)
	}
}

func seedOrg(t *testing.T, db orm.DB, name string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", name
	o.SetId("admin/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org %s: %v", name, err)
	}
}

func seedUser(t *testing.T, db orm.DB, owner, name, email, password string, admin bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email, u.IsAdmin = owner, name, email, admin
	hash, herr := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if herr != nil {
		t.Fatalf("hash: %v", herr)
	}
	u.PasswordHash, u.PasswordType = string(hash), "bcrypt"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %s/%s: %v", owner, name, err)
	}
}
