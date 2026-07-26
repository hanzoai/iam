// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package registry

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
)

// HTTP-level harness: every test drives the REAL registered token/jwks routes through
// the router a docker client hits, so it exercises the HTTP contract — status,
// WWW-Authenticate, the token JSON, and (for a minted token) verification against
// the SAME JWKS the endpoint serves.

// goldenKeyPEM is a fixed 2048-bit RSA key. Pinning it makes the libtrust key-id
// (goldenKID) a reproducible golden vector rather than a per-run value, and lets
// every token test share one key so a minted token verifies against the served
// JWKS without per-test keygen.
const goldenKeyPEM = `-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDiW+cP7isQziMn
yKKJYUcy10NJTgqB+3+kPXEhuvlxwpOcGPOujMjA3E53u0g13EAH07q+egoHTvkv
QE1R4lvVtINdJr7j56YYMiJGPo4xNpvrtHHWKNVSctrXq9LlsghGaul/vRYRxcTm
zoEZjMpiIXekTxB050rZ+Fk6kLakEYgdKKfJYk5Zonvw6bzXiC5TSNtx/K4kIfjA
Aa0gs10yst7qukM6Dttb45/c5rR5Iffo05zJzNKYVClteMg09KraAxSE5hwprdAk
cwN1sXWgEYKTrncVG7w9IxQ8Meb87wBYW2UbVXD00dYUYxT2Hs1qVnn/lKIuyXI4
QMDwJQ5hAgMBAAECggEAAWQcsaeeSqJlq2krfIolQJ37iyAIZv+Xa3g4MYOfZFBU
jWVG3Bf/5NWFwu0a9r/FgfbOYzzHQn+8/soXn4zzUQcktoYWLrrd9bCbLtDUGV/T
SfnIKE+EbhcIGsKyz1gOfnZKPI96Kv5K5Ts4JmLL3JoFjPQybvF774Z77+TzRmNV
O/ugqOUxLoW6vtBUw7vqEHOdUp1PmRUeO/lAH5PR3DWCSydIiL0G3BdlQaZoiA1R
svCfJkN5K0tdZfEuvOK33PjkeTjmZgjeguOezd7dZxIVE9GZm3qpOHZ3dNo1Ge0V
/Ty/6gKJd26t5urMj4LxhLv+U9QfxPQGeujjNnJAAQKBgQD1aWMR5pfkRvNsgzA7
tlC18MSfsQ4v0T9rzSXxD3p8fe19rILgsSmxavXOLNyqynIb9k7pc0fmgO69nA6N
Mz+dShqLa95FQu3BDWVO6oV4aCJfmVt8bdAhGswt7BQMR/AgAiHM1JRIcrjwIFuF
2yfyTJT4+P4blwtXmjL7/uEmYQKBgQDsIBNcB27+WzO8nDxk9jKsHW/gtoSGp5qu
lCi+PhH8Lchlv4SnU/Czo4mlKiJk66S8KPqNl0aDrYrNCIEoXwON1p5cNoJHxGo4
Peb3xG4UdcI7CSYOJheELDtNFQ7Jnnh+j+pc1sF9s74bwvVMfA3g4f/Bp8BBk+aC
RDI9f/zoAQKBgQDvmo9hgNQ3ypYMEiHbiutOV96BU6rYQOI87DTpIQWj2ocvNmkp
248ra5TGUcK49aNnbZoqD6XZhXSSp3UFo02u0hUMnqqK0Qe0ftG0tQDPSEyXLfHG
kKiuSa2kAGSqgOoPNkWt6LdF7MxnlhAFpq1fwimI1AG1CknGpAS3SGimwQKBgQCQ
Nf7c5AVb/6OXe+w+1UaZa9kaax6BhvenzAEeP5aIaAXObqu77j5B2I2GfDdJX8na
yURNGakNXv44vwry9ySaigtp0ji7UDB3bQcVJ7j7cfhQSgQd/BG8va7yIvxHEywQ
UCEY1miSNybSmb1rGxD22dB0G9oFsyjDQpdUjEiQAQKBgQChWgkzefBOxPXLWPys
Dkmhp3QOH3bI46OA/r6awJpE5A0rpjIzxTPiJFyPFCV+2r7lrXZ9xsxf95xxkq58
SrP58cloZiYdfe4H2OhqztdmQVFa9PnZzvd3EcHwjPJ4Splgx3oVwUFdRE3LSBvQ
4HPLPh7oIoRvEFyhRe5h0vu2Kw==
-----END PRIVATE KEY-----
`

// goldenKID is the libtrust key-id of goldenKeyPEM, computed independently (the
// beego libtrustKeyID algorithm) and pinned: the registry's ROOTCERTBUNDLE keys
// its trust by this exact string, so a drift here is a cutover-breaking change.
const goldenKID = "4OXX:MSLV:WPTU:C3KW:NTVU:RRAB:BXZS:L3WB:NUPJ:UI7X:WVFG:EHRL"

const testHost = "iam.hanzo.ai"

func openTestDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds() // force the schema init() (kind registration)
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "registry.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// testKeyring builds a keyring from the pinned golden key — deterministic and
// keygen-free, so every token verifies against the same served JWKS.
func testKeyring(t *testing.T) *keyring {
	t.Helper()
	key, err := parseRSAPEM([]byte(goldenKeyPEM))
	if err != nil {
		t.Fatalf("parse golden key: %v", err)
	}
	return newKeyring(key)
}

// newServer registers the registry surface exactly as routes.Route does — on a root
// (empty-prefix) PUBLIC router — with an injected keyring resolver. The resolver
// closes over the fixed golden key, so tests never touch env/process state and the
// signing/JWKS key is deterministic.
func newServer(t *testing.T) (*zip.App, orm.DB, *keyring) {
	t.Helper()
	db := openTestDB(t)
	kr := testKeyring(t)
	app := zip.New(zip.Config{AppName: "iam2-registry-test", DisableStartupMessage: true})
	route(app.Group(""), db, func() (*keyring, error) { return kr, nil })
	return app, db, kr
}

// --- seed helpers ---

func seedUser(t *testing.T, db orm.DB, org, name, password string, isAdmin bool) {
	t.Helper()
	hash, err := cred.Hash(password)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u := orm.New[schema.User](db)
	u.Owner = org
	u.Name = name
	u.PasswordHash = hash
	u.PasswordType = cred.TypeArgon2id
	u.IsAdmin = isAdmin
	u.SetId(org + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func seedUserKey(t *testing.T, db orm.DB, org, name, accessKey string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner = org
	u.Name = name
	u.AccessKey = accessKey
	u.SetId(org + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user key: %v", err)
	}
}

// seedKeyRow creates a user in org `org` (IsAdmin as given) plus a schema.Key
// (pk-/sk- halves) that belongs to it — the exact shape store.UserByAccessKey
// resolves a pk-/sk- credential through. Used to model the attacker: a key minted
// in the attacker's OWN org (a legitimate self-org write) that must nonetheless
// gain nothing on the shared registry.
func seedKeyRow(t *testing.T, db orm.DB, org, name string, isAdmin bool, pk, sk string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner = org
	u.Name = name
	u.IsAdmin = isAdmin
	u.SetId(org + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed key-row user: %v", err)
	}
	k := orm.New[schema.Key](db)
	k.Owner = org
	k.Name = name + "-key"
	k.User = org + "/" + name
	k.AccessKey = pk
	k.AccessSecret = sk
	k.SetId(org + "/" + name + "-key")
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed key row: %v", err)
	}
}

// seedApp seeds a confidential app owned by the admin org — a legitimate platform
// service account (the CI/push identity shape).
func seedApp(t *testing.T, db orm.DB, clientID, secret string) {
	t.Helper()
	seedAppInOrg(t, db, "admin", clientID, secret)
}

// seedAppInOrg seeds a confidential app OWNED by `owner` — the field the
// candidateOrgs gate checks. owner="evil" models a tenant that created an app in
// its own org (a legitimate self-org write) and tries to use it on the shared
// registry.
func seedAppInOrg(t *testing.T, db orm.DB, owner, clientID, secret string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner = owner
	a.Name = clientID
	a.ClientId = clientID
	a.ClientSecret = secret
	a.Organization = owner
	a.SetId(owner + "/" + clientID)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app: %v", err)
	}
}

// --- HTTP drivers ---

// tokenGET drives the docker GET flow: Basic creds + query scopes.
func tokenGET(t *testing.T, app *zip.App, id, secret, service string, scopes ...string) (int, map[string]any, http.Header) {
	t.Helper()
	q := url.Values{}
	if service != "" {
		q.Set("service", service)
	}
	for _, s := range scopes {
		q.Add("scope", s)
	}
	req := httptest.NewRequest("GET", PathToken+"?"+q.Encode(), nil)
	req.Host = testHost
	if id != "" || secret != "" {
		req.SetBasicAuth(id, secret)
	}
	return do(t, app, req)
}

// tokenPOST drives the OAuth2 POST flow: form username/password + form scopes.
func tokenPOST(t *testing.T, app *zip.App, id, secret, service string, scopes ...string) (int, map[string]any, http.Header) {
	t.Helper()
	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("username", id)
	form.Set("password", secret)
	if service != "" {
		form.Set("service", service)
	}
	for _, s := range scopes {
		form.Add("scope", s)
	}
	req := httptest.NewRequest("POST", PathToken, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = testHost
	return do(t, app, req)
}

func do(t *testing.T, app *zip.App, req *http.Request) (int, map[string]any, http.Header) {
	t.Helper()
	resp, err := app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	var m map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatalf("decode %q (status %d): %v", string(raw), resp.StatusCode, err)
		}
	}
	return resp.StatusCode, m, resp.Header
}

// verifyClaims verifies a minted token against the JWKS the endpoint serves — the
// full external-verifier round-trip — and returns the claims. It asserts RS256, a
// header kid matching the JWKS key, and a valid signature.
func verifyClaims(t *testing.T, app *zip.App, tokenStr string) jwt.MapClaims {
	t.Helper()
	pub, kid := servedKey(t, app)
	claims := jwt.MapClaims{}
	tok, err := jwt.ParseWithClaims(tokenStr, claims, func(tk *jwt.Token) (any, error) {
		if tk.Method.Alg() != "RS256" {
			t.Fatalf("alg = %s, want RS256", tk.Method.Alg())
		}
		if h, _ := tk.Header["kid"].(string); h != kid {
			t.Fatalf("header kid = %q, want served %q", h, kid)
		}
		return pub, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil {
		t.Fatalf("verify token against served JWKS: %v", err)
	}
	if !tok.Valid {
		t.Fatal("token did not verify against served JWKS")
	}
	return claims
}

// servedKey reconstructs the RSA public key the JWKS endpoint publishes.
func servedKey(t *testing.T, app *zip.App) (*rsa.PublicKey, string) {
	t.Helper()
	status, body, _ := do(t, app, func() *http.Request {
		r := httptest.NewRequest("GET", PathJWKS, nil)
		r.Host = testHost
		return r
	}())
	if status != 200 {
		t.Fatalf("jwks status = %d", status)
	}
	keys, _ := body["keys"].([]any)
	if len(keys) != 1 {
		t.Fatalf("jwks keys = %d, want 1", len(keys))
	}
	k, _ := keys[0].(map[string]any)
	if k["kty"] != "RSA" || k["alg"] != "RS256" || k["use"] != "sig" {
		t.Fatalf("jwks key header = %v", k)
	}
	nStr, _ := k["n"].(string)
	eStr, _ := k["e"].(string)
	nb, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		t.Fatalf("jwks n: %v", err)
	}
	eb, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		t.Fatalf("jwks e: %v", err)
	}
	kid, _ := k["kid"].(string)
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nb), E: int(new(big.Int).SetBytes(eb).Int64())}, kid
}

// accessOf extracts the token's `access` array as a comparable slice.
func accessOf(t *testing.T, claims jwt.MapClaims) []access {
	t.Helper()
	raw, ok := claims["access"]
	if !ok || raw == nil {
		return nil
	}
	b, _ := json.Marshal(raw)
	var out []access
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("access decode: %v", err)
	}
	return out
}

// --- tests ---

// TestToken_ServiceAccount_PullPush is the CI push identity: a confidential app's
// clientId:clientSecret is privileged, so a pull,push scope is granted in full and
// the minted token verifies against the served JWKS with the exact Docker shape.
func TestToken_ServiceAccount_PullPush(t *testing.T) {
	app, db, kr := newServer(t)
	seedApp(t, db, "hanzo-registry", "s3cr3t-pushpull")

	status, body, _ := tokenGET(t, app, "hanzo-registry", "s3cr3t-pushpull",
		"registry.hanzo.ai", "repository:hanzo/app:pull,push")
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	tokStr, _ := body["token"].(string)
	if tokStr == "" {
		t.Fatal("no token in response")
	}
	if body["access_token"] != tokStr {
		t.Fatal("access_token must mirror token")
	}
	if body["expires_in"].(float64) != 900 {
		t.Fatalf("expires_in = %v, want 900", body["expires_in"])
	}

	claims := verifyClaims(t, app, tokStr)
	if claims["iss"] != issuer {
		t.Fatalf("iss = %v, want %q", claims["iss"], issuer)
	}
	if claims["aud"] != "registry.hanzo.ai" {
		t.Fatalf("aud = %v, want the service (a bare string)", claims["aud"])
	}
	if claims["sub"] != "hanzo-registry" {
		t.Fatalf("sub = %v, want the clientId", claims["sub"])
	}
	// exp/nbf/iat are integer seconds; the lifetime is exactly tokenTTL.
	exp := int64(claims["exp"].(float64))
	iat := int64(claims["iat"].(float64))
	nbf := int64(claims["nbf"].(float64))
	if exp-iat != 900 {
		t.Fatalf("exp-iat = %d, want 900", exp-iat)
	}
	if nbf != iat {
		t.Fatalf("nbf (%d) != iat (%d)", nbf, iat)
	}
	if claims["jti"] == nil || claims["jti"] == "" {
		t.Fatal("missing jti")
	}
	acc := accessOf(t, claims)
	want := []access{{Type: "repository", Name: "hanzo/app", Actions: []string{"pull", "push"}}}
	if !eqAccess(acc, want) {
		t.Fatalf("access = %v, want %v", acc, want)
	}
	// The header kid is the pinned libtrust id the ROOTCERTBUNDLE trusts.
	if kr.kid != goldenKID {
		t.Fatalf("keyring kid = %q, want golden %q", kr.kid, goldenKID)
	}
}

// TestToken_User_PullOnly proves a non-privileged authenticated user is restricted
// to pull: push is dropped, never silently granted.
func TestToken_User_PullOnly(t *testing.T) {
	app, db, _ := newServer(t)
	seedUser(t, db, "hanzo", "alice", "correct horse", false)

	status, body, _ := tokenGET(t, app, "alice", "correct horse",
		"registry.hanzo.ai", "repository:hanzo/app:pull,push")
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	claims := verifyClaims(t, app, body["token"].(string))
	if claims["sub"] != "hanzo/alice" {
		t.Fatalf("sub = %v, want hanzo/alice", claims["sub"])
	}
	acc := accessOf(t, claims)
	want := []access{{Type: "repository", Name: "hanzo/app", Actions: []string{"pull"}}}
	if !eqAccess(acc, want) {
		t.Fatalf("access = %v, want pull-only %v", acc, want)
	}
}

// TestToken_User_PushOnly_Denied proves fail-closed: a non-privileged user asking
// for a push-only scope gets NO access entry for that repo (not an empty grant).
func TestToken_User_PushOnly_Denied(t *testing.T) {
	app, db, _ := newServer(t)
	seedUser(t, db, "hanzo", "bob", "hunter2 hunter2", false)

	status, body, _ := tokenGET(t, app, "bob", "hunter2 hunter2",
		"registry.hanzo.ai", "repository:hanzo/secret:push")
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	claims := verifyClaims(t, app, body["token"].(string))
	if acc := accessOf(t, claims); len(acc) != 0 {
		t.Fatalf("access = %v, want empty (push denied, no silent grant)", acc)
	}
}

// TestToken_HanzoOrgAdmin_CanPush is the v1-PARITY assertion: a hanzo-org user with
// IsAdmin=true authenticates (hanzo ∈ candidateOrgs) and IS privileged — casdoor
// grants push to an IsAdmin within {admin,hanzo}, and this port preserves that
// exactly. The real cross-tenant close is that a FOREIGN-tenant admin never reaches
// this gate (TestToken_ForeignTenantKey_Denied). Tightening hanzo-human push to
// admin-org-only is a deferred owner policy decision, not a migration change.
func TestToken_HanzoOrgAdmin_CanPush(t *testing.T) {
	app, db, _ := newServer(t)
	seedUser(t, db, "hanzo", "carol", "s0verysecret!!", true) // IsAdmin in org hanzo

	status, body, _ := tokenGET(t, app, "carol", "s0verysecret!!",
		"registry.hanzo.ai", "repository:hanzo/app:pull,push")
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	claims := verifyClaims(t, app, body["token"].(string))
	acc := accessOf(t, claims)
	want := []access{{Type: "repository", Name: "hanzo/app", Actions: []string{"pull", "push"}}}
	if !eqAccess(acc, want) {
		t.Fatalf("hanzo-org admin access = %v, want pull+push %v (v1 parity)", acc, want)
	}
}

// TestToken_SuperAdminKey_CanPush proves a SuperAdmin (admin org) pushes via its
// HIGH-ENTROPY machine credential — an API key — and is privileged (owner==admin).
// This is the reserved-org push identity that remains after the password path is
// narrowed to non-reserved orgs (see TestToken_SuperAdminPassword_Denied).
func TestToken_SuperAdminKey_CanPush(t *testing.T) {
	app, db, _ := newServer(t)
	seedUserKey(t, db, "admin", "z", "hk-SUPERADMINkey0001") // owner==admin ⇒ SuperAdmin

	status, body, _ := tokenGET(t, app, "z", "hk-SUPERADMINkey0001",
		"registry.hanzo.ai", "repository:hanzo/app:pull,push")
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	claims := verifyClaims(t, app, body["token"].(string))
	if claims["sub"] != "admin/z" {
		t.Fatalf("sub = %v, want admin/z", claims["sub"])
	}
	acc := accessOf(t, claims)
	if len(acc) != 1 || !eqStrings(acc[0].Actions, []string{"pull", "push"}) {
		t.Fatalf("superadmin key access = %v, want pull+push", acc)
	}
}

// TestToken_SuperAdminPassword_Denied is the FINDING 2 policy: a reserved-org
// (SuperAdmin) WEB PASSWORD is NOT a registry credential. Even the CORRECT password
// is refused (401, no token) — a guessable password never authenticates the platform
// root identity on a public realm, and verifying it can never drive its lockout
// counter (no unauth DoS on the super). The SuperAdmin pushes via its API key /
// service account instead (TestToken_SuperAdminKey_CanPush).
func TestToken_SuperAdminPassword_Denied(t *testing.T) {
	app, db, _ := newServer(t)
	seedUser(t, db, "admin", "z", "${SEED_SUPERUSER_PASSWORD}", false) // owner==admin ⇒ SuperAdmin

	for _, flow := range []string{"GET", "POST"} {
		var status int
		var body map[string]any
		if flow == "GET" {
			status, body, _ = tokenGET(t, app, "z", "${SEED_SUPERUSER_PASSWORD}",
				"registry.hanzo.ai", "repository:hanzo/app:pull,push")
		} else {
			status, body, _ = tokenPOST(t, app, "z", "${SEED_SUPERUSER_PASSWORD}",
				"registry.hanzo.ai", "repository:hanzo/app:pull,push")
		}
		if status != 401 || body["token"] != nil {
			t.Fatalf("%s: SuperAdmin password ACCEPTED on the registry: status=%d body=%v — reserved-org password must not be a registry credential", flow, status, body)
		}
	}
}

// TestToken_ApiKey_Password proves the hk- API-key credential path: the key rides
// in the password field (docker login -u <anything> -p hk-...) and resolves to its
// owning user through the ONE key resolver.
func TestToken_ApiKey_Password(t *testing.T) {
	app, db, _ := newServer(t)
	seedUserKey(t, db, "hanzo", "dave", "hk-DEADBEEFdeadbeef00")

	status, body, _ := tokenGET(t, app, "dave", "hk-DEADBEEFdeadbeef00",
		"registry.hanzo.ai", "repository:hanzo/app:pull")
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	claims := verifyClaims(t, app, body["token"].(string))
	if claims["sub"] != "hanzo/dave" {
		t.Fatalf("sub = %v, want hanzo/dave", claims["sub"])
	}
	acc := accessOf(t, claims)
	want := []access{{Type: "repository", Name: "hanzo/app", Actions: []string{"pull"}}}
	if !eqAccess(acc, want) {
		t.Fatalf("access = %v, want %v", acc, want)
	}
}

// TestToken_ApiKey_Username proves the token-as-username shape (docker login -u
// hk-... -p x) also resolves via the same key path.
func TestToken_ApiKey_Username(t *testing.T) {
	app, db, _ := newServer(t)
	seedUserKey(t, db, "hanzo", "erin", "hk-CAFEBABEcafebabe11")

	status, body, _ := tokenGET(t, app, "hk-CAFEBABEcafebabe11", "x",
		"registry.hanzo.ai", "repository:hanzo/app:pull")
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	claims := verifyClaims(t, app, body["token"].(string))
	if claims["sub"] != "hanzo/erin" {
		t.Fatalf("sub = %v, want hanzo/erin", claims["sub"])
	}
}

// TestToken_ForeignTenantKey_Denied is the regression proof for the cross-tenant
// image-poisoning CRITICAL. The attacker self-onboards org "evil" (becomes IsAdmin
// there), mints a key in their OWN org (a legitimate self-org write), and presents
// it at docker login. The key resolves — to a user whose owner is "evil" — but
// that owner is outside candidateOrgs {admin, hanzo}, so authentication is DENIED:
// 401, NO token. A foreign-tenant key cannot get even a pull token, let alone
// push. Before the fix this path minted a privileged (push) token on the shared
// registry.
func TestToken_ForeignTenantKey_Denied(t *testing.T) {
	app, db, _ := newServer(t)
	seedKeyRow(t, db, "evil", "mallory", true, "pk-live-EVIL", "sk-live-EVIL")

	// Probe BOTH key halves and BOTH credential positions (username / password),
	// and BOTH a push and a pull scope — every shape must be denied.
	for _, key := range []string{"sk-live-EVIL", "pk-live-EVIL"} {
		for _, scope := range []string{"repository:hanzo/iam:pull,push", "repository:hanzo/iam:pull"} {
			// key as password
			status, body, hdr := tokenGET(t, app, "mallory", key, "registry.hanzo.ai", scope)
			if status != 401 || body["token"] != nil {
				t.Fatalf("foreign key %s (password) scope %q: status=%d body=%v — must be 401/no token", key, scope, status, body)
			}
			if hdr.Get("WWW-Authenticate") == "" {
				t.Fatalf("foreign key %s: missing WWW-Authenticate on 401", key)
			}
			// key as username
			status, body, _ = tokenGET(t, app, key, "x", "registry.hanzo.ai", scope)
			if status != 401 || body["token"] != nil {
				t.Fatalf("foreign key %s (username) scope %q: status=%d body=%v — must be 401/no token", key, scope, status, body)
			}
		}
	}
}

// TestToken_ForeignTenantApp_Denied is the regression proof for F-R1 — the
// cross-tenant push path via the service-account credential shape. The attacker
// self-onboards org "evil" and creates a confidential app OWNED by "evil" (a
// legitimate self-org write) with a clientId/clientSecret, then docker-logs-in with
// those. NON-VACUOUS: the secret MATCHES, so the constant-time compare passes and
// the ONLY thing denying the request is the candidateOrgs gate on app.Owner — a
// foreign-org app is denied 401, NO token, no push. Before the fix this minted a
// privileged (push) token because serviceAccount resolved GetApplicationByClientId
// globally with no org bound.
func TestToken_ForeignTenantApp_Denied(t *testing.T) {
	app, db, _ := newServer(t)
	seedAppInOrg(t, db, "evil", "evilci-xyz", "evil-secret-matches")

	for _, scope := range []string{"repository:hanzo/iam:pull,push", "repository:hanzo/iam:pull"} {
		// Basic-auth (docker GET flow) with the CORRECT secret — denial is the gate.
		status, body, hdr := tokenGET(t, app, "evilci-xyz", "evil-secret-matches", "registry.hanzo.ai", scope)
		if status != 401 || body["token"] != nil {
			t.Fatalf("foreign app (GET) scope %q: status=%d body=%v — must be 401/no token", scope, status, body)
		}
		if hdr.Get("WWW-Authenticate") == "" {
			t.Fatal("foreign app: missing WWW-Authenticate on 401")
		}
		// OAuth2 POST flow — same denial.
		status, body, _ = tokenPOST(t, app, "evilci-xyz", "evil-secret-matches", "registry.hanzo.ai", scope)
		if status != 401 || body["token"] != nil {
			t.Fatalf("foreign app (POST) scope %q: status=%d body=%v — must be 401/no token", scope, status, body)
		}
	}
}

// TestToken_HanzoKey_PullToken is the positive control for the API-key path: a
// hanzo-org pk-/sk- Key resolves and gets a (pull) token, so the candidateOrgs gate
// admits in-platform keys — the foreign-key denial is the gate, not a broken path.
func TestToken_HanzoKey_PullToken(t *testing.T) {
	app, db, _ := newServer(t)
	seedKeyRow(t, db, "hanzo", "grace", false, "pk-live-HANZO", "sk-live-HANZO")

	for _, key := range []string{"sk-live-HANZO", "pk-live-HANZO"} {
		status, body, _ := tokenGET(t, app, "x", key, "registry.hanzo.ai", "repository:hanzo/app:pull")
		if status != 200 {
			t.Fatalf("hanzo key %s: status=%d body=%v — must authenticate", key, status, body)
		}
		claims := verifyClaims(t, app, body["token"].(string))
		if claims["sub"] != "hanzo/grace" {
			t.Fatalf("hanzo key %s: sub=%v, want hanzo/grace", key, claims["sub"])
		}
		acc := accessOf(t, claims)
		want := []access{{Type: "repository", Name: "hanzo/app", Actions: []string{"pull"}}}
		if !eqAccess(acc, want) {
			t.Fatalf("hanzo key %s: access=%v, want %v", key, acc, want)
		}
	}
}

// TestToken_BadPassword_401 proves a wrong password yields 401 with a
// WWW-Authenticate challenge and NO token — no oracle, fail-closed.
func TestToken_BadPassword_401(t *testing.T) {
	app, db, _ := newServer(t)
	seedUser(t, db, "hanzo", "frank", "the real password", false)

	status, body, hdr := tokenGET(t, app, "frank", "WRONG",
		"registry.hanzo.ai", "repository:hanzo/app:pull")
	if status != 401 {
		t.Fatalf("status = %d, want 401", status)
	}
	if body["token"] != nil {
		t.Fatalf("token leaked on bad creds: %v", body)
	}
	if !strings.HasPrefix(hdr.Get("WWW-Authenticate"), "Basic realm=") {
		t.Fatalf("WWW-Authenticate = %q", hdr.Get("WWW-Authenticate"))
	}
}

// TestToken_AdminPassword_NotDosableOnPublicRegistry is the FINDING 2 DoS proof: an
// unauthenticated attacker MUST NOT be able to lock the platform SuperAdmin out of
// its password doors by hammering the PUBLIC registry endpoint. It mints a SuperAdmin
// (org "admin") through the REAL users.Create path, then floods far past the lock
// threshold with wrong passwords on the public token endpoint. Every attempt is a
// no-match 401 (reserved-org password is not a registry credential), and — crucially
// — the admin row's shared lockout counter is NEVER advanced, so the super stays
// signable on every OTHER door. The registry password path never touches a reserved
// account.
func TestToken_AdminPassword_NotDosableOnPublicRegistry(t *testing.T) {
	app, db, _ := newServer(t)
	ctx := context.Background()
	const pw = "the real admin password"
	if _, err := users.New(db).Create(ctx, &users.CreateInput{
		User:     schema.User{Owner: "admin", Name: "root", IsAdmin: true},
		Password: pw,
	}); err != nil {
		t.Fatalf("create admin user through the canonical path: %v", err)
	}

	// Flood well past the threshold with wrong passwords — each a fresh HTTP request.
	for i := 0; i < users.LockThreshold*3; i++ {
		status, body, _ := tokenGET(t, app, "root", "WRONG",
			"registry.hanzo.ai", "repository:hanzo/app:pull")
		if status != 401 || body["token"] != nil {
			t.Fatalf("wrong attempt %d: status=%d body=%v, want 401 no-token", i, status, body)
		}
	}
	// The SuperAdmin's shared lockout counter is untouched — the public registry could
	// NOT weaponize a hard per-account lock against the super.
	after, err := store.GetUserByName(ctx, db, "admin", "root")
	if err != nil || after == nil {
		t.Fatalf("reload admin/root: %v", err)
	}
	if after.SigninWrongTimes != 0 {
		t.Fatalf("admin/root SigninWrongTimes = %d after a public registry flood, want 0 — unauth SuperAdmin lockout DoS", after.SigninWrongTimes)
	}
}

// TestToken_RegistryPassword_NoCrossOrgCoupling is the FINDING 2 coupling/parity
// proof for the z@hanzo.ai collision (same name+email in BOTH the reserved admin org
// and the non-reserved hanzo org, with DIFFERENT passwords). It asserts:
//   - a wrong registry password advances ONLY the hanzo row's counter (single-row,
//     login-parity — no double-speed), and NEVER the reserved admin row's;
//   - the correct hanzo password authenticates as hanzo/z and never touches admin/z.
func TestToken_RegistryPassword_NoCrossOrgCoupling(t *testing.T) {
	app, db, _ := newServer(t)
	ctx := context.Background()
	// Same identifier in both orgs (the real collision). seedUser sets Name; give both
	// the same email so an email-form login would resolve both, too.
	if _, err := users.New(db).Create(ctx, &users.CreateInput{
		User:     schema.User{Owner: "admin", Name: "z", Email: "z@hanzo.ai"},
		Password: "admin-only-secret",
	}); err != nil {
		t.Fatalf("create admin/z: %v", err)
	}
	if _, err := users.New(db).Create(ctx, &users.CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"},
		Password: "hanzo-only-secret",
	}); err != nil {
		t.Fatalf("create hanzo/z: %v", err)
	}

	// One wrong attempt: exactly ONE row (the non-reserved hanzo/z) is bumped; admin/z
	// is untouched.
	status, body, _ := tokenGET(t, app, "z", "WRONG", "registry.hanzo.ai", "repository:hanzo/app:pull")
	if status != 401 || body["token"] != nil {
		t.Fatalf("wrong attempt: status=%d body=%v, want 401 no-token", status, body)
	}
	adminZ, _ := store.GetUserByName(ctx, db, "admin", "z")
	hanzoZ, _ := store.GetUserByName(ctx, db, "hanzo", "z")
	if adminZ.SigninWrongTimes != 0 {
		t.Fatalf("admin/z counter = %d after a wrong registry attempt on a shared name, want 0 — cross-org coupling / reserved DoS", adminZ.SigninWrongTimes)
	}
	if hanzoZ.SigninWrongTimes != 1 {
		t.Fatalf("hanzo/z counter = %d after ONE wrong attempt, want 1 — single-row login-parity", hanzoZ.SigninWrongTimes)
	}

	// The correct hanzo password authenticates as hanzo/z (resets its own counter) and
	// never touches admin/z.
	status, body, _ = tokenGET(t, app, "z", "hanzo-only-secret", "registry.hanzo.ai", "repository:hanzo/app:pull")
	if status != 200 {
		t.Fatalf("correct hanzo password: status=%d body=%v, want 200", status, body)
	}
	claims := verifyClaims(t, app, body["token"].(string))
	if claims["sub"] != "hanzo/z" {
		t.Fatalf("sub = %v, want hanzo/z", claims["sub"])
	}
	adminZ, _ = store.GetUserByName(ctx, db, "admin", "z")
	if adminZ.SigninWrongTimes != 0 {
		t.Fatalf("admin/z counter = %d after a correct hanzo login, want 0 — cross-org coupling", adminZ.SigninWrongTimes)
	}
}

// TestToken_EmptyCreds_401 proves no credential ⇒ 401, no token.
func TestToken_EmptyCreds_401(t *testing.T) {
	app, _, _ := newServer(t)
	status, body, hdr := tokenGET(t, app, "", "", "registry.hanzo.ai",
		"repository:hanzo/app:pull")
	if status != 401 {
		t.Fatalf("status = %d, want 401", status)
	}
	if body["token"] != nil {
		t.Fatalf("token leaked on empty creds: %v", body)
	}
	if hdr.Get("WWW-Authenticate") == "" {
		t.Fatal("missing WWW-Authenticate on 401")
	}
}

// TestToken_UnknownUser_401 proves an unknown username fails closed identically to
// a wrong password (same opaque 401).
func TestToken_UnknownUser_401(t *testing.T) {
	app, _, _ := newServer(t)
	status, body, _ := tokenGET(t, app, "ghost", "whatever",
		"registry.hanzo.ai", "repository:hanzo/app:pull")
	if status != 401 {
		t.Fatalf("status = %d, want 401", status)
	}
	if body["token"] != nil {
		t.Fatal("token leaked for unknown user")
	}
}

// TestToken_WrongServiceSecret_401 proves an application whose secret does not
// match is not authenticated.
func TestToken_WrongServiceSecret_401(t *testing.T) {
	app, db, _ := newServer(t)
	seedApp(t, db, "hanzo-registry", "the-right-secret")
	status, _, _ := tokenGET(t, app, "hanzo-registry", "the-WRONG-secret",
		"registry.hanzo.ai", "repository:hanzo/app:pull,push")
	if status != 401 {
		t.Fatalf("status = %d, want 401", status)
	}
}

// TestToken_POSTForm proves the containerd/BuildKit OAuth2 POST flow: credentials
// and scopes in the form body, no Basic header. access_token must be present.
func TestToken_POSTForm(t *testing.T) {
	app, db, _ := newServer(t)
	seedApp(t, db, "hanzo-buildkit", "buildkit-secret")

	status, body, _ := tokenPOST(t, app, "hanzo-buildkit", "buildkit-secret",
		"registry.hanzo.ai", "repository:hanzo/app:pull,push")
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	at, _ := body["access_token"].(string)
	if at == "" {
		t.Fatal("OAuth2 POST flow must return access_token")
	}
	claims := verifyClaims(t, app, at)
	acc := accessOf(t, claims)
	if len(acc) != 1 || !eqStrings(acc[0].Actions, []string{"pull", "push"}) {
		t.Fatalf("access = %v, want pull+push", acc)
	}
}

// TestToken_MultiScope proves repeated scope params (buildx multi-scope) are all
// honored, not just the first.
func TestToken_MultiScope(t *testing.T) {
	app, db, _ := newServer(t)
	seedApp(t, db, "hanzo-registry", "multi-secret")

	_, body, _ := tokenGET(t, app, "hanzo-registry", "multi-secret", "registry.hanzo.ai",
		"repository:hanzo/a:pull,push", "repository:hanzo/b:pull")
	claims := verifyClaims(t, app, body["token"].(string))
	acc := accessOf(t, claims)
	want := []access{
		{Type: "repository", Name: "hanzo/a", Actions: []string{"pull", "push"}},
		{Type: "repository", Name: "hanzo/b", Actions: []string{"pull"}},
	}
	if !eqAccess(acc, want) {
		t.Fatalf("access = %v, want %v", acc, want)
	}
}

// TestToken_NoScope_LoginOnly proves `docker login` (no scope) authenticates and
// returns a token with an empty access array (a valid login token, no grants).
func TestToken_NoScope_LoginOnly(t *testing.T) {
	app, db, _ := newServer(t)
	seedApp(t, db, "hanzo-registry", "login-secret")

	status, body, _ := tokenGET(t, app, "hanzo-registry", "login-secret", "registry.hanzo.ai")
	if status != 200 {
		t.Fatalf("status = %d, body %v", status, body)
	}
	claims := verifyClaims(t, app, body["token"].(string))
	if acc := accessOf(t, claims); len(acc) != 0 {
		t.Fatalf("access = %v, want empty for a bare login", acc)
	}
}

// TestKID_GoldenVector pins the libtrust key-id algorithm: the fixed key's id must
// equal the pinned golden string AND an independent recomputation of the algorithm,
// so a refactor that drifts the id (and would silently break the ROOTCERTBUNDLE
// trust) fails here.
func TestKID_GoldenVector(t *testing.T) {
	key, err := parseRSAPEM([]byte(goldenKeyPEM))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := libtrustKeyID(&key.PublicKey)
	if got != goldenKID {
		t.Fatalf("libtrustKeyID = %q, want pinned %q", got, goldenKID)
	}
	if indep := independentKID(t, &key.PublicKey); indep != got {
		t.Fatalf("independent kid %q != package kid %q", indep, got)
	}
	// Shape invariants the registry depends on: 12 quads, colon-joined, 48 base32
	// chars (240 bits) — no padding.
	if n := strings.Count(got, ":"); n != 11 {
		t.Fatalf("kid has %d colons, want 11 (12 groups)", n)
	}
	if len(strings.ReplaceAll(got, ":", "")) != 48 {
		t.Fatalf("kid base32 length = %d, want 48", len(strings.ReplaceAll(got, ":", "")))
	}
}

// TestKID_Deterministic proves the id is a pure function of the key.
func TestKID_Deterministic(t *testing.T) {
	key, _ := parseRSAPEM([]byte(goldenKeyPEM))
	if libtrustKeyID(&key.PublicKey) != libtrustKeyID(&key.PublicKey) {
		t.Fatal("kid is not deterministic")
	}
}

// independentKID reimplements the libtrust algorithm from scratch in the test, so
// TestKID_GoldenVector cross-checks the package implementation against a second one.
func independentKID(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	sum := sha256.Sum256(der)
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(sum[:30]), "=")
	var parts []string
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		parts = append(parts, s[i:end])
	}
	return strings.Join(parts, ":")
}

// --- signing-key resolution (fail-closed by default) ---

// clearKeyEnv wipes every signing-key env var for a test, so resolveKeyring reads
// exactly what the test sets and never inherits an ambient key.
func clearKeyEnv(t *testing.T) {
	t.Helper()
	t.Setenv(envSigningKey, "")
	t.Setenv(envSigningKeyFile, "")
	t.Setenv(envAllowEphemeral, "")
}

// TestKeyring_FailsClosed_NoEphemeralByDefault is the regression proof for the
// fail-open MEDIUM: with NO key configured and NO explicit opt-in, resolution
// ERRORS — it must NOT silently mint an ephemeral key the registry cannot trust.
func TestKeyring_FailsClosed_NoEphemeralByDefault(t *testing.T) {
	clearKeyEnv(t)
	kr, err := resolveKeyring()
	if err == nil {
		t.Fatalf("resolveKeyring succeeded (kid %q) with no key and no opt-in — must fail closed", kr.kid)
	}
	if kr != nil {
		t.Fatalf("resolveKeyring returned a keyring on failure: %v", kr)
	}
}

// TestKeyring_EphemeralRequiresOptIn proves an ephemeral key is minted ONLY under
// the explicit dev opt-in.
func TestKeyring_EphemeralRequiresOptIn(t *testing.T) {
	clearKeyEnv(t)
	t.Setenv(envAllowEphemeral, "true")
	kr, err := resolveKeyring()
	if err != nil || kr == nil {
		t.Fatalf("dev opt-in should mint an ephemeral key: kr=%v err=%v", kr, err)
	}
	if kr.kid == "" {
		t.Fatal("ephemeral keyring has no kid")
	}
}

// TestKeyring_LoadsConfiguredKey proves a configured inline key is used and yields
// the pinned kid — the continuity path (same key ⇒ same kid ⇒ ROOTCERTBUNDLE valid).
func TestKeyring_LoadsConfiguredKey(t *testing.T) {
	clearKeyEnv(t)
	t.Setenv(envSigningKey, goldenKeyPEM)
	kr, err := resolveKeyring()
	if err != nil {
		t.Fatalf("resolveKeyring with a configured key: %v", err)
	}
	if kr.kid != goldenKID {
		t.Fatalf("configured-key kid = %q, want golden %q", kr.kid, goldenKID)
	}
}

// TestKeyring_BrokenKeyIsError proves a configured-but-unparseable key is an error
// in every environment — never a silent ephemeral fallback that masks a broken
// secret (even WITH the ephemeral opt-in set).
func TestKeyring_BrokenKeyIsError(t *testing.T) {
	clearKeyEnv(t)
	t.Setenv(envSigningKey, "-----BEGIN PRIVATE KEY-----\nnot base64 pem\n-----END PRIVATE KEY-----")
	t.Setenv(envAllowEphemeral, "true") // even opted-in, a broken configured key must error
	if _, err := resolveKeyring(); err == nil {
		t.Fatal("a broken configured key must be an error, not a silent ephemeral fallback")
	}
}

// --- comparison helpers ---

func eqAccess(a, b []access) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || a[i].Name != b[i].Name || !eqStrings(a[i].Actions, b[i].Actions) {
			return false
		}
	}
	return true
}

func eqStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
