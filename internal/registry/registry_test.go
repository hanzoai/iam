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
)

// HTTP-level harness: every test drives the REAL mounted token/jwks routes through
// the router a docker client hits, so it exercises the wire contract — status,
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

// newServer mounts the registry surface exactly as routes.Route does — on a root
// (empty-prefix) PUBLIC router — with the injected keyring.
func newServer(t *testing.T) (*zip.App, orm.DB, *keyring) {
	t.Helper()
	db := openTestDB(t)
	kr := testKeyring(t)
	app := zip.New(zip.Config{AppName: "iam2-registry-test", DisableStartupMessage: true})
	mount(app.Group(""), db, kr)
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

func seedApp(t *testing.T, db orm.DB, clientID, secret string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner = "admin"
	a.Name = clientID
	a.ClientId = clientID
	a.ClientSecret = secret
	a.Organization = "hanzo"
	a.SetId("admin/" + clientID)
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

// TestToken_AdminUser_PullPush proves an admin user is privileged (push granted).
func TestToken_AdminUser_PullPush(t *testing.T) {
	app, db, _ := newServer(t)
	seedUser(t, db, "hanzo", "carol", "s0verysecret!!", true) // IsAdmin

	_, body, _ := tokenGET(t, app, "carol", "s0verysecret!!",
		"registry.hanzo.ai", "repository:hanzo/app:pull,push")
	claims := verifyClaims(t, app, body["token"].(string))
	acc := accessOf(t, claims)
	want := []access{{Type: "repository", Name: "hanzo/app", Actions: []string{"pull", "push"}}}
	if !eqAccess(acc, want) {
		t.Fatalf("admin access = %v, want %v", acc, want)
	}
}

// TestToken_SuperAdmin_PullPush proves a user in the admin org (SuperAdmin) is
// privileged even without the IsAdmin flag.
func TestToken_SuperAdmin_PullPush(t *testing.T) {
	app, db, _ := newServer(t)
	seedUser(t, db, "admin", "z", "***REMOVED***", false) // owner==admin ⇒ SuperAdmin

	_, body, _ := tokenGET(t, app, "z", "***REMOVED***",
		"registry.hanzo.ai", "repository:hanzo/app:pull,push")
	claims := verifyClaims(t, app, body["token"].(string))
	if claims["sub"] != "admin/z" {
		t.Fatalf("sub = %v, want admin/z", claims["sub"])
	}
	acc := accessOf(t, claims)
	if len(acc) != 1 || !eqStrings(acc[0].Actions, []string{"pull", "push"}) {
		t.Fatalf("superadmin access = %v, want pull+push", acc)
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
