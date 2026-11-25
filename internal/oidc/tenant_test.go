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
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/certs"
	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// AN ORGANIZATION'S APPLICATION SIGNS WITH THE ORGANIZATION'S OWN CERT, under the
// organization's own issuer, published in the organization's own key set. Nothing a
// tenant cert signs is a platform token, and nothing platform trusts a tenant cert.

// memVault is the Vault a host supplies, in memory.
type memVault struct {
	mu sync.Mutex
	m  map[[2]string]string
}

func (v *memVault) Put(_ context.Context, org, name, pem string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.m[[2]string{org, name}]; ok {
		return keyring.ErrExists
	}
	v.m[[2]string{org, name}] = pem
	return nil
}

func (v *memVault) Get(_ context.Context, org, name string) (string, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if p, ok := v.m[[2]string{org, name}]; ok {
		return p, nil
	}
	return "", keyring.ErrNoKey
}

func (v *memVault) Delete(_ context.Context, org, name string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	delete(v.m, [2]string{org, name})
	return nil
}

var getSeq int

const tenantClient = "acme-portal"

// tenant is an organization "acme" with a person, an application and an own cert.
type tenant struct {
	app    *zip.App
	db     orm.DB
	vault  *memVault
	appRow *schema.Application
}

func newTenant(t *testing.T) *tenant {
	t.Helper()
	db := openTestDB(t)
	app := zip.New(zip.Config{AppName: "iam-test", DisableStartupMessage: true})
	Route(app.Group(""), db)
	certs.Route(app.Group(""), db)
	tenantSets.Lock()
	tenantSets.m, tenantSets.order = map[string]*keySet{}, nil
	tenantSets.Unlock()
	v := &memVault{m: map[[2]string]string{}}
	keyring.UseVault(v)
	t.Cleanup(func() { keyring.UseVault(nil) })

	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", "acme"
	o.SetId("admin/acme")
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	seedUserInOrg(t, db, "acme", "alice", "alice@acme.example", "pw")
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.Organization = "acme", "portal", "acme"
	a.ClientId, a.ClientSecret, a.Cert = tenantClient, "s3cret", "acme-signing"
	a.EnablePassword, a.ExpireInHours = true, 1
	a.RedirectUris = []string{testRedirect}
	a.SetId("acme/portal")
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	tn := &tenant{app: app, db: db, vault: v, appRow: a}
	tn.createCert(t, "acme", "acme-signing", http.StatusOK)
	return tn
}

// createCert asks the certs surface for a tenant cert, as the router would hand it.
func (tn *tenant) createCert(t *testing.T, org, name string, want int) {
	t.Helper()
	resp, body := do(t, tn.app, jsonReq("POST", "/v1/iam/certs", map[string]any{"owner": org, "name": name, "scope": schema.CertTenant}))
	if resp.StatusCode != want {
		t.Fatalf("create tenant cert %s/%s: status %d, want %d: %s", org, name, resp.StatusCode, want, body)
	}
}

// signIn returns the token response of acme/alice's sign-in to the tenant app.
func (tn *tenant) signIn(t *testing.T) map[string]any {
	t.Helper()
	code, resp, body := loginForCode(t, tn.app, map[string]string{
		"organization": "acme", "username": "alice", "password": "pw",
		"clientId": tenantClient, "redirectUri": testRedirect, "scope": "openid profile email", "nonce": "n1",
	})
	if code == "" {
		t.Fatalf("login minted no code: %d %s", resp.StatusCode, body)
	}
	tr, tok := exchangeCode(t, tn.app, url.Values{
		"code": {code}, "client_id": {tenantClient}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	if tr.StatusCode != 200 {
		t.Fatalf("exchange: %d %v", tr.StatusCode, tok)
	}
	return tok
}

// get fetches path from host. The response is cached at the edge of the router per path, so each
// call carries its own query and reads what the store holds now.
func (tn *tenant) get(t *testing.T, host, path string) (int, []byte) {
	t.Helper()
	getSeq++
	req := formReqNoBody("GET", path+"?seq="+strconv.Itoa(getSeq))
	req.Host = host
	resp, body := do(t, tn.app, req)
	return resp.StatusCode, body
}

// keyOf builds the RSA public key of a JWK.
func keyOf(t *testing.T, jwk map[string]any) *rsa.PublicKey {
	t.Helper()
	n, err := base64.RawURLEncoding.DecodeString(jwk["n"].(string))
	if err != nil {
		t.Fatal(err)
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk["e"].(string))
	if err != nil {
		t.Fatal(err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
}

// verifyAt verifies tok against the key set served at path, the way a relying party
// holding that issuer's discovery would: kid, signature, algorithm and issuer.
func (tn *tenant) verifyAt(t *testing.T, path, tok, iss string) error {
	t.Helper()
	var body []byte
	if strings.HasPrefix(path, "/acme/") {
		// The router caches responses per path across the process; the key set is read
		// as the handler builds it.
		b, _, err := publishTenant(context.Background(), tn.db, "acme")
		if err != nil {
			t.Fatalf("publish: %v", err)
		}
		body = b
	} else {
		var st int
		st, body = tn.get(t, "hanzo.id", path)
		if st != 200 {
			t.Fatalf("GET %s = %d", path, st)
		}
	}
	var set struct{ Keys []map[string]any }
	if err := json.Unmarshal(body, &set); err != nil {
		t.Fatal(err)
	}
	_, err := jwt.Parse(tok, func(j *jwt.Token) (any, error) {
		kid, _ := j.Header["kid"].(string)
		for _, k := range set.Keys {
			if k["kid"] == kid {
				return keyOf(t, k), nil
			}
		}
		return nil, jwt.ErrTokenUnverifiable
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithIssuer(iss), jwt.WithTimeFunc(nowFunc))
	return err
}

func claimsOf(t *testing.T, tok string) (jwt.MapClaims, map[string]any) {
	t.Helper()
	c := jwt.MapClaims{}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, c)
	if err != nil {
		t.Fatal(err)
	}
	return c, parsed.Header
}

// THE END-TO-END: sign in, and the token is the organization's. Its issuer is the
// organization's, its kid is the tenant cert's, its audience stays the client id, and it
// verifies against the organization's key set and against nothing the platform serves.
func TestTenant_SignsUnderTheOrgsOwnIssuerAndVerifiesOnlyAtItsOwnKeys(t *testing.T) {
	tn := newTenant(t)
	tok := tn.signIn(t)
	access, id := tok["access_token"].(string), tok["id_token"].(string)
	for name, raw := range map[string]string{"access_token": access, "id_token": id} {
		c, h := claimsOf(t, raw)
		if c["iss"] != "https://hanzo.ai/acme" || c["owner"] != "acme" || h["kid"] != "acme-signing" {
			t.Fatalf("%s: iss=%v owner=%v kid=%v", name, c["iss"], c["owner"], h["kid"])
		}
		if aud, _ := c["aud"].(string); aud != tenantClient {
			if l, _ := c["aud"].([]any); len(l) != 1 || l[0] != tenantClient {
				t.Fatalf("%s: aud=%v, want the client id", name, c["aud"])
			}
		}
		// Verifies at the organization's key set, under the organization's issuer.
		if err := tn.verifyAt(t, "/acme"+PathJWKSRoot, raw, "https://hanzo.ai/acme"); err != nil {
			t.Fatalf("%s does not verify at the org's key set: %v", name, err)
		}
		// And at neither platform key set, nor under a platform issuer.
		for _, p := range []string{PathJWKS, PathJWKSRoot} {
			if err := tn.verifyAt(t, p, raw, "https://hanzo.ai/acme"); err == nil {
				t.Fatalf("%s verified at the platform key set %s", name, p)
			}
		}
	}
	ctx := context.Background()
	for what, err := range map[string]error{
		"parseToken":   second(parseToken(ctx, tn.db, access)),
		"verifyBearer": second(verifyBearer(ctx, tn.db, access)),
		"VerifyToken":  second(VerifyToken(ctx, tn.db, access)),
		"verifyToken":  second(verifyToken(ctx, tn.db, access)),
	} {
		if err == nil {
			t.Fatalf("%s, the platform-authority verification, accepted a tenant token", what)
		}
	}
	// The organization's own paths do.
	if c, err := verifyIssuedBearer(ctx, tn.db, access); err != nil || c.Owner != "acme" {
		t.Fatalf("verifyIssuedBearer: %v", err)
	}
}

func second[T any](_ T, err error) error { return err }

// userinfo and introspection are what a tenant's relying party calls: both answer for its
// token, under its issuer; revocation, which keys on the row, retires it.
func TestTenant_UserinfoAndIntrospectionServeTheOrgsToken(t *testing.T) {
	tn := newTenant(t)
	tok := tn.signIn(t)
	access := tok["access_token"].(string)

	req := formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, body := do(t, tn.app, req)
	if resp.StatusCode != 200 {
		t.Fatalf("userinfo: %d %s", resp.StatusCode, body)
	}
	if m := decode(t, body); m["iss"] != "https://hanzo.ai/acme" || m["owner"] != "acme" {
		t.Fatalf("userinfo = %v", m)
	}

	resp, body = do(t, tn.app, formReq("POST", PathIntrospect, url.Values{
		"token": {access}, "client_id": {tenantClient}, "client_secret": {"s3cret"},
	}))
	if m := decode(t, body); resp.StatusCode != 200 || m["active"] != true || m["iss"] != "https://hanzo.ai/acme" {
		t.Fatalf("introspect: %d %v", resp.StatusCode, m)
	}

	if resp, _ = do(t, tn.app, formReq("POST", PathRevoke, url.Values{
		"token": {access}, "client_id": {tenantClient}, "client_secret": {"s3cret"},
	})); resp.StatusCode != 200 {
		t.Fatalf("revoke: %d", resp.StatusCode)
	}
	req = formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+access)
	if resp, _ = do(t, tn.app, req); resp.StatusCode != 401 {
		t.Fatalf("a revoked tenant token still answers userinfo: %d", resp.StatusCode)
	}
}

// The refresh grant signs again with the same cert, under the same issuer.
func TestTenant_RefreshSignsUnderTheSameIssuer(t *testing.T) {
	tn := newTenant(t)
	tn.appRow.RefreshExpireInHours = 24
	tn.appRow.GrantTypes = []string{"authorization_code", "refresh_token"}
	if err := tn.appRow.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	tok := tn.signIn(t)
	refresh, _ := tok["refresh_token"].(string)
	if refresh == "" {
		t.Skip("this application mints no refresh token")
	}
	resp, out := postToken(t, tn.app, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh}, "client_id": {tenantClient}, "client_secret": {"s3cret"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("refresh: %d %v", resp.StatusCode, out)
	}
	if c, h := claimsOf(t, out["access_token"].(string)); c["iss"] != "https://hanzo.ai/acme" || h["kid"] != "acme-signing" {
		t.Fatalf("refreshed token: iss=%v kid=%v", c["iss"], h["kid"])
	}
}

// DISCOVERY AND THE KEY SET live under the issuer, and 404 for anything that is not an
// organization holding a published tenant cert: never a platform document.
func TestTenant_DiscoveryAndKeySetUnderTheIssuer(t *testing.T) {
	tn := newTenant(t)
	st, body := tn.get(t, "hanzo.ai", "/acme/.well-known/openid-configuration")
	if st != 200 {
		t.Fatalf("discovery: %d %s", st, body)
	}
	d := decode(t, body)
	if d["issuer"] != "https://hanzo.ai/acme" || d["jwks_uri"] != "https://hanzo.ai/acme/.well-known/jwks" ||
		d["token_endpoint"] != "https://hanzo.id/v1/iam/oauth/token" || d["authorization_endpoint"] != "https://hanzo.id/v1/iam/oauth/authorize" {
		t.Fatalf("discovery = %v", d)
	}
	if _, ok := d["registration_endpoint"]; ok {
		t.Fatal("an organization's discovery advertises the platform's registration endpoint")
	}
	st, body = tn.get(t, "hanzo.ai", "/acme/.well-known/jwks")
	if st != 200 || strings.Contains(string(body), "cert-") || !strings.Contains(string(body), `"kid":"acme-signing"`) {
		t.Fatalf("key set: %d %s", st, body)
	}
	for _, leak := range []string{"PRIVATE", `"d"`, `"p"`, `"q"`, `"dp"`, `"dq"`, `"qi"`} {
		if strings.Contains(string(body), leak) {
			t.Fatalf("the org key set carries %s", leak)
		}
	}

	// An org row with no tenant cert, an unknown org, and names that can hold no issuer.
	o := orm.New[schema.Organization](tn.db)
	o.Owner, o.Name = "admin", "beta"
	o.SetId("admin/beta")
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{"beta", "nobody", "hanzo", "admin", "built-in", "lux", "zoo", "app", "platform", "v1", "Acme", "a"} {
		for _, p := range []string{"/.well-known/openid-configuration", "/.well-known/jwks"} {
			if st, body := tn.get(t, "hanzo.ai", "/"+org+p); st != 404 || strings.Contains(string(body), "issuer") || strings.Contains(string(body), "keys") {
				t.Fatalf("/%s%s = %d %s, want a bare 404", org, p, st, body)
			}
		}
	}
	// The platform documents are unchanged by it.
	st, body = tn.get(t, "hanzo.id", "/.well-known/openid-configuration")
	if d := decode(t, body); st != 200 || d["issuer"] != "https://hanzo.id" || d["jwks_uri"] != "https://hanzo.id"+PathJWKS {
		t.Fatalf("platform discovery = %d %v", st, d)
	}
}

// THE PLATFORM KEY SET NEVER LISTS A TENANT CERT, whatever its row says: not one with a
// certificate set, not one under a reserved owner, not one named like a platform kid.
func TestTenant_PlatformKeySetNeverListsATenantCert(t *testing.T) {
	tn := newTenant(t)
	seedRSACert(t, tn.db, "cert-hanzo")
	own, err := orm.Get[schema.Cert](tn.db, "acme/acme-signing")
	if err != nil {
		t.Fatal(err)
	}
	// The same cert refiled under a reserved owner, and one named like a platform kid.
	for _, c := range []*schema.Cert{
		{Owner: "admin", Name: "shadow", Scope: schema.CertTenant, CryptoAlgorithm: "RS256", Certificate: own.Certificate},
		{Owner: "built-in", Name: "shadow2", Scope: schema.CertTenant, CryptoAlgorithm: "RS256", Certificate: own.Certificate},
		{Owner: "acme", Name: "cert-hanzo", Scope: schema.CertTenant, CryptoAlgorithm: "RS256", Certificate: own.Certificate},
	} {
		row := orm.New[schema.Cert](tn.db)
		model := row.Model
		*row = *c
		row.Model = model
		row.SetId(c.Owner + "/" + c.Name)
		if err := row.CreateCtx(context.Background()); err != nil {
			t.Fatal(err)
		}
		if Publishes(row) {
			t.Fatalf("Publishes(%s/%s) = true for a tenant cert", c.Owner, c.Name)
		}
	}
	st, body := tn.get(t, "hanzo.id", PathJWKS)
	var set struct{ Keys []map[string]any }
	if err := json.Unmarshal(body, &set); err != nil || st != 200 {
		t.Fatalf("platform key set: %d %s", st, body)
	}
	for _, k := range set.Keys {
		if k["kid"] == "acme-signing" || k["kid"] == "shadow" || k["kid"] == "shadow2" {
			t.Fatalf("platform key set lists a tenant cert: %v", k["kid"])
		}
		if k["kid"] == "cert-hanzo" {
			// the platform's own, whose key is the shared test key, not the tenant's
			if keyOf(t, k).N.Cmp(sharedKey(t).N) != 0 {
				t.Fatal("the platform kid cert-hanzo is not the platform's key")
			}
		}
	}
	// A tenant cert named like a platform kid is no key of the org's either.
	if _, body := tn.get(t, "hanzo.ai", "/acme/.well-known/jwks"); strings.Contains(string(body), `"cert-hanzo"`) {
		t.Fatalf("the org key set lists a cert named like a platform kid: %s", body)
	}
	if _, body := tn.get(t, "hanzo.ai", "/acme/.well-known/jwks"); !strings.Contains(string(body), `"acme-signing"`) {
		t.Fatal("the org's own cert left its key set")
	}
}

// KID COLLISION. A platform cert that takes a tenant cert's name later does not make the
// application sign under the platform key, and neither key verifies the other's tokens.
func TestTenant_KidCollisionRefusesAndCrossVerifies(t *testing.T) {
	tn := newTenant(t)
	before := tn.signIn(t)["access_token"].(string)

	seedRSACert(t, tn.db, "acme-signing") // SuperAdmin files a platform cert with the tenant cert's name

	// The application is refused, not moved onto the platform's key.
	code, _, _ := loginForCode(t, tn.app, map[string]string{
		"organization": "acme", "username": "alice", "password": "pw",
		"clientId": tenantClient, "redirectUri": testRedirect, "scope": "openid", "nonce": "n2",
	})
	resp, out := exchangeCode(t, tn.app, url.Values{
		"code": {code}, "client_id": {tenantClient}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	requireError(t, resp, out, 500, "server_error")
	if d, _ := out["error_description"].(string); !strings.Contains(d, "a platform signing cert now holds") {
		t.Fatalf("error_description = %q", d)
	}
	if _, ok := out["access_token"]; ok {
		t.Fatal("a token was issued for a tenant cert whose name a platform cert holds")
	}

	// A token the tenant cert signed earlier is no longer the org's key's to vouch for,
	// and the platform's key under the same kid does not vouch for it either.
	ctx := context.Background()
	if _, err := parseIssued(ctx, tn.db, before); err == nil {
		t.Fatal("a tenant token verified although its kid is now a platform kid")
	}
	if _, err := parseToken(ctx, tn.db, before); err == nil {
		t.Fatal("a tenant token verified at the platform path under a colliding kid")
	}
	// A token the PLATFORM key signs under that kid, claiming the org's issuer, is refused.
	sg, err := NewRSASignerFromCert(&schema.Cert{Name: "acme-signing", PrivateKey: rsaKeyToPEM(t, sharedKey(t))}, "https://hanzo.ai/acme")
	if err != nil {
		t.Fatal(err)
	}
	forged, err := sg.SignUserToken(Identity{Id: "x"}, "acme", tenantClient, tenantClient, "", time.Hour, nowFunc())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := parseIssued(ctx, tn.db, forged); err == nil {
		t.Fatal("a platform-signed token claiming an organization's issuer verified")
	}
}

// A CERT OF ANOTHER ORG never signs, and nor does a missing vault key.
func TestTenant_CrossOrgAndMissingKeyRefuse(t *testing.T) {
	tn := newTenant(t)
	o := orm.New[schema.Organization](tn.db)
	o.Owner, o.Name = "admin", "beta"
	o.SetId("admin/beta")
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	// beta's application names acme's cert by name.
	b := orm.New[schema.Application](tn.db)
	b.Owner, b.Name, b.Organization, b.ClientId, b.Cert = "beta", "portal", "beta", "beta-portal", "acme-signing"
	b.SetId("beta/portal")
	if err := b.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := signerFor(context.Background(), tn.db, b, "https://hanzo.id", origin{}); err == nil {
		t.Fatal("an application signed with another organization's cert")
	}

	// The vault loses the key: fail closed, naming the registration and never a key.
	_ = tn.vault.Delete(context.Background(), "acme", "acme-signing")
	keyring.UseVault(tn.vault) // drops the key cache
	_, err := signerFor(context.Background(), tn.db, tn.appRow, "https://hanzo.id", origin{})
	if err == nil || !strings.Contains(err.Error(), "acme/portal") || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("a missing key: %v", err)
	}
	// No vault at all is the same refusal.
	keyring.UseVault(nil)
	if _, err := signerFor(context.Background(), tn.db, tn.appRow, "https://hanzo.id", origin{}); err == nil {
		t.Fatal("signed with no vault installed")
	}
}

// NO FALLBACK. An application naming no tenant cert is refused as it was, and the
// refusal now names the tenant-cert fix; a reserved owner's, spanning or platform
// application never takes the tenant path.
func TestTenant_NoFallbackAndIneligibleApplications(t *testing.T) {
	tn := newTenant(t)
	ctx := context.Background()
	for name, mod := range map[string]func(*schema.Application){
		"names none":          func(a *schema.Application) { a.Cert = "" },
		"names a missing one": func(a *schema.Application) { a.Cert = "acme-other" },
		"platform":            func(a *schema.Application) { a.Platform = true },
		"shared":              func(a *schema.Application) { a.IsShared = true },
		"org choice":          func(a *schema.Application) { a.OrgChoiceMode = "create" },
		"owner differs":       func(a *schema.Application) { a.Organization = "beta" },
	} {
		a := *tn.appRow
		mod(&a)
		s, err := signerFor(ctx, tn.db, &a, "https://hanzo.id", origin{})
		if err == nil || s != nil {
			t.Fatalf("%s: signed under a tenant cert (%v)", name, err)
		}
	}
	a := *tn.appRow
	a.Cert = ""
	_, err := signerFor(ctx, tn.db, &a, "https://hanzo.id", origin{})
	if d := err.Error(); !strings.Contains(d, `scope \"tenant\"`) && !strings.Contains(d, `scope "tenant"`) {
		t.Fatalf("the refusal does not name the tenant-cert fix: %v", err)
	}
	// A reserved owner's application keeps the platform resolution untouched.
	if tenantApp(&schema.Application{Owner: "admin", Organization: "admin", Cert: "acme-signing"}) ||
		tenantApp(&schema.Application{Owner: "hanzo", Organization: "hanzo"}) {
		t.Fatal("a platform org's application is tenant-eligible")
	}
}

// THE ISSUER IS THE ORG'S AND NEVER READS AS A PLATFORM ONE.
func TestTenantIssuer_ShapeAndConfusion(t *testing.T) {
	for _, org := range []string{"hanzo", "lux", "zoo", "pars", "admin", "built-in", "app", "platform", "hanzo-id", "lux-id", "hanzoai", "adnexus", "v1", "login", "healthz", "pricing", "download", "signup", "about", "api", "images", "Acme", "a", "", "a/b", "a.b", "-ab", "x y"} {
		if iss, err := tenantIssuer(org); err == nil {
			t.Errorf("tenantIssuer(%q) = %q, want a refusal", org, iss)
		}
	}
	if iss, err := tenantIssuer("acme"); err != nil || iss != "https://hanzo.ai/acme" {
		t.Fatalf("tenantIssuer = %q %v", iss, err)
	}
	for iss, want := range map[string]string{
		"https://hanzo.ai/acme":  "acme",
		"https://hanzo.ai/acme/": "acme",
	} {
		if org, ok := tenantOrgOf(iss); !ok || org != want {
			t.Errorf("tenantOrgOf(%q) = %q %v", iss, org, ok)
		}
	}
	for _, iss := range []string{
		"https://hanzo.id/acme", "https://hanzo.id", "https://hanzo.ai", "https://hanzo.ai/", "https://hanzo.ai/hanzo", "https://hanzo.ai/admin",
		"https://hanzo.ai/built-in", "https://hanzo.ai/pricing", "https://hanzo.ai/acme/x", "https://hanzo.ai/acme?x=1", "https://evil.example/acme",
		"http://hanzo.ai/acme", "https://hanzo.ai.evil.example/acme", "https://xhanzo.ai/acme", "https://hanzo.ai//acme", "https://hanzo.ai/v1", "",
	} {
		if org, ok := tenantOrgOf(iss); ok {
			t.Errorf("tenantOrgOf(%q) = %q, want none", iss, org)
		}
	}
	// A tenant issuer is no platform issuer, and no platform issuer is a tenant's.
	if issues("https://hanzo.ai/acme") || issues("https://hanzo.ai") || !issues("https://hanzo.id") {
		t.Fatal("issues() confuses a tenant issuer with the platform's")
	}
}

// With no tenant origin configured nothing derives an issuer: tenant certs do not sign and
// the org paths answer 404, naming the knob to the operator. The origin itself is pinned.
func TestTenantIssuer_UnsetFailsClosedAndIsValidated(t *testing.T) {
	tn := newTenant(t)
	withTenantBase(t, "")
	if _, err := tenantIssuer("acme"); !errors.Is(err, errNoTenantIssuer) {
		t.Fatalf("tenantIssuer with no origin: %v", err)
	}
	_, err := signerFor(context.Background(), tn.db, tn.appRow, "https://hanzo.id", origin{})
	if err == nil || !strings.Contains(err.Error(), EnvTenantIssuer) {
		t.Fatalf("an unset origin must say so: %v", err)
	}
	if _, ok := tenantOrgOf("https://hanzo.ai/acme"); ok {
		t.Fatal("a tenant issuer was recognised with none configured")
	}
	for _, host := range []string{"hanzo.ai", "hanzo.id"} {
		if st, _ := tn.get(t, host, "/acme/.well-known/jwks"); st != 404 {
			t.Fatalf("%s answered an org key set with no tenant origin: %d", host, st)
		}
	}
	for _, bad := range []string{"http://hanzo.ai", "hanzo.ai", "https://hanzo.ai/path", "https://user@hanzo.ai", "https://hanzo.ai?x=1", "https://127.0.0.1"} {
		if _, err := newTenantBase(bad); err == nil {
			t.Errorf("newTenantBase(%q) accepted", bad)
		}
	}
	if o, err := newTenantBase(" https://Hanzo.AI/ "); err != nil || o != "https://hanzo.ai" {
		t.Fatalf("newTenantBase = %q %v", o, err)
	}
}

// Only the host the issuer lives on answers for it.
func TestTenant_OnlyTheTenantHostAnswers(t *testing.T) {
	tn := newTenant(t)
	for _, p := range []string{"/acme/.well-known/openid-configuration", "/acme/.well-known/jwks"} {
		if st, _ := tn.get(t, "hanzo.id", p); st != 404 {
			t.Fatalf("hanzo.id answered %s: %d", p, st)
		}
		if st, _ := tn.get(t, "hanzo.ai", p); st != 200 {
			t.Fatalf("hanzo.ai did not answer %s: %d", p, st)
		}
	}
}

// withTenantBase installs a tenant origin for one test.
func withTenantBase(t *testing.T, origin string) {
	t.Helper()
	prev := tenantBase()
	activeTenantBase.Store(&origin)
	t.Cleanup(func() { activeTenantBase.Store(&prev) })
}

// A reserved slug is never founded by self-service: signup's derivation walks past it, onboard
// and provision refuse it.
func TestReservedSlugsAreNeverFoundedBySelfService(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	shaped := 0
	for _, n := range schema.ReservedSlugs() {
		if schema.OrgName(n) != nil {
			continue
		}
		shaped++
		if free, err := orgSlugFree(ctx, db, n); err != nil || free {
			t.Errorf("orgSlugFree(%q) = %v %v", n, free, err)
		}
		if _, err := provision(ctx, db, claim{owner: "admin", name: "someone", slug: n, display: n}); err == nil {
			t.Errorf("provision founded the reserved slug %q", n)
		}
	}
	if shaped < 150 {
		t.Fatalf("only %d shaped slugs", shaped)
	}
}

// A tenant token is refused at the RFC 8693 exchange, which mints platform tokens from one.
func TestTenant_TokenExchangeRefusesATenantSubject(t *testing.T) {
	tn := newTenant(t)
	access := tn.signIn(t)["access_token"].(string)
	seedApp(t, tn.db, appOpts{clientID: "xchg", secret: "x", grants: []string{"urn:ietf:params:oauth:grant-type:token-exchange"}})
	resp, out := postToken(t, tn.app, url.Values{
		"grant_type": {"urn:ietf:params:oauth:grant-type:token-exchange"}, "client_id": {"xchg"}, "client_secret": {"x"},
		"subject_token": {access}, "subject_token_type": {"urn:ietf:params:oauth:token-type:access_token"},
	})
	if resp.StatusCode == 200 {
		t.Fatalf("a tenant token was exchanged for another token: %v", out)
	}
}

// An org that deletes its last cert stops publishing at once, and its next cert is served at once.
func TestTenant_KeySetFollowsTheOrgsCerts(t *testing.T) {
	tn := newTenant(t)
	if st, _ := tn.get(t, "hanzo.ai", "/acme/.well-known/jwks"); st != 200 {
		t.Fatalf("key set: %d", st)
	}
	row, err := orm.Get[schema.Cert](tn.db, "acme/acme-signing")
	if err != nil {
		t.Fatal(err)
	}
	if err := row.DeleteCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Within the cache window the last set may stand; the held set lapses, and the
	// next read replaces it with nothing.
	tenantSets.Lock()
	held := tenantSets.m["acme"]
	tenantSets.Unlock()
	held.mu.Lock()
	held.at = time.Now().Add(-2 * jwksTTL)
	held.mu.Unlock()
	if st, _ := tn.get(t, "hanzo.ai", "/acme/.well-known/jwks"); st != 404 {
		t.Fatalf("an org with no cert still publishes: %d", st)
	}
	tn.createCert(t, "acme", "acme-next", http.StatusOK)
	if st, body := tn.get(t, "hanzo.ai", "/acme/.well-known/jwks"); st != 200 || !strings.Contains(string(body), "acme-next") {
		t.Fatalf("the next cert is not served: %d %s", st, body)
	}
}

// A cert deleted and created again under the same name, while this replica still holds the
// old key, signs with the new key: tokens verify at the org's current key set.
func TestTenant_RecreatedCertNeverReusesACachedKey(t *testing.T) {
	tn := newTenant(t)
	first := tn.signIn(t)["access_token"].(string) // caches the key
	if err := tn.verifyAt(t, "/acme"+PathJWKSRoot, first, "https://hanzo.ai/acme"); err != nil {
		t.Fatal(err)
	}
	// Another replica deletes the cert and its key; this one is not told.
	row, err := orm.Get[schema.Cert](tn.db, "acme/acme-signing")
	if err != nil {
		t.Fatal(err)
	}
	if err := row.DeleteCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	_ = tn.vault.Delete(context.Background(), "acme", "acme-signing")
	tn.createCert(t, "acme", "acme-signing", http.StatusOK)
	dropTenantSet("acme")
	if rows, _ := store.ListTenantCerts(context.Background(), tn.db, "acme"); len(rows) != 1 {
		t.Fatalf("the org holds %d tenant cert rows after the recreate", len(rows))
	}
	second := tn.signIn(t)["access_token"].(string)
	if err := tn.verifyAt(t, "/acme"+PathJWKSRoot, second, "https://hanzo.ai/acme"); err != nil {
		t.Fatalf("a token signed after the cert was recreated does not verify at its key set: %v", err)
	}
	if err := tn.verifyAt(t, "/acme"+PathJWKSRoot, first, "https://hanzo.ai/acme"); err == nil {
		t.Fatal("a token of the deleted cert verifies under the recreated one")
	}
}

// The oldest key set is dropped when the cache is full; the others stay.
func TestTenantSetsEvictTheOldest(t *testing.T) {
	tenantSets.Lock()
	tenantSets.m, tenantSets.order = map[string]*keySet{}, nil
	tenantSets.Unlock()
	t.Cleanup(func() {
		tenantSets.Lock()
		tenantSets.m, tenantSets.order = map[string]*keySet{}, nil
		tenantSets.Unlock()
	})
	first := tenantSetOf("org-0")
	keep := tenantSetOf("org-1")
	for i := 2; i <= tenantSetMax; i++ {
		tenantSetOf("org-" + strconv.Itoa(i))
	}
	if tenantSetOf("org-1") != keep {
		t.Fatal("a recent key set was dropped when the cache filled")
	}
	if tenantSetOf("org-0") == first {
		t.Fatal("the oldest key set was kept")
	}
	if len(tenantSets.m) > tenantSetMax {
		t.Fatalf("the cache holds %d sets", len(tenantSets.m))
	}
}

// An application that is no tenant application never signs with a platform cert that merely
// shares a name with a tenant cert row of its org; neither does a platform cert created later.
func TestTenant_ATenantRowNeverFallsThroughToAPlatformCert(t *testing.T) {
	tn := newTenant(t)
	seedRSACert(t, tn.db, "acme-signing") // a platform cert under the tenant cert's name
	for name, mod := range map[string]func(*schema.Application){
		"shared":    func(a *schema.Application) { a.IsShared = true },
		"platform":  func(a *schema.Application) { a.Platform = true },
		"spans":     func(a *schema.Application) { a.OrgChoiceMode = "create" },
		"other org": func(a *schema.Application) { a.Organization = "beta" },
	} {
		a := *tn.appRow
		mod(&a)
		if s, err := signerFor(context.Background(), tn.db, &a, "https://hanzo.id", origin{}); s != nil || err == nil {
			t.Errorf("%s: signed under a platform cert named like the tenant's (%v)", name, err)
		}
	}
}

// A tenant origin that holds a platform issuer is refused at boot; one that IS a platform
// issuer is allowed, since an organization's issuer always has an org after the origin.
func TestTenantOrigin_NeverOverlapsAPlatformIssuer(t *testing.T) {
	prevIss, prevMap, prevTen := os.Getenv("IAM_ISSUER"), os.Getenv("IAM_ISSUER_MAP"), os.Getenv(EnvTenantIssuer)
	t.Cleanup(func() {
		os.Setenv("IAM_ISSUER", prevIss)
		os.Setenv(EnvTenantIssuer, prevTen)
		if prevMap == "" {
			os.Unsetenv("IAM_ISSUER_MAP")
		} else {
			os.Setenv("IAM_ISSUER_MAP", prevMap)
		}
		if err := InitIssuerResolver(); err != nil {
			t.Fatal(err)
		}
	})
	for name, c := range map[string]struct{ iss, m, tenant string }{
		"default lies under it":        {"https://hanzo.ai/x", "", "https://hanzo.ai"},
		"a brand issuer lies under it": {"https://hanzo.id", `{"lux.id":"https://hanzo.ai/lux"}`, "https://hanzo.ai"},
	} {
		os.Setenv("IAM_ISSUER", c.iss)
		os.Setenv(EnvTenantIssuer, c.tenant)
		if c.m == "" {
			os.Unsetenv("IAM_ISSUER_MAP")
		} else {
			os.Setenv("IAM_ISSUER_MAP", c.m)
		}
		if err := InitIssuerResolver(); err == nil {
			t.Errorf("%s: booted", name)
		}
	}
	os.Setenv("IAM_ISSUER", "https://hanzo.id")
	os.Unsetenv("IAM_ISSUER_MAP")
	os.Setenv(EnvTenantIssuer, "https://hanzo.ai")
	if err := InitIssuerResolver(); err != nil {
		t.Fatalf("disjoint origins refused: %v", err)
	}
}
