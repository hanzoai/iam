// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package compat_test

// End-to-end tests for the Casdoor verb aliases, driven through the REAL mounted
// router (routes.Mount installs the authz Guard first, then compat.Mount). Every
// case is a wire request a live console/gateway client sends. The assertions are
// the three contracts a backend swap depends on: the v1 {status,data,data2}
// envelope shape, owner-scoping that no request parameter can widen, and — the
// security one — that NO secret material ever appears in a response body.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/routes"
	"github.com/hanzoai/iam2/internal/schema"
)

const signingKid = "cert-hanzo"

// Distinctive secret sentinels: if any of these strings appears in ANY response
// body, redaction failed and a real credential leaked.
const (
	secretUserHash   = "$argon2id$SENTINEL_USER_PW_HASH"
	secretOrgMaster  = "SENTINEL_ORG_MASTER_PW"
	secretAppClient  = "SENTINEL_APP_CLIENT_SECRET"
	secretProvClient = "SENTINEL_PROVIDER_CLIENT_SECRET"
)

type harness struct {
	app *zip.App
	key *rsa.PrivateKey
	db  orm.DB
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	_ = schema.Kinds()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "compat.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Trust anchor (admin-owned RS256 signing cert = JWKS kid).
	seedCert(t, db, "admin", signingKid, pemOf(t, key))

	// Principals across two orgs: a SuperAdmin, an org-admin, a regular user.
	seedUser(t, db, "admin", "root", true)   // SuperAdmin (org == admin)
	seedUser(t, db, "hanzo", "boss", true)   // org-admin of hanzo
	seedUser(t, db, "hanzo", "alice", false) // regular user in hanzo
	seedUser(t, db, "orgb", "bob", true)     // org-admin of a second tenant

	// Secret-bearing rows: every one carries a sentinel that must never surface.
	// users already seeded carry a password hash sentinel (set in seedUser).
	seedOrg(t, db, "hanzo")             // Owner="admin", Name="hanzo", MasterPassword sentinel
	seedApp(t, db, "hanzo-console")     // Owner="admin", ClientSecret sentinel
	seedProvider(t, db, "provider-gh")  // Owner="admin", ClientSecret sentinel

	app := zip.New(zip.Config{AppName: "compat-test", DisableStartupMessage: true})
	routes.Mount(app, db)
	app.Prepare()
	return &harness{app: app, key: key, db: db}
}

func (h *harness) token(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = signingKid
	s, err := tok.SignedString(h.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// get issues a GET through the real router and returns (status, rawBody).
func (h *harness) get(t *testing.T, path, bearer string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := h.app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// envelope is the v1 Response shape the clients parse.
type envelope struct {
	Status string            `json:"status"`
	Msg    string            `json:"msg"`
	Data   []json.RawMessage `json:"data"`
	Data2  json.RawMessage   `json:"data2"`
}

// ---- assertions ------------------------------------------------------------

func TestGetUsers_super_envelopeAndNoSecretLeak(t *testing.T) {
	h := newHarness(t)
	status, body := h.get(t, "/v1/iam/get-users", h.token(t, "admin/root"))
	if status != 200 {
		t.Fatalf("status = %d, want 200; body=%s", status, body)
	}
	assertNoSecretLeak(t, body)

	var env envelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("body is not the v1 envelope: %v; body=%s", err, body)
	}
	if env.Status != "ok" {
		t.Fatalf("status field = %q, want ok", env.Status)
	}
	// SuperAdmin, no owner filter → every user across every org (4 seeded).
	if len(env.Data) != 4 {
		t.Fatalf("super get-users returned %d users, want 4", len(env.Data))
	}
}

func TestGetUsers_paged_data2IsTotal(t *testing.T) {
	h := newHarness(t)
	_, body := h.get(t, "/v1/iam/get-users?p=1&pageSize=2", h.token(t, "admin/root"))
	assertNoSecretLeak(t, body)

	var env envelope
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("not the v1 envelope: %v", err)
	}
	if len(env.Data) != 2 {
		t.Fatalf("page 1 pageSize 2 returned %d rows, want 2", len(env.Data))
	}
	// data2 carries the FULL owner-scoped total (4), not the page length.
	var total int
	if err := json.Unmarshal(env.Data2, &total); err != nil {
		t.Fatalf("data2 is not an int total: %v (data2=%s)", err, env.Data2)
	}
	if total != 4 {
		t.Fatalf("data2 total = %d, want 4", total)
	}
}

func TestGetUsers_unpaged_hasNoData2(t *testing.T) {
	h := newHarness(t)
	_, body := h.get(t, "/v1/iam/get-users", h.token(t, "admin/root"))
	// v1 omits data2 entirely when the list is not paginated.
	if strings.Contains(body, "\"data2\"") {
		t.Fatalf("unpaged list must omit data2; body=%s", body)
	}
}

func TestGetOrganizations_super_listsAll_masked(t *testing.T) {
	h := newHarness(t)
	status, body := h.get(t, "/v1/iam/get-organizations", h.token(t, "admin/root"))
	if status != 200 {
		t.Fatalf("status = %d; body=%s", status, body)
	}
	assertNoSecretLeak(t, body)
	// The masked org keeps its "***" sentinel, proving Mask ran (not the raw pw).
	if !strings.Contains(body, "***") {
		t.Fatalf("expected the masked '***' marker in the org list; body=%s", body)
	}
}

func TestGetApplications_super_noClientSecret(t *testing.T) {
	h := newHarness(t)
	status, body := h.get(t, "/v1/iam/get-applications", h.token(t, "admin/root"))
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	assertNoSecretLeak(t, body)
}

func TestGetProviders_super_noClientSecret(t *testing.T) {
	h := newHarness(t)
	status, body := h.get(t, "/v1/iam/get-providers", h.token(t, "admin/root"))
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	assertNoSecretLeak(t, body)
}

func TestGetUser_byId_super(t *testing.T) {
	h := newHarness(t)
	// The Casdoor `?id=<owner>/<name>` shape — resolved by authz.ReadTarget.
	status, body := h.get(t, "/v1/iam/get-user?id=hanzo/alice", h.token(t, "admin/root"))
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	assertNoSecretLeak(t, body)
	if !strings.Contains(body, "alice") {
		t.Fatalf("get-user?id=hanzo/alice did not return alice; body=%s", body)
	}
}

func TestGetUsers_orgAdmin_scopedToOwnOrg(t *testing.T) {
	h := newHarness(t)
	// An org-admin MUST pass its own owner (the Guard denies an empty owner for a
	// non-super); it then sees only its org's users.
	status, body := h.get(t, "/v1/iam/get-users?owner=hanzo", h.token(t, "hanzo/boss"))
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var env envelope
	_ = json.Unmarshal([]byte(body), &env)
	if len(env.Data) != 2 { // hanzo/boss + hanzo/alice, never orgb/bob
		t.Fatalf("org-admin get-users?owner=hanzo returned %d, want 2 (own org only)", len(env.Data))
	}
	assertNoSecretLeak(t, body)
}

func TestGetUsers_orgAdmin_crossTenantDenied(t *testing.T) {
	h := newHarness(t)
	// hanzo's admin cannot list orgb's users — the Guard refuses a foreign owner.
	status, _ := h.get(t, "/v1/iam/get-users?owner=orgb", h.token(t, "hanzo/boss"))
	if status != 403 {
		t.Fatalf("cross-tenant get-users status = %d, want 403", status)
	}
}

func TestGetUser_byId_crossTenantDenied(t *testing.T) {
	h := newHarness(t)
	// The `?id=` fallback must not open a cross-tenant hole: hanzo's admin naming
	// orgb/bob is refused at the Guard, exactly as the ?owner= form is.
	status, _ := h.get(t, "/v1/iam/get-user?id=orgb/bob", h.token(t, "hanzo/boss"))
	if status != 403 {
		t.Fatalf("cross-tenant get-user?id=orgb/bob status = %d, want 403", status)
	}
}

func TestGetUsers_regularUser_cannotList(t *testing.T) {
	h := newHarness(t)
	// A non-admin user may not enumerate its org's users (the self-service rule is
	// a single-record read, never a list).
	status, _ := h.get(t, "/v1/iam/get-users?owner=hanzo", h.token(t, "hanzo/alice"))
	if status != 403 {
		t.Fatalf("regular-user get-users status = %d, want 403", status)
	}
}

func TestGetApplications_nonSuper_deniedOnPlatformOwned(t *testing.T) {
	h := newHarness(t)
	// Applications are platform-owned (Owner "admin"); a non-super gets a safe 403
	// at the Guard, never another tenant's app rows.
	status, _ := h.get(t, "/v1/iam/get-applications", h.token(t, "hanzo/boss"))
	if status != 403 {
		t.Fatalf("non-super get-applications status = %d, want 403", status)
	}
}

func TestCompatAliases_requireAuth(t *testing.T) {
	h := newHarness(t)
	// No bearer → the Guard fails closed (not in the public allowlist).
	if status, _ := h.get(t, "/v1/iam/get-users", ""); status != 401 {
		t.Fatalf("unauthenticated get-users status = %d, want 401", status)
	}
}

// assertNoSecretLeak fails if any seeded secret sentinel appears in the body —
// the single most important property of the whole layer.
func assertNoSecretLeak(t *testing.T, body string) {
	t.Helper()
	for _, secret := range []string{secretUserHash, secretOrgMaster, secretAppClient, secretProvClient} {
		if strings.Contains(body, secret) {
			t.Fatalf("SECRET LEAK: %q appeared in a response body:\n%s", secret, body)
		}
	}
}

// ---- seed helpers ----------------------------------------------------------

func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	c.CryptoAlgorithm = "RS256"
	c.PrivateKey = privPEM
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

func seedUser(t *testing.T, db orm.DB, owner, name string, admin bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.IsAdmin = admin
	u.PasswordHash = secretUserHash // the sentinel that must never surface
	u.PasswordType = "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func seedOrg(t *testing.T, db orm.DB, name string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", name // orgs are platform-owned
	o.MasterPassword = secretOrgMaster
	o.SetId("admin/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
}

func seedApp(t *testing.T, db orm.DB, name string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name = "admin", name
	a.Organization = "hanzo"
	a.ClientSecret = secretAppClient
	a.SetId("admin/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app: %v", err)
	}
}

func seedProvider(t *testing.T, db orm.DB, name string) {
	t.Helper()
	p := orm.New[schema.Provider](db)
	p.Owner, p.Name = "admin", name
	p.ClientSecret = secretProvClient
	p.SetId("admin/" + name)
	if err := p.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
}

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}
