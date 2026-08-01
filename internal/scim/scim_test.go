// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package scim_test

// SCIM 2.0 tests driven through the REAL registered router (routes.Route installs
// the authz Guard, then scim.Route). Every case is a HTTP request an IdP / SCIM
// client sends. The assertions pin the three contracts a provisioning surface
// depends on: the RFC-standard envelopes (ListResponse / a bare resource / Error),
// owner-scoping that no path can widen, and — the security one — that NO secret
// (password, hash) ever appears in a SCIM response.

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

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"

	"github.com/hanzoai/iam/internal/testhttp"
)

const (
	signingKid    = "cert-hanzo"
	secretUserPw  = "SENTINEL_PLAINTEXT_PASSWORD"
	secretUserHsh = "$argon2id$SENTINEL_USER_HASH"
	scimUsers     = "/v1/iam/scim/v2/Users"
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
		Path:   filepath.Join(dir, "scim.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, "admin", signingKid, pemOf(t, key))
	seedUser(t, db, "admin", "root", true)   // SuperAdmin (org == admin)
	seedUser(t, db, "hanzo", "boss", true)   // org-admin of hanzo
	seedUser(t, db, "hanzo", "alice", false) // regular user in hanzo
	seedUser(t, db, "orgb", "bob", true)     // org-admin of a second tenant

	app := zip.New(zip.Config{AppName: "scim-test", DisableStartupMessage: true})
	routes.Route(app, db)
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

// do issues a request through the real router and returns (status, rawBody).
func (h *harness) do(t *testing.T, method, path, bearer, body string) (int, string) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	if body != "" {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// assertNoSecretLeak fails if any credential sentinel appears in a response body.
func assertNoSecretLeak(t *testing.T, body string) {
	t.Helper()
	for _, s := range []string{secretUserPw, secretUserHsh, "passwordHash", "\"password\""} {
		if strings.Contains(body, s) {
			t.Fatalf("SECRET LEAK: %q in SCIM response:\n%s", s, body)
		}
	}
}

func TestSCIM_createGetDelete_lifecycle(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")

	// CREATE — a super provisions a user in the hanzo tenant (owner via extension).
	create := `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],
		"userName":"carol","displayName":"Carol",
		"emails":[{"value":"carol@hanzo.ai","primary":true}],
		"active":true,"password":"` + secretUserPw + `",
		"urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo"}}`
	status, body := h.do(t, "POST", scimUsers, super, create)
	if status != 201 {
		t.Fatalf("create status = %d; body=%s", status, body)
	}
	assertNoSecretLeak(t, body)
	var created scimUserResp
	if err := json.Unmarshal([]byte(body), &created); err != nil {
		t.Fatalf("create body not a SCIM user: %v", err)
	}
	if created.ID != "hanzo/carol" || created.UserName != "carol" {
		t.Fatalf("create id/userName = %q/%q, want hanzo/carol / carol", created.ID, created.UserName)
	}
	// The password WAS stored (login works) — verify at the store, not the response.
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "carol")
	if u == nil || u.PasswordHash == "" {
		t.Fatalf("created user has no stored password hash")
	}

	// GET by the returned id (two-segment path).
	status, body = h.do(t, "GET", scimUsers+"/hanzo/carol", super, "")
	if status != 200 {
		t.Fatalf("get status = %d; body=%s", status, body)
	}
	assertNoSecretLeak(t, body)

	// DELETE → 204, then GET → 404.
	if status, _ := h.do(t, "DELETE", scimUsers+"/hanzo/carol", super, ""); status != 204 {
		t.Fatalf("delete status = %d, want 204", status)
	}
	if status, _ := h.do(t, "GET", scimUsers+"/hanzo/carol", super, ""); status != 404 {
		t.Fatalf("get after delete status = %d, want 404", status)
	}
}

func TestSCIM_listOwnerScoped_and_Envelope(t *testing.T) {
	h := newHarness(t)

	// SuperAdmin lists every user across every tenant (4 seeded).
	status, body := h.do(t, "GET", scimUsers, h.token(t, "admin/root"), "")
	if status != 200 {
		t.Fatalf("super list status = %d; body=%s", status, body)
	}
	assertNoSecretLeak(t, body)
	var lr listResp
	if err := json.Unmarshal([]byte(body), &lr); err != nil {
		t.Fatalf("not a ListResponse: %v", err)
	}
	if len(lr.Schemas) == 0 || lr.Schemas[0] != "urn:ietf:params:scim:api:messages:2.0:ListResponse" {
		t.Fatalf("wrong ListResponse schema: %v", lr.Schemas)
	}
	if lr.TotalResults != 4 || len(lr.Resources) != 4 {
		t.Fatalf("super list total/resources = %d/%d, want 4/4", lr.TotalResults, len(lr.Resources))
	}

	// An org-admin lists ONLY its own org (2 hanzo users), never orgb's.
	status, body = h.do(t, "GET", scimUsers+"?owner=hanzo", h.token(t, "hanzo/boss"), "")
	if status != 200 {
		t.Fatalf("org-admin list status = %d; body=%s", status, body)
	}
	_ = json.Unmarshal([]byte(body), &lr)
	if lr.TotalResults != 2 {
		t.Fatalf("org-admin list total = %d, want 2 (own org only)", lr.TotalResults)
	}
}

func TestSCIM_filterByUserName(t *testing.T) {
	h := newHarness(t)
	status, body := h.do(t, "GET", scimUsers+`?owner=hanzo&filter=userName+eq+%22alice%22`, h.token(t, "hanzo/boss"), "")
	if status != 200 {
		t.Fatalf("filter status = %d; body=%s", status, body)
	}
	var lr listResp
	_ = json.Unmarshal([]byte(body), &lr)
	if lr.TotalResults != 1 {
		t.Fatalf("filter userName eq alice total = %d, want 1", lr.TotalResults)
	}
}

func TestSCIM_patchDeactivate(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"active","value":false}]}`
	status, body := h.do(t, "PATCH", scimUsers+"/hanzo/alice", super, patch)
	if status != 200 {
		t.Fatalf("patch status = %d; body=%s", status, body)
	}
	assertNoSecretLeak(t, body)
	u, _ := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if u == nil || !u.IsForbidden {
		t.Fatalf("patch active:false did not set IsForbidden (got %+v)", u)
	}
}

func TestSCIM_crossTenant_denied(t *testing.T) {
	h := newHarness(t)
	// hanzo's admin addressing an orgb user: authz.Scope refuses the foreign owner
	// outright, so the store is never consulted — neither for orgb/bob's data nor
	// for a same-named hanzo row to answer in its place.
	status, body := h.do(t, "GET", scimUsers+"/orgb/bob", h.token(t, "hanzo/boss"), "")
	if status != 403 {
		t.Fatalf("cross-tenant get status = %d, want 403 (foreign org refused); body=%s", status, body)
	}
	// Prove it's a SCIM Error, not a leaked user resource (no userName, no orgb
	// owner in a resource body).
	if !strings.Contains(body, "urn:ietf:params:scim:api:messages:2.0:Error") {
		t.Fatalf("cross-tenant get did not return a SCIM Error; body=%s", body)
	}
	if strings.Contains(body, "\"userName\"") || strings.Contains(body, "\"owner\":\"orgb\"") {
		t.Fatalf("cross-tenant get leaked an orgb user resource; body=%s", body)
	}
}

func TestSCIM_requiresAuth(t *testing.T) {
	h := newHarness(t)
	if status, _ := h.do(t, "GET", scimUsers, "", ""); status != 401 {
		t.Fatalf("unauthenticated SCIM list status = %d, want 401", status)
	}
}

func TestSCIM_serviceProviderConfig(t *testing.T) {
	h := newHarness(t)
	status, body := h.do(t, "GET", "/v1/iam/scim/v2/ServiceProviderConfig", h.token(t, "admin/root"), "")
	if status != 200 {
		t.Fatalf("SPConfig status = %d; body=%s", status, body)
	}
	if !strings.Contains(body, "\"patch\"") || !strings.Contains(body, "\"filter\"") {
		t.Fatalf("SPConfig missing capability advertisement; body=%s", body)
	}
}

// ---- minimal response shapes for assertions ----

type scimUserResp struct {
	Schemas  []string `json:"schemas"`
	ID       string   `json:"id"`
	UserName string   `json:"userName"`
	Active   bool     `json:"active"`
}

type listResp struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	Resources    []json.RawMessage `json:"Resources"`
}

// ---- seed helpers ----

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
	u.PasswordHash = secretUserHsh
	u.PasswordType = "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}
