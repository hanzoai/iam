// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package memberships_test

// The Casdoor membership VERB aliases (GAP A): get-memberships / add-membership /
// delete-membership, the spellings cloud's clients/team invite path hard-codes.
// Every case is a wire request driven through the REAL mounted router (routes.Route
// installs the authz Guard, then registers memberships after it), so the assertions
// prove the three things a backend swap depends on: the verbs reach the SAME store
// as the REST surface, the SAME tenant authz gates the REST surface uses, and a
// cross-tenant caller is refused with v1's verbatim message.

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

const signingKid = "cert-hanzo"

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
		Path:   filepath.Join(dir, "memberships.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, "admin", signingKid, pemOf(t, key))
	seedUser(t, db, "admin", "root", true) // SuperAdmin (org == admin)
	seedUser(t, db, "hanzo", "boss", true) // org-admin of hanzo
	seedUser(t, db, "orgb", "bob", true)   // org-admin of a second tenant

	app := zip.New(zip.Config{AppName: "memberships-test", DisableStartupMessage: true})
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

func (h *harness) get(t *testing.T, path, bearer string) (int, env) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return h.do(t, req)
}

func (h *harness) post(t *testing.T, path string, body any, bearer string) (int, env) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return h.do(t, req)
}

// do drives the request through the real mounted router and decodes the v1
// envelope. A raw 401 (the Guard's fail-closed refusal) has no envelope body; the
// caller asserts on the status alone.
func (h *harness) do(t *testing.T, req *http.Request) (int, env) {
	t.Helper()
	resp, err := h.app.Fiber().Test(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var e env
	_ = json.Unmarshal(body, &e)
	return resp.StatusCode, e
}

// env is the v1 Response envelope the clients parse.
type env struct {
	Status string          `json:"status"`
	Msg    string          `json:"msg"`
	Data   json.RawMessage `json:"data"`
	Data2  json.RawMessage `json:"data2"`
}

// ---- cases -----------------------------------------------------------------

// get-memberships?user=<owner/name> lists one identity's orgs (SuperAdmin path).
func TestGetMemberships_byUser(t *testing.T) {
	h := newHarness(t)
	seedMembership(t, h.db, "hanzo/alice", "hanzo", store.RoleMember)
	seedMembership(t, h.db, "hanzo/alice", "team-x", store.RoleAdmin)

	status, e := h.get(t, "/v1/iam/get-memberships?user=hanzo/alice", h.token(t, "admin/root"))
	if status != 200 || e.Status != "ok" {
		t.Fatalf("get-memberships?user status=%d env=%+v, want 200 ok", status, e)
	}
	rows := parseMemberships(t, e)
	if len(rows) != 2 {
		t.Fatalf("alice acts in %d orgs, want 2 (hanzo, team-x)", len(rows))
	}
}

// get-memberships?org=<slug> lists an org's roster.
func TestGetMemberships_byOrg(t *testing.T) {
	h := newHarness(t)
	seedMembership(t, h.db, "hanzo/alice", "hanzo", store.RoleMember)
	seedMembership(t, h.db, "hanzo/boss", "hanzo", store.RoleAdmin)

	// hanzo's own admin may read its own org's roster (handler-authorized scoped()).
	status, e := h.get(t, "/v1/iam/get-memberships?org=hanzo", h.token(t, "hanzo/boss"))
	if status != 200 || e.Status != "ok" {
		t.Fatalf("get-memberships?org status=%d env=%+v, want 200 ok", status, e)
	}
	if rows := parseMemberships(t, e); len(rows) != 2 {
		t.Fatalf("hanzo roster = %d, want 2 (alice, boss)", len(rows))
	}
}

// add-membership creates the row the same store EnsureMembership does, and a
// following get-memberships shows it — the verbs share ONE store.
func TestAddMembership_thenGetShowsIt(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")

	status, e := h.post(t, "/v1/iam/add-membership",
		map[string]string{"user": "hanzo/alice", "org": "team-x", "role": "admin"}, super)
	if status != 200 || e.Status != "ok" {
		t.Fatalf("add-membership status=%d env=%+v, want 200 ok", status, e)
	}
	if !parseBool(t, e) {
		t.Fatal("add-membership reported no row created")
	}

	_, g := h.get(t, "/v1/iam/get-memberships?user=hanzo/alice", super)
	rows := parseMemberships(t, g)
	if len(rows) != 1 || rows[0].Org != "team-x" || rows[0].Role != store.RoleAdmin {
		t.Fatalf("after add, memberships = %+v, want one {team-x, admin}", rows)
	}
}

// delete-membership removes the row and is idempotent: a second delete of the same
// (user, org) reports removed=false with no error.
func TestDeleteMembership_removesAndIdempotent(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	seedMembership(t, h.db, "hanzo/alice", "team-x", store.RoleAdmin)

	status, e := h.post(t, "/v1/iam/delete-membership",
		map[string]string{"user": "hanzo/alice", "org": "team-x"}, super)
	if status != 200 || e.Status != "ok" || !parseBool(t, e) {
		t.Fatalf("first delete status=%d env=%+v, want 200 ok removed=true", status, e)
	}
	// Row is gone.
	if m, _ := store.GetMembership(context.Background(), h.db, "hanzo/alice", "team-x"); m != nil {
		t.Fatal("membership survived delete")
	}
	// Idempotent second delete: still ok, but removed=false.
	_, e2 := h.post(t, "/v1/iam/delete-membership",
		map[string]string{"user": "hanzo/alice", "org": "team-x"}, super)
	if e2.Status != "ok" || parseBool(t, e2) {
		t.Fatalf("second delete env=%+v, want ok removed=false (idempotent)", e2)
	}
}

// A cross-tenant caller is refused with v1's verbatim message — neither writing nor
// reading another tenant's membership rows.
func TestMembership_crossTenantDenied(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss") // admin of hanzo, NOT of orgb

	// Write into orgb: refused.
	_, add := h.post(t, "/v1/iam/add-membership",
		map[string]string{"user": "orgb/bob", "org": "orgb", "role": "member"}, boss)
	if add.Status != "error" || add.Msg != "auth:Unauthorized operation" {
		t.Fatalf("cross-tenant add-membership env=%+v, want error auth:Unauthorized operation", add)
	}
	// Delete from orgb: refused the same way.
	_, del := h.post(t, "/v1/iam/delete-membership",
		map[string]string{"user": "orgb/bob", "org": "orgb"}, boss)
	if del.Status != "error" || del.Msg != "auth:Unauthorized operation" {
		t.Fatalf("cross-tenant delete-membership env=%+v, want error auth:Unauthorized operation", del)
	}
	// Read orgb's roster: refused the same way.
	_, roster := h.get(t, "/v1/iam/get-memberships?org=orgb", boss)
	if roster.Status != "error" || roster.Msg != "auth:Unauthorized operation" {
		t.Fatalf("cross-tenant get-memberships?org=orgb env=%+v, want error auth:Unauthorized operation", roster)
	}
}

// The verbs are gated: no bearer → the Guard fails closed (401).
func TestMembershipVerbs_requireAuth(t *testing.T) {
	h := newHarness(t)
	if status, _ := h.get(t, "/v1/iam/get-memberships?org=hanzo", ""); status != 401 {
		t.Fatalf("unauthenticated get-memberships status=%d, want 401", status)
	}
}

// ---- helpers ---------------------------------------------------------------

func parseMemberships(t *testing.T, e env) []schema.Membership {
	t.Helper()
	var rows []schema.Membership
	if err := json.Unmarshal(e.Data, &rows); err != nil {
		t.Fatalf("data is not a membership list: %v (data=%s)", err, e.Data)
	}
	return rows
}

func parseBool(t *testing.T, e env) bool {
	t.Helper()
	var b bool
	if err := json.Unmarshal(e.Data, &b); err != nil {
		t.Fatalf("data is not a bool: %v (data=%s)", err, e.Data)
	}
	return b
}

func seedMembership(t *testing.T, db orm.DB, user, org, role string) {
	t.Helper()
	if _, err := store.EnsureMembership(context.Background(), db, user, org, role); err != nil {
		t.Fatalf("seed membership %s@%s: %v", user, org, err)
	}
}

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
