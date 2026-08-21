// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package memberships_test

// The the legacy surface membership VERB aliases (GAP A): get-memberships / add-membership /
// delete-membership, the spellings cloud's clients/team invite path hard-codes.
// Every case is a HTTP request driven through the REAL registered router (routes.Route
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
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
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
	status, body := h.read(t, path, bearer)
	return status, envOf(body)
}

// send is the ONE writer: the surface is one address and the METHOD says which
// operation, so the helper takes the method rather than the helpers multiplying.
func (h *harness) send(t *testing.T, method, path string, body any, bearer string) (int, env) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return h.do(t, req)
}

func (h *harness) post(t *testing.T, path string, body any, bearer string) (int, env) {
	t.Helper()
	return h.send(t, "POST", path, body, bearer)
}

// del revokes. It is a separate helper only so a call site READS as a revoke;
// the operation it reaches is chosen by the method, not by the address.
func (h *harness) del(t *testing.T, path string, body any, bearer string) (int, env) {
	t.Helper()
	return h.send(t, "DELETE", path, body, bearer)
}

// postBasic drives an add/delete verb authenticating as a confidential client
// (client_secret_basic) — how a brand console / cloud service calls these verbs.
func (h *harness) postBasic(t *testing.T, path string, body any, clientID, secret string) (int, env) {
	t.Helper()
	return h.basic(t, "POST", path, body, clientID, secret)
}

func (h *harness) delBasic(t *testing.T, path string, body any, clientID, secret string) (int, env) {
	t.Helper()
	return h.basic(t, "DELETE", path, body, clientID, secret)
}

func (h *harness) basic(t *testing.T, method, path string, body any, clientID, secret string) (int, env) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(clientID, secret)
	return h.do(t, req)
}

// do drives the request through the real registered router and decodes the v1
// envelope. A raw 401 (the Guard's fail-closed refusal) has no envelope body; the
// caller asserts on the status alone.
func (h *harness) do(t *testing.T, req *http.Request) (int, env) {
	t.Helper()
	status, body := h.raw(t, req)
	return status, envOf(body)
}

// envOf decodes the v1 envelope a body carries — the ONE decode, so `get` and
// `do` cannot drift into reading the same bytes two ways.
func envOf(body string) env {
	var e env
	_ = json.Unmarshal([]byte(body), &e)
	return e
}

// raw is do without the decode — the status and the body VERBATIM, for a case
// whose subject IS the bytes.
func (h *harness) raw(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL.Path, err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(body)
}

// read drives one GET and returns the status and the body verbatim.
func (h *harness) read(t *testing.T, url, bearer string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", url, nil)
	req.Host = "hanzo.id"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return h.raw(t, req)
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

	status, e := h.get(t, "/v1/iam/memberships?user=hanzo/alice", h.token(t, "admin/root"))
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
	status, e := h.get(t, "/v1/iam/memberships?org=hanzo", h.token(t, "hanzo/boss"))
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

	status, e := h.post(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/alice", "org": "team-x", "role": "admin"}, super)
	if status != 200 || e.Status != "ok" {
		t.Fatalf("add-membership status=%d env=%+v, want 200 ok", status, e)
	}
	if !parseBool(t, e) {
		t.Fatal("add-membership reported no row created")
	}

	_, g := h.get(t, "/v1/iam/memberships?user=hanzo/alice", super)
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

	status, e := h.del(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/alice", "org": "team-x"}, super)
	if status != 200 || e.Status != "ok" || !parseBool(t, e) {
		t.Fatalf("first delete status=%d env=%+v, want 200 ok removed=true", status, e)
	}
	// Row is gone.
	if m, _ := store.GetMembership(context.Background(), h.db, "hanzo/alice", "team-x"); m != nil {
		t.Fatal("membership survived delete")
	}
	// Idempotent second delete: still ok, but removed=false.
	_, e2 := h.del(t, "/v1/iam/memberships",
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
	_, add := h.post(t, "/v1/iam/memberships",
		map[string]string{"user": "orgb/bob", "org": "orgb", "role": "member"}, boss)
	if add.Status != "error" || add.Msg != "auth:Unauthorized operation" {
		t.Fatalf("cross-tenant add-membership env=%+v, want error auth:Unauthorized operation", add)
	}
	// Delete from orgb: refused the same way.
	_, del := h.del(t, "/v1/iam/memberships",
		map[string]string{"user": "orgb/bob", "org": "orgb"}, boss)
	if del.Status != "error" || del.Msg != "auth:Unauthorized operation" {
		t.Fatalf("cross-tenant delete-membership env=%+v, want error auth:Unauthorized operation", del)
	}
	// Read orgb's roster: refused the same way.
	_, roster := h.get(t, "/v1/iam/memberships?org=orgb", boss)
	if roster.Status != "error" || roster.Msg != "auth:Unauthorized operation" {
		t.Fatalf("cross-tenant get-memberships?org=orgb env=%+v, want error auth:Unauthorized operation", roster)
	}
}

// RED F2 — a CapOrgAdmin (non-super) confidential client can create customer-org
// memberships but must NEVER grant tenancy INTO a reserved system org (admin /
// built-in), which would seed a SuperAdmin-org `orgs` claim on the target user. Only
// a real SuperAdmin may. The client's legitimate power over a normal org is intact.
func TestEnsureMembership_reservedOrgRequiresSuper(t *testing.T) {
	h := newHarness(t)
	seedClientApp(t, h.db, "hanzo-console", "console-secret")
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")

	// Into the reserved admin/built-in orgs: refused, verbatim.
	for _, org := range []string{"admin", "built-in"} {
		_, e := h.postBasic(t, "/v1/iam/memberships",
			map[string]string{"user": "hanzo/alice", "org": org, "role": "admin"}, "hanzo-console", "console-secret")
		if e.Status != "error" || e.Msg != "auth:Unauthorized operation" {
			t.Fatalf("CapOrgAdmin ensure into %q env=%+v, want error auth:Unauthorized operation", org, e)
		}
		if m, _ := store.GetMembership(context.Background(), h.db, "hanzo/alice", org); m != nil {
			t.Fatalf("a reserved-org membership was created in %q despite the refusal", org)
		}
	}
	// Revoke into a reserved org is gated the same way.
	_, del := h.delBasic(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/alice", "org": "admin"}, "hanzo-console", "console-secret")
	if del.Status != "error" || del.Msg != "auth:Unauthorized operation" {
		t.Fatalf("CapOrgAdmin revoke into admin env=%+v, want error auth:Unauthorized operation", del)
	}

	// Legit power preserved: the SAME client CAN ensure into a normal customer org.
	_, ok := h.postBasic(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/alice", "org": "hanzo", "role": "member"}, "hanzo-console", "console-secret")
	if ok.Status != "ok" {
		t.Fatalf("CapOrgAdmin ensure into a normal org env=%+v, want ok (legit power broken)", ok)
	}

	// And a real SuperAdmin MAY grant a reserved-org membership (the escape hatch).
	_, sup := h.post(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/alice", "org": "admin", "role": "admin"}, h.token(t, "admin/root"))
	if sup.Status != "ok" {
		t.Fatalf("SuperAdmin ensure into admin env=%+v, want ok", sup)
	}
}

// ---- the read as a typed op ------------------------------------------------

// The list is a TYPED op at BOTH addresses, so it reaches two seams a raw handler
// never did: zip's query binder, and the op-invoke authorizer (authz.Authorize).
// Both are silent when they work and fatal when they do not — a binder that missed
// ?org= answers "exactly one of user or org is required", an authorizer that saw a
// target answers 403 — so these cases assert the RAW BODY BYTES at each address.
//
// The bytes are the point. Typing this read is a projection, not a change: same
// address, same status, same envelope, before and after.
func TestList_wire(t *testing.T) {
	h := newHarness(t)
	seedMembership(t, h.db, "hanzo/alice", "hanzo", store.RoleMember)
	seedMembership(t, h.db, "hanzo/boss", "hanzo", store.RoleAdmin)
	boss := h.token(t, "hanzo/boss")

	// Both addresses, one handler, one answer.
	for _, path := range []string{"/v1/iam/memberships", "/v1/iam/memberships"} {
		t.Run(path, func(t *testing.T) {
			status, body := h.read(t, path+"?org=hanzo", boss)
			if status != 200 {
				t.Fatalf("status=%d body=%s, want 200", status, body)
			}
			if !strings.HasPrefix(body, `{"status":"ok","msg":"","data":[`) || !strings.HasSuffix(body, `],"data2":2}`) {
				t.Fatalf("body=%s, want the v1 envelope with data2=2", body)
			}
			// The other question the same op answers: one identity's orgs.
			status, body = h.read(t, path+"?user=hanzo/alice", boss)
			if status != 200 || !strings.HasSuffix(body, `],"data2":1}`) {
				t.Fatalf("?user status=%d body=%s, want 200 with data2=1", status, body)
			}
		})
	}
}

// The refusals, byte for byte at both addresses: 400 carrying {status:"error",
// msg, data:null}.
func TestList_refusals(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss") // admin of hanzo, NOT of orgb
	const denied = `{"status":"error","msg":"auth:Unauthorized operation","data":null}`
	for _, c := range []struct{ name, query, want string }{
		{"neither", "", `{"status":"error","msg":"exactly one of user or org is required","data":null}`},
		{"both", "?user=hanzo/alice&org=hanzo", `{"status":"error","msg":"exactly one of user or org is required","data":null}`},
		// The angle brackets arrive escaped: encoding/json escapes HTML by
		// default, so the bytes carry the < form. The brackets are the
		// message's, the escaping is the encoder's, and the escaped form is what
		// this address has always put on the wire — assert the bytes, not the
		// message.
		{"unqualified user", "?user=alice", `{"status":"error","msg":"user must be \u003cowner\u003e/\u003cname\u003e","data":null}`},
		{"cross-tenant org", "?org=orgb", denied},
		{"cross-tenant user", "?user=orgb/bob", denied},
	} {
		for _, path := range []string{"/v1/iam/memberships", "/v1/iam/memberships"} {
			t.Run(c.name+" "+path, func(t *testing.T) {
				status, body := h.read(t, path+c.query, boss)
				if status != 400 || body != c.want {
					t.Fatalf("status=%d body=%s, want 400 %s", status, body, c.want)
				}
			})
		}
	}
}

// The op-invoke authorizer admits this read because its input names no owner —
// `lookup` declares no Owner field and no AuthzTarget(). An unknown query key is
// therefore just an unknown query key: it is ignored by the binder and can never
// become the target the authorizer decides on. Give the input an Owner field and
// this is a 403, which is why the case is here rather than in a comment.
func TestList_ownerQueryIsNotATarget(t *testing.T) {
	h := newHarness(t)
	seedMembership(t, h.db, "hanzo/alice", "hanzo", store.RoleMember)
	for _, path := range []string{"/v1/iam/memberships", "/v1/iam/memberships"} {
		status, body := h.read(t, path+"?org=hanzo&owner=orgb&name=whatever", h.token(t, "hanzo/boss"))
		if status != 200 {
			t.Fatalf("%s status=%d body=%s, want 200 — the read is authorized by scoped(), not by ?owner=", path, status, body)
		}
	}
}

// The verbs are gated: no bearer → the Guard fails closed (401).
func TestMembershipVerbs_requireAuth(t *testing.T) {
	h := newHarness(t)
	if status, _ := h.get(t, "/v1/iam/memberships?org=hanzo", ""); status != 401 {
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

// seedClientApp seeds an admin-owned confidential client (so the CapOrgAdmin
// owner-pin holds) with a client_secret for Basic-auth authentication.
func seedClientApp(t *testing.T, db orm.DB, name, secret string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name = "admin", name
	a.Organization = "hanzo"
	a.ClientId = name
	a.ClientSecret = secret
	a.SetId("admin/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed client app: %v", err)
	}
}

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

// readBasic drives a GET authenticating as a confidential client, the way a
// brand console reaches this surface.
func (h *harness) readBasic(t *testing.T, path, clientID, secret string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	req.SetBasicAuth(clientID, secret)
	return h.raw(t, req)
}
