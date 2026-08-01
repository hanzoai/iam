// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package workspaces_test

// Workspace tests driven through the REAL registered router (routes.Route installs
// the Guard, the typed CRUD, and the legacy verb aliases). Every case is a bind
// request the console ScopeSwitcher / Workspaces page sends via the /org/iam
// proxy. The assertions pin the parity contract (add-workspace →
// get-organization-workspaces → delete-workspace), the Organization → Workspace →
// Project hierarchy (a Project's Workspace FK round-trips), the storage binding
// (Bucket round-trips through create AND update), the default flag (IsDefault
// round-trips), and the security ones: any org member may LIST its org's
// workspaces (the switcher is shown to everyone), a WRITE needs org-admin
// authority, and no request parameter can list another tenant's workspaces.

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
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "workspaces.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, "admin", signingKid, pemOf(t, key))
	seedUser(t, db, "admin", "root", true)   // SuperAdmin
	seedUser(t, db, "hanzo", "boss", true)   // org-admin of hanzo
	seedUser(t, db, "hanzo", "alice", false) // regular user in hanzo

	app := zip.New(zip.Config{AppName: "workspaces-test", DisableStartupMessage: true})
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

func (h *harness) do(t *testing.T, method, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, r)
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

// rows returns the row objects out of an envelope's data.
func rows(m map[string]any) []map[string]any {
	raw, _ := m["data"].([]any)
	out := make([]map[string]any, 0, len(raw))
	for _, r := range raw {
		if o, ok := r.(map[string]any); ok {
			out = append(out, o)
		}
	}
	return out
}

// names reads the names out of an envelope's data.
func names(m map[string]any) []string {
	out := []string{}
	for _, o := range rows(m) {
		if n, _ := o["name"].(string); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// find returns the row with the given name, or nil.
func find(m map[string]any, name string) map[string]any {
	for _, o := range rows(m) {
		if n, _ := o["name"].(string); n == name {
			return o
		}
	}
	return nil
}

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestWorkspaces_lifecycle: an org-admin creates a workspace, any member lists it,
// the admin deletes it. Add → GetOrganizationWorkspaces → Delete.
func TestWorkspaces_lifecycle(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")
	alice := h.token(t, "hanzo/alice")

	// add-workspace (org-admin).
	body := `{"owner":"hanzo","name":"alpha","displayName":"Alpha","organization":"hanzo","description":"first","bucket":"hanzo-alpha"}`
	if st, m := h.do(t, "POST", "/v1/iam/add-workspace", boss, body); st != 200 || m["status"] != "ok" {
		t.Fatalf("add-workspace: status=%d body=%v", st, m)
	}

	// get-organization-workspaces — a REGULAR member sees it (the switcher is for all).
	st, m := h.do(t, "GET", "/v1/iam/get-organization-workspaces?organization=hanzo", alice, "")
	if st != 200 || m["status"] != "ok" {
		t.Fatalf("list: status=%d body=%v", st, m)
	}
	if !has(names(m), "alpha") {
		t.Fatalf("list missing 'alpha': %v", names(m))
	}

	// delete-workspace (org-admin), keyed by owner/name.
	if st, m := h.do(t, "POST", "/v1/iam/delete-workspace", boss,
		`{"owner":"hanzo","name":"alpha","organization":"hanzo"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("delete-workspace: status=%d body=%v", st, m)
	}
	_, m = h.do(t, "GET", "/v1/iam/get-organization-workspaces?organization=hanzo", alice, "")
	if has(names(m), "alpha") {
		t.Fatalf("'alpha' still listed after delete: %v", names(m))
	}
}

// TestWorkspaces_bucketAndDefaultRoundTrip: the Bucket storage handle and the
// IsDefault flag round-trip through create, and a subsequent update re-binds the
// bucket. This is the GetDefaultWorkspace / bucket-round-trips contract, read back
// off the same list the ScopeSwitcher renders.
func TestWorkspaces_bucketAndDefaultRoundTrip(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	// create a default workspace bound to a bucket.
	if st, m := h.do(t, "POST", "/v1/iam/add-workspace", boss,
		`{"owner":"hanzo","name":"prod","organization":"hanzo","bucket":"hanzo-prod","isDefault":true}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("add-workspace: status=%d body=%v", st, m)
	}

	_, m := h.do(t, "GET", "/v1/iam/get-organization-workspaces?organization=hanzo", boss, "")
	w := find(m, "prod")
	if w == nil {
		t.Fatalf("workspace 'prod' not listed: %v", names(m))
	}
	if got, _ := w["bucket"].(string); got != "hanzo-prod" {
		t.Fatalf("bucket did not round-trip on create: got %q, want %q", got, "hanzo-prod")
	}
	if d, _ := w["isDefault"].(bool); !d {
		t.Fatalf("isDefault did not round-trip on create: got %v", w["isDefault"])
	}

	// update the workspace: re-bind the bucket (native typed CRUD, admin-authorized).
	if st, m := h.do(t, "POST", "/v1/iam/workspaces/update", boss,
		`{"owner":"hanzo","name":"prod","organization":"hanzo","bucket":"hanzo-prod-v2","isDefault":true}`); st != 200 {
		t.Fatalf("workspaces/update: status=%d body=%v", st, m)
	}
	_, m = h.do(t, "GET", "/v1/iam/get-organization-workspaces?organization=hanzo", boss, "")
	w = find(m, "prod")
	if got, _ := w["bucket"].(string); got != "hanzo-prod-v2" {
		t.Fatalf("bucket did not round-trip on update: got %q, want %q", got, "hanzo-prod-v2")
	}
}

// TestWorkspaces_projectFKRoundTrip: a Project created with its Workspace FK set
// round-trips that FK (Organization → Workspace → Project), and a Project with no
// Workspace stays org-level (empty FK) — backward compatible.
func TestWorkspaces_projectFKRoundTrip(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	// parent workspace + a project attached to it.
	if st, m := h.do(t, "POST", "/v1/iam/add-workspace", boss,
		`{"owner":"hanzo","name":"alpha","organization":"hanzo"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("add-workspace: status=%d body=%v", st, m)
	}
	if st, m := h.do(t, "POST", "/v1/iam/add-project", boss,
		`{"owner":"hanzo","name":"scoped","organization":"hanzo","workspace":"alpha"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("add-project(scoped): status=%d body=%v", st, m)
	}
	// a legacy/org-level project with no workspace.
	if st, m := h.do(t, "POST", "/v1/iam/add-project", boss,
		`{"owner":"hanzo","name":"orglevel","organization":"hanzo"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("add-project(orglevel): status=%d body=%v", st, m)
	}

	_, m := h.do(t, "GET", "/v1/iam/get-organization-projects?organization=hanzo", boss, "")
	scoped := find(m, "scoped")
	if scoped == nil {
		t.Fatalf("project 'scoped' not listed: %v", names(m))
	}
	if got, _ := scoped["workspace"].(string); got != "alpha" {
		t.Fatalf("Workspace FK did not round-trip: got %q, want %q", got, "alpha")
	}
	orglevel := find(m, "orglevel")
	if orglevel == nil {
		t.Fatalf("project 'orglevel' not listed: %v", names(m))
	}
	if got, _ := orglevel["workspace"].(string); got != "" {
		t.Fatalf("org-level project should have empty Workspace FK: got %q", got)
	}
}

// TestWorkspaces_writeNeedsAdmin: a regular member can LIST but not create/delete.
func TestWorkspaces_writeNeedsAdmin(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice") // regular

	body := `{"owner":"hanzo","name":"beta","organization":"hanzo"}`
	if st, _ := h.do(t, "POST", "/v1/iam/add-workspace", alice, body); st != 403 {
		t.Fatalf("regular user add-workspace: status=%d, want 403", st)
	}
	if st, _ := h.do(t, "POST", "/v1/iam/delete-workspace", alice, body); st != 403 {
		t.Fatalf("regular user delete-workspace: status=%d, want 403", st)
	}
	// But listing is allowed (200) — the switcher is shown to every user.
	if st, m := h.do(t, "GET", "/v1/iam/get-organization-workspaces?organization=hanzo", alice, ""); st != 200 || m["status"] != "ok" {
		t.Fatalf("regular user list: status=%d body=%v", st, m)
	}
}

// TestWorkspaces_crossTenantScoping: a non-super cannot list another tenant's
// workspaces — authz.Scope pins the read to the caller's own org regardless of the
// ?organization= it asks for.
func TestWorkspaces_crossTenantScoping(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	alice := h.token(t, "hanzo/alice")

	// super seeds a workspace under a DIFFERENT tenant, orgb.
	if st, m := h.do(t, "POST", "/v1/iam/add-workspace", super,
		`{"owner":"orgb","name":"secret","organization":"orgb","bucket":"orgb-secret"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("super add orgb workspace: status=%d body=%v", st, m)
	}

	// alice (hanzo) asks for orgb's workspaces → gets HER org's scope, never orgb's.
	_, m := h.do(t, "GET", "/v1/iam/get-organization-workspaces?organization=orgb", alice, "")
	if has(names(m), "secret") {
		t.Fatalf("VULN: hanzo user listed orgb's workspace 'secret': %v", names(m))
	}
}

// ---- seed helpers ----

func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
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
	u.PasswordHash = "$argon2id$SENTINEL"
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
