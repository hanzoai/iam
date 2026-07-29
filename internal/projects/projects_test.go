// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package projects_test

// Project tests driven through the REAL registered router (routes.Route installs the
// Guard, the typed CRUD, and the legacy verb aliases). Every case is a bind
// request the console ScopeSwitcher / Projects page sends via the /org/iam proxy.
// The assertions pin the parity contract (add-project → get-organization-projects
// → delete-project) and the security ones: any org member may LIST its org's
// projects (the switcher is shown to everyone), a WRITE needs org-admin authority,
// and no request parameter can list another tenant's projects.

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
	"github.com/hanzoai/iam/internal/schema"

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
		Path:   filepath.Join(t.TempDir(), "projects.db"),
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

	app := zip.New(zip.Config{AppName: "projects-test", DisableStartupMessage: true})
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

// names reads the project names out of a get-organization-projects envelope's data.
func names(m map[string]any) []string {
	rows, _ := m["data"].([]any)
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		if o, ok := r.(map[string]any); ok {
			if n, _ := o["name"].(string); n != "" {
				out = append(out, n)
			}
		}
	}
	return out
}

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestProjects_lifecycle: an org-admin creates a project, any member lists it, the
// admin deletes it.
func TestProjects_lifecycle(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")
	alice := h.token(t, "hanzo/alice")

	// add-project (org-admin).
	body := `{"owner":"hanzo","name":"alpha","displayName":"Alpha","organization":"hanzo","description":"first"}`
	if st, m := h.do(t, "POST", "/v1/iam/add-project", boss, body); st != 200 || m["status"] != "ok" {
		t.Fatalf("add-project: status=%d body=%v", st, m)
	}

	// get-organization-projects — a REGULAR member sees it (the switcher is for all).
	st, m := h.do(t, "GET", "/v1/iam/get-organization-projects?organization=hanzo", alice, "")
	if st != 200 || m["status"] != "ok" {
		t.Fatalf("list: status=%d body=%v", st, m)
	}
	if !has(names(m), "alpha") {
		t.Fatalf("list missing 'alpha': %v", names(m))
	}

	// delete-project (org-admin), keyed by owner/name.
	if st, m := h.do(t, "POST", "/v1/iam/delete-project", boss,
		`{"owner":"hanzo","name":"alpha","organization":"hanzo"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("delete-project: status=%d body=%v", st, m)
	}
	_, m = h.do(t, "GET", "/v1/iam/get-organization-projects?organization=hanzo", alice, "")
	if has(names(m), "alpha") {
		t.Fatalf("'alpha' still listed after delete: %v", names(m))
	}
}

// TestProjects_writeNeedsAdmin: a regular member can LIST but not create/delete.
func TestProjects_writeNeedsAdmin(t *testing.T) {
	h := newHarness(t)
	alice := h.token(t, "hanzo/alice") // regular

	body := `{"owner":"hanzo","name":"beta","organization":"hanzo"}`
	if st, _ := h.do(t, "POST", "/v1/iam/add-project", alice, body); st != 403 {
		t.Fatalf("regular user add-project: status=%d, want 403", st)
	}
	if st, _ := h.do(t, "POST", "/v1/iam/delete-project", alice, body); st != 403 {
		t.Fatalf("regular user delete-project: status=%d, want 403", st)
	}
	// But listing is allowed (200) — the switcher is shown to every user.
	if st, m := h.do(t, "GET", "/v1/iam/get-organization-projects?organization=hanzo", alice, ""); st != 200 || m["status"] != "ok" {
		t.Fatalf("regular user list: status=%d body=%v", st, m)
	}
}

// TestProjects_crossTenantScoping: a non-super cannot list another tenant's
// projects — authz.Scope pins the read to the caller's own org regardless of the
// ?organization= it asks for.
func TestProjects_crossTenantScoping(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	alice := h.token(t, "hanzo/alice")

	// super seeds a project under a DIFFERENT tenant, orgb.
	if st, m := h.do(t, "POST", "/v1/iam/add-project", super,
		`{"owner":"orgb","name":"secret","organization":"orgb"}`); st != 200 || m["status"] != "ok" {
		t.Fatalf("super add orgb project: status=%d body=%v", st, m)
	}

	// alice (hanzo) asks for orgb's projects → gets HER org's scope, never orgb's.
	_, m := h.do(t, "GET", "/v1/iam/get-organization-projects?organization=orgb", alice, "")
	if has(names(m), "secret") {
		t.Fatalf("VULN: hanzo user listed orgb's project 'secret': %v", names(m))
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
