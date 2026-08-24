// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invitations_test

// List authorizes on the query rather than a decoded body, so it runs behind the
// Guard and is exercised through the registered router (routes.Route installs the
// Guard). The owner a listing is pinned to is the one principal.Scope resolves from
// the credential — the caller's own org for a tenant, the whole estate for a
// SuperAdmin — never the request parameter, which the caller writes.
// This pins that scoping and List's store-fault arm: a read that fails under an
// admitted caller is a 500, never a 200 carrying an empty page that would read as
// "your org has no invitations" and hide the outage.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
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
		Path:   filepath.Join(t.TempDir(), "invitations.db"),
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

	app := zip.New(zip.Config{AppName: "invitations-list-test", DisableStartupMessage: true})
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

// list issues the get-invitations request as bearer against app and returns the
// status and the names carried in the invitations envelope.
func list(t *testing.T, app *zip.App, bearer, path string) (int, []string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var out struct {
		Invitations []struct {
			Name string `json:"name"`
		} `json:"invitations"`
	}
	_ = json.Unmarshal(b, &out)
	names := make([]string, 0, len(out.Invitations))
	for _, inv := range out.Invitations {
		names = append(names, inv.Name)
	}
	return resp.StatusCode, names
}

// ---- seed helpers ----

func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	keyring.Set(name, privPEM) // the deployment supplies key material; the row never carries it
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

func seedInvitation(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	inv := orm.New[schema.Invitation](db)
	inv.Owner, inv.Name = owner, name
	inv.SetId(owner + "/" + name)
	if err := inv.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed invitation %s/%s: %v", owner, name, err)
	}
}

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}

func has(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

// TestList_scopedToOwnOrg: a tenant admin's listing is filtered to its own org —
// the invitations it owns, and no other tenant's. principal.Scope pins the read to the
// credential's org, so the orgb row never appears in hanzo's page.
func TestList_scopedToOwnOrg(t *testing.T) {
	h := newHarness(t)
	seedInvitation(t, h.db, "hanzo", "welcome")
	seedInvitation(t, h.db, "orgb", "secret")

	// boss (hanzo org-admin) lists — sees hanzo's invitation, filtered by owner.
	st, names := list(t, h.app, h.token(t, "hanzo/boss"), "/v1/iam/invitations?owner=hanzo")
	if st != 200 {
		t.Fatalf("list: status = %d, want 200", st)
	}
	if !has(names, "welcome") {
		t.Fatalf("own-org invitation missing: %v", names)
	}
	if has(names, "secret") {
		t.Fatalf("VULN: hanzo admin listed orgb's invitation 'secret': %v", names)
	}
}

// TestList_superSeesEveryTenant: a SuperAdmin's listing is unfiltered — the empty
// owner it resolves to lists every tenant's invitations, the branch a tenant read
// never takes.
func TestList_superSeesEveryTenant(t *testing.T) {
	h := newHarness(t)
	seedInvitation(t, h.db, "hanzo", "welcome")
	seedInvitation(t, h.db, "orgb", "secret")

	st, names := list(t, h.app, h.token(t, "admin/root"), "/v1/iam/invitations")
	if st != 200 {
		t.Fatalf("list: status = %d, want 200", st)
	}
	if !has(names, "welcome") || !has(names, "secret") {
		t.Fatalf("SuperAdmin listing is not estate-wide: %v", names)
	}
}

// invQueryFailDB passes every store call through to a real backend except a query
// for the invitations kind, whose execution fails. The Guard's own reads (cert,
// user, membership) are other kinds and pass through, so a caller is still admitted;
// only the handler's invitations listing meets the fault.
type invQueryFailDB struct{ orm.DB }

func (d invQueryFailDB) Query(kind string) orm.Query {
	q := d.DB.Query(kind)
	if kind == "invitations" {
		return failQuery{Query: q}
	}
	return q
}

var errRead = errors.New("invitations read path down")

// failQuery keeps its wrapper across the builder chain and fails at execution, so a
// Filter/Order chain still ends in the fault rather than unwrapping to the real query.
type failQuery struct{ orm.Query }

func (f failQuery) Filter(string, interface{}) orm.Query { return f }
func (f failQuery) Order(string) orm.Query               { return f }
func (f failQuery) Limit(int) orm.Query                  { return f }
func (f failQuery) Offset(int) orm.Query                 { return f }
func (f failQuery) Ancestor(orm.Key) orm.Query           { return f }
func (f failQuery) KeysOnly() orm.Query                  { return f }
func (failQuery) GetAll(context.Context, interface{}) ([]orm.Key, error) {
	return nil, errRead
}

// TestList_storeFaultIsInternal: an invitations read that fails under an admitted
// caller is a 500, not a 200 empty page.
func TestList_storeFaultIsInternal(t *testing.T) {
	h := newHarness(t)
	app := zip.New(zip.Config{AppName: "invitations-list-fault", DisableStartupMessage: true})
	routes.Route(app, invQueryFailDB{DB: h.db})
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	req := httptest.NewRequest("GET", "/v1/iam/invitations?owner=hanzo", nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer "+h.token(t, "hanzo/boss"))
	resp, err := testhttp.Do(app, req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 500 {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}
}
