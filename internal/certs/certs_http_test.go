// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Certs LIST driven through the REAL registered router (routes.Route installs the
// Guard and the typed CRUD), because the listing's owner is decided from the
// caller's verified principal and nowhere else — a query parameter must never
// widen it. Only the full stack carries a principal, so only the full stack can
// prove WHOSE certs a request lists: a SuperAdmin sees any org's, an org-admin
// sees its own, and neither a foreign owner in the query nor a non-admin caller
// can reach another tenant's signing material.
package certs_test

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
		Path:   filepath.Join(t.TempDir(), "certs.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// The signing cert the Guard verifies bearers against, plus the callers.
	seedSigningCert(t, db, key)
	seedUser(t, db, "admin", "root", true)   // SuperAdmin
	seedUser(t, db, "hanzo", "boss", true)   // org-admin of hanzo
	seedUser(t, db, "hanzo", "alice", false) // regular member of hanzo

	// Listable rows: two under hanzo (one carrying an ACME secret, to prove the
	// listing masks it), one under a second tenant that a hanzo request must never
	// see.
	seedCertRow(t, db, &schema.Cert{Owner: "hanzo", Name: "cert-a", CryptoAlgorithm: "RS256", AccessSecret: "acme-dns-token"})
	seedCertRow(t, db, &schema.Cert{Owner: "hanzo", Name: "cert-b", CryptoAlgorithm: "RS256"})
	seedCertRow(t, db, &schema.Cert{Owner: "orgb", Name: "cert-c", CryptoAlgorithm: "RS256"})

	app := zip.New(zip.Config{AppName: "certs-test", DisableStartupMessage: true})
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

func (h *harness) get(t *testing.T, path, bearer string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	return resp.StatusCode, m
}

// certNames reads the cert names out of a list envelope's data.
func certNames(m map[string]any) []string {
	rows, _ := m["certs"].([]any)
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

// A SUPERADMIN LISTS EVERY TENANT'S CERTS when it names no owner, and exactly one
// tenant's when it names it. The empty owner is not "no filter for anyone" — it is
// the cross-tenant scope only a SuperAdmin holds — and naming an owner narrows the
// same authority to that org.
func TestList_SuperAdmin(t *testing.T) {
	h := newHarness(t)
	root := h.token(t, "admin/root")

	st, m := h.get(t, "/v1/iam/certs", root)
	if st != 200 {
		t.Fatalf("list-all status = %d: %v", st, m)
	}
	all := certNames(m)
	for _, want := range []string{signingKid, "cert-a", "cert-b", "cert-c"} {
		if !has(all, want) {
			t.Fatalf("cross-tenant listing missing %q: %v", want, all)
		}
	}
	if total, _ := m["total"].(float64); int(total) != len(all) {
		t.Fatalf("total = %v, want %d", m["total"], len(all))
	}

	st, m = h.get(t, "/v1/iam/certs?owner=hanzo", root)
	if st != 200 {
		t.Fatalf("list-hanzo status = %d: %v", st, m)
	}
	got := certNames(m)
	if !has(got, "cert-a") || !has(got, "cert-b") {
		t.Fatalf("owner filter dropped hanzo's certs: %v", got)
	}
	if has(got, "cert-c") {
		t.Fatalf("owner=hanzo listed another tenant's cert: %v", got)
	}
}

// AN ORG-ADMIN LISTS ITS OWN ORG'S CERTS, and the listing masks the ACME/DNS
// secret — a read serves the public half, never the credential ACME renewal uses.
func TestList_OrgAdminSeesOwnOrgMasked(t *testing.T) {
	h := newHarness(t)
	st, m := h.get(t, "/v1/iam/certs?owner=hanzo", h.token(t, "hanzo/boss"))
	if st != 200 {
		t.Fatalf("status = %d: %v", st, m)
	}
	if got := certNames(m); !has(got, "cert-a") || has(got, "cert-c") {
		t.Fatalf("org-admin listing = %v, want its own org only", got)
	}
	for _, r := range m["certs"].([]any) {
		row := r.(map[string]any)
		if row["name"] == "cert-a" {
			if s, _ := row["accessSecret"].(string); s != "" {
				t.Fatalf("the listing disclosed the ACME secret: %q", s)
			}
		}
	}
}

// THE QUERY PARAMETER NEVER WIDENS THE LISTING. A hanzo org-admin that spells
// another tenant's owner is refused, not answered with that tenant's rows — the
// one thing the scope rule must never do is return org B's certs to a caller
// pinned to org A.
func TestList_ForeignOwnerRefused(t *testing.T) {
	h := newHarness(t)
	if st, m := h.get(t, "/v1/iam/certs?owner=orgb", h.token(t, "hanzo/boss")); st == 200 {
		t.Fatalf("a foreign owner was answered, not refused: %v", m)
	}
}

// A REGULAR MEMBER CANNOT LIST CERTS. Signing material is not self-service: a
// non-admin caller is refused even for its own org, so a leaked ordinary bearer
// never enumerates the keys its tokens are verified against.
func TestList_RegularMemberRefused(t *testing.T) {
	h := newHarness(t)
	if st, _ := h.get(t, "/v1/iam/certs?owner=hanzo", h.token(t, "hanzo/alice")); st == 200 {
		t.Fatal("a regular member listed certs")
	}
}

// ---- seed helpers ----

func seedSigningCert(t *testing.T, db orm.DB, key *rsa.PrivateKey) {
	t.Helper()
	priv := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	keyring.Set(signingKid, priv) // the deployment supplies key material; the row never carries it
	seedCertRow(t, db, &schema.Cert{Owner: "admin", Name: signingKid, CryptoAlgorithm: "RS256"})
}

func seedCertRow(t *testing.T, db orm.DB, in *schema.Cert) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	model := c.Model
	*c = *in
	c.Model = model
	if c.CreatedTime == "" {
		c.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	c.SetId(in.Owner + "/" + in.Name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert %s/%s: %v", in.Owner, in.Name, err)
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
