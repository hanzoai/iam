// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications_test

// authorizeOrganization gates the Organization an application will SERVE — the
// tenant a credential minted through it lands in — separately from the registry
// Owner the Guard already authorizes. These cases drive the REAL router
// (routes.Route installs the Guard, so a Principal is attached), because the gate
// only runs when a Principal is present: an org-admin may point an app at its OWN
// org, but not at the reserved admin org (a SuperAdmin-minting app) nor at a
// victim tenant.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

const orgSigningKid = "cert-hanzo"

type orgHarness struct {
	app *zip.App
	key *rsa.PrivateKey
}

func newOrgHarness(t *testing.T) *orgHarness {
	t.Helper()
	_ = schema.Kinds()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "apporg.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, "admin", orgSigningKid, pemOf(t, key))
	seedUser(t, db, "admin", "root", true) // SuperAdmin
	seedUser(t, db, "hanzo", "boss", true) // org-admin of hanzo

	app := zip.New(zip.Config{AppName: "apporg-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &orgHarness{app: app, key: key}
}

func (h *orgHarness) token(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = orgSigningKid
	s, err := tok.SignedString(h.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func (h *orgHarness) do(t *testing.T, method, path, bearer, body string) int {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	keyring.Set(name, privPEM)
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

// An org-admin may point an app at its OWN org (CanSetOrg true), but not at the
// reserved admin org (CanSetOrg false) — the latter would mint a SuperAdmin.
func TestCreate_OrganizationGate(t *testing.T) {
	h := newOrgHarness(t)
	boss := h.token(t, "hanzo/boss")

	if st := h.do(t, "POST", "/v1/iam/applications", boss, `{"owner":"hanzo","name":"own","organization":"hanzo","clientId":"own"}`); st != 200 {
		t.Fatalf("own-org app: status=%d, want 200", st)
	}
	if st := h.do(t, "POST", "/v1/iam/applications", boss, `{"owner":"hanzo","name":"esc","organization":"admin","clientId":"esc"}`); st != 403 {
		t.Fatalf("pointing an app at the reserved admin org: status=%d, want 403", st)
	}
}

// The same organization gate guards Update: an org-admin cannot re-point an
// existing app at the reserved admin org either.
func TestUpdate_OrganizationGate(t *testing.T) {
	h := newOrgHarness(t)
	boss := h.token(t, "hanzo/boss")

	if st := h.do(t, "POST", "/v1/iam/applications", boss, `{"owner":"hanzo","name":"svc","organization":"hanzo","clientId":"svc"}`); st != 200 {
		t.Fatalf("seed: status=%d, want 200", st)
	}
	if st := h.do(t, "PUT", "/v1/iam/applications/hanzo/svc", boss, `{"owner":"hanzo","name":"svc","organization":"admin","clientId":"svc"}`); st != 403 {
		t.Fatalf("re-pointing at the reserved admin org: status=%d, want 403", st)
	}
}

// A SuperAdmin is the one identity that may set any org, including admin.
func TestCreate_SuperAdminMaySetAnyOrg(t *testing.T) {
	h := newOrgHarness(t)
	root := h.token(t, "admin/root")

	if st := h.do(t, "POST", "/v1/iam/applications", root, `{"owner":"hanzo","name":"platform","organization":"admin","clientId":"platform"}`); st != 200 {
		t.Fatalf("SuperAdmin set organization=admin: status=%d, want 200", st)
	}
}
