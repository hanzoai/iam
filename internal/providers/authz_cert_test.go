// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package providers_test

// A provider NAMES a signing cert — the key a federated assertion is verified
// against. That name is a reference to signing material, and such material is
// trusted only under the reserved platform owners, so naming cert-hanzo is naming
// the key the platform's own tokens are signed with. An org admin may name a cert
// its own org owns and no other; only a SuperAdmin may name the reserved one. It is
// the same authority an application's cert carries and takes the same gate.
//
// These drive the REAL router with the Guard and the op-invoke seam installed, so
// the principal is the one a live request carries.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/providers"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

// certKid is the platform signing cert every token in this file is signed with,
// and the one a tenant must not be able to name.
const certKid = "cert-hanzo"

type certEnv struct {
	app *zip.App
	key *rsa.PrivateKey
	db  orm.DB
}

// certHarness boots the provider surface behind the real Guard and op-invoke seam,
// with the platform cert under the reserved admin owner, one org admin and one
// SuperAdmin.
func certHarness(t *testing.T) *certEnv {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "c.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	keyring.Set(certKid, string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})))
	seedCert(t, db, "admin", certKid)
	// A cert the tenant's own org owns — nameable by that tenant, and not signing
	// material, so it proves the gate pins the OWNER rather than blocking the field.
	seedCert(t, db, "hanzo", "cert-tenant")
	seedUser(t, db, "admin", "root", false)
	seedUser(t, db, "hanzo", "boss", true)

	app := zip.New(zip.Config{AppName: "c", DisableStartupMessage: true})
	authed := app.Group("").(*zip.App)
	authed.Use(authz.Guard(db))
	authed.Authorize(authz.Authorize)
	providers.Route(authed, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &certEnv{app: app, key: key, db: db}
}

func seedCert(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = owner, name, "RS256"
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert %s/%s: %v", owner, name, err)
	}
}

func seedUser(t *testing.T, db orm.DB, owner, name string, admin bool) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.IsAdmin = owner, name, admin
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %s/%s: %v", owner, name, err)
	}
}

func (e *certEnv) token(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = certKid
	s, err := tok.SignedString(e.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func (e *certEnv) do(t *testing.T, method, path, bearer, body string) int {
	t.Helper()
	var r *http.Request
	if body != "" {
		r, _ = http.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r, _ = http.NewRequest(method, path, nil)
	}
	r.Header.Set("Authorization", "Bearer "+bearer)
	res, err := testhttp.Do(e.app, r)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	return res.StatusCode
}

// An org admin cannot create a provider that names the platform signing cert.
func TestAddProvider_refusesReservedSigningCert(t *testing.T) {
	e := certHarness(t)
	boss := e.token(t, "hanzo/boss")

	if st := e.do(t, "POST", "/v1/iam/providers", boss,
		`{"owner":"hanzo","name":"forge","type":"SAML","cert":"`+certKid+`"}`); st != 403 {
		t.Fatalf("org admin naming the platform signing cert: status=%d, want 403", st)
	}
	if _, err := orm.Get[schema.Provider](e.db, "hanzo/forge"); err == nil {
		t.Fatal("a refused create persisted a row")
	}
}

// The same gate guards the update: an org admin cannot re-point a provider it owns
// at the platform signing cert either.
func TestUpdateProvider_refusesReservedSigningCert(t *testing.T) {
	e := certHarness(t)
	boss := e.token(t, "hanzo/boss")

	if st := e.do(t, "POST", "/v1/iam/providers", boss,
		`{"owner":"hanzo","name":"idp","type":"SAML"}`); st != 200 {
		t.Fatalf("seed own provider: status=%d, want 200", st)
	}
	if st := e.do(t, "PUT", "/v1/iam/providers/hanzo/idp", boss,
		`{"owner":"hanzo","name":"idp","type":"SAML","cert":"`+certKid+`"}`); st != 403 {
		t.Fatalf("org admin re-pointing at the platform signing cert: status=%d, want 403", st)
	}
	stored, err := orm.Get[schema.Provider](e.db, "hanzo/idp")
	if err != nil {
		t.Fatalf("load stored: %v", err)
	}
	if stored.Cert != "" {
		t.Fatalf("a refused update set the cert to %q", stored.Cert)
	}
}

// The legitimate writes still pass. An org admin names a cert its OWN org owns; an
// editor that reads a provider and saves it back re-sends the cert it read, and an
// unchanged cert is not a change to authorize.
func TestProvider_allowsOwnCertAndUnchangedRoundTrip(t *testing.T) {
	e := certHarness(t)
	boss := e.token(t, "hanzo/boss")

	if st := e.do(t, "POST", "/v1/iam/providers", boss,
		`{"owner":"hanzo","name":"own","type":"SAML","cert":"cert-tenant"}`); st != 200 {
		t.Fatalf("naming an own-org cert: status=%d, want 200", st)
	}
	if st := e.do(t, "PUT", "/v1/iam/providers/hanzo/own", boss,
		`{"owner":"hanzo","name":"own","type":"SAML","cert":"cert-tenant","displayName":"Our IdP"}`); st != 200 {
		t.Fatalf("saving back the cert it read: status=%d, want 200", st)
	}

	// And a provider a SuperAdmin already pointed at the platform cert keeps saving:
	// the tenant admin re-sends the same value, which is not a change.
	root := e.token(t, "admin/root")
	if st := e.do(t, "POST", "/v1/iam/providers", root,
		`{"owner":"hanzo","name":"platform","type":"SAML","cert":"`+certKid+`"}`); st != 200 {
		t.Fatalf("a SuperAdmin naming the platform cert: status=%d, want 200", st)
	}
	if st := e.do(t, "PUT", "/v1/iam/providers/hanzo/platform", boss,
		`{"owner":"hanzo","name":"platform","type":"SAML","cert":"`+certKid+`","displayName":"Edited"}`); st != 200 {
		t.Fatalf("round-tripping a cert set by a SuperAdmin: status=%d, want 200", st)
	}
}
