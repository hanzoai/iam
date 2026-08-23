// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// The harness every test in this package drives: the REAL registered router,
// built by routes.Route, with the Guard between the public group and the gated
// routes. Tokens are genuine RS256 bearers signed by a seeded admin signing cert,
// so they pass the same verification a live request does — nothing here is
// mocked.
//
// It lives at this level because the subjects do. A key endpoint reads the Principal
// the Guard attached, so it has no behaviour at all outside a mounted router; a
// retired address is only public because of WHERE it is registered. Testing
// either one against a bare handler would prove nothing about the service.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// signingKid is the seeded admin signing cert's name, which is the JWKS kid.
const signingKid = "cert-hanzo"

// secretUserHash is a distinctive sentinel stamped on every seeded user's
// password digest: if it appears in any response body, redaction failed.
const secretUserHash = "$argon2id$SENTINEL_USER_PW_HASH"

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
		Path:   filepath.Join(t.TempDir(), "routes.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Trust anchor: the admin-owned RS256 signing cert whose name is the JWKS kid.
	seedCert(t, db, "admin", signingKid, pemOf(t, key))

	// One principal per scope, across two tenants.
	seedUser(t, db, "admin", "root", true)   // SuperAdmin (org == admin)
	seedUser(t, db, "hanzo", "boss", true)   // org-admin of hanzo
	seedUser(t, db, "hanzo", "alice", false) // regular user in hanzo
	seedUser(t, db, "orgb", "bob", true)     // org-admin of a second tenant

	app := zip.New(zip.Config{AppName: "routes-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &harness{app: app, key: key, db: db}
}

// token signs an RS256 bearer for subject `sub` ("owner/name") under the trusted
// kid — the exact shape a real token carries.
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

// get issues a GET as a signed-in person and returns (status, body).
func (h *harness) get(t *testing.T, path, bearer string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	return h.do(t, req)
}

// getBasic issues a GET as a confidential client (client_secret_basic) — how a
// service authenticates to the key endpoints.
func (h *harness) getBasic(t *testing.T, path, clientID, secret string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	req.SetBasicAuth(clientID, secret)
	return h.do(t, req)
}

// do drives one request through the built router and returns (status, body).
func (h *harness) do(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// ---- seed helpers ----------------------------------------------------------

func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	c.CryptoAlgorithm = "RS256"
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
	u.PasswordHash = secretUserHash
	u.PasswordType = "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
}

// seedUserEmail is seedUser plus the address, stored the way every write path
// stores one — normalized — so a read is matching what a real row holds.
func seedUserEmail(t *testing.T, h *harness, owner, name, email string) {
	t.Helper()
	u := orm.New[schema.User](h.db)
	u.Owner, u.Name = owner, name
	u.Email = store.NormalizeEmail(email)
	u.PasswordHash = secretUserHash
	u.PasswordType = "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

// seedClientApp registers an admin-owned confidential client, so a capability
// pinned to a reserved signing owner can be held.
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
