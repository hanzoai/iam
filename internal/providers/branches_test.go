// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package providers_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"path/filepath"
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

// addProvider takes the (owner, name) from the body, so a body missing either
// half is the one that reaches the 400. The path-addressed ops cannot: their key
// rides in the URL and the route only matches with both segments present.
func TestAddProviderRejectsMissingKey(t *testing.T) {
	app := boot(t)
	cases := []struct {
		name string
		body string
	}{
		{"no owner", `{"name":"github","type":"GitHub"}`},
		{"no name", `{"owner":"acme","type":"GitHub"}`},
		{"neither", `{"type":"GitHub"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := call(t, app, "POST", "/v1/iam/providers", tc.body); code != http.StatusBadRequest {
				t.Fatalf("want 400, got %d", code)
			}
		})
	}
}

// A write against a row that is not there answers "nothing changed" rather than
// an error, so the call is safe to repeat.
func TestUpdateAndDeleteMissingRowAreNoOps(t *testing.T) {
	app := boot(t)
	cases := []struct {
		method, path, body string
	}{
		{"PUT", "/v1/iam/providers/ghost/none", `{"displayName":"x"}`},
		{"DELETE", "/v1/iam/providers/ghost/none", ""},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			code, out := call(t, app, tc.method, tc.path, tc.body)
			if code != http.StatusOK || out["affected"] != false {
				t.Fatalf("want 200 affected=false, got %d %v", code, out)
			}
		})
	}
}

// listProviders scopes to the caller's org, so with no principal on the context
// authz.Scope fails closed — the one op the unauthenticated router refuses.
func TestListWithoutPrincipalIsForbidden(t *testing.T) {
	app := boot(t)
	if code, _ := call(t, app, "GET", "/v1/iam/providers", ""); code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", code)
	}
}

// Every op turns a store error into a 500. Closing the store under a built router
// makes each first orm call fail, which is the arm a not-found or a bad-request
// never reaches.
func TestStoreErrorsAre500(t *testing.T) {
	app, db := bootDB(t)
	_ = db.Close() // handlers now run against a closed store

	cases := []struct {
		method, path, body string
	}{
		{"GET", "/v1/iam/providers/acme/github", ""},
		{"POST", "/v1/iam/providers", `{"owner":"acme","name":"github","type":"GitHub"}`},
		{"PUT", "/v1/iam/providers/acme/github", `{"displayName":"x"}`},
		{"DELETE", "/v1/iam/providers/acme/github", ""},
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			if code, _ := call(t, app, tc.method, tc.path, tc.body); code != http.StatusInternalServerError {
				t.Fatalf("want 500, got %d", code)
			}
		})
	}
}

// A SuperAdmin bearer is the credential that carries the list past the Guard and
// lets authz.Scope resolve a real owner, so the collection read, its owner filter
// and the credential masking all run. The token is a genuine RS256 JWT the
// Guard's own oidc.VerifyToken accepts: signed by an admin-owned signing cert,
// subject a user in the reserved "admin" org, which membership IS SuperAdmin.
func TestListAsSuperAdmin(t *testing.T) {
	app, tok := guardedList(t)

	code, out := callAuth(t, app, "GET", "/v1/iam/providers", tok)
	if code != http.StatusOK {
		t.Fatalf("list: %d %v", code, out)
	}
	all, _ := out["providers"].([]any)
	if len(all) != 2 {
		t.Fatalf("superuser view should span every tenant, got %v", all)
	}

	code, out = callAuth(t, app, "GET", "/v1/iam/providers?owner=acme", tok)
	if code != http.StatusOK {
		t.Fatalf("filtered list: %d %v", code, out)
	}
	one, _ := out["providers"].([]any)
	if len(one) != 1 {
		t.Fatalf("owner filter should pin to one tenant, got %v", one)
	}
	if row := one[0].(map[string]any); row["owner"] != "acme" {
		t.Fatalf("filter returned the wrong tenant: %v", row["owner"])
	}
}

const listKid = "cert-hanzo" // the admin signing cert's name = JWKS kid

// guardedList builds the authed surface the way routes.Route does — the Guard on
// the group, providers on the group — plus the trust anchor a bearer needs, two
// providers across tenants, and a SuperAdmin token to read them with.
func guardedList(t *testing.T) (*zip.App, string) {
	t.Helper()
	_ = schema.Kinds()
	ctx := context.Background()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "g.db"),
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
	// The signing cert the verifier trusts. The row carries no key material; the
	// deployment supplies it through the keyring, keyed by the cert's name.
	keyring.Set(listKid, string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	})))
	cert := orm.New[schema.Cert](db)
	cert.Owner, cert.Name, cert.CryptoAlgorithm = "admin", listKid, "RS256"
	cert.SetId("admin/" + listKid)
	if err := cert.CreateCtx(ctx); err != nil {
		t.Fatalf("seed cert: %v", err)
	}

	root := orm.New[schema.User](db)
	root.Owner, root.Name = "admin", "root"
	root.SetId("admin/root")
	if err := root.CreateCtx(ctx); err != nil {
		t.Fatalf("seed user: %v", err)
	}

	seedProvider(t, db, "acme", "github")
	seedProvider(t, db, "beta", "google")

	app := zip.New(zip.Config{AppName: "g", DisableStartupMessage: true})
	authed := app.Group("").(*zip.App)
	authed.Use(authz.Guard(db))
	providers.Route(authed, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": "admin/root",
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = listKid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return app, signed
}

func seedProvider(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	p := orm.New[schema.Provider](db)
	p.Owner, p.Name, p.Type = owner, name, "GitHub"
	p.SetId(owner + "/" + name)
	if err := p.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed provider %s/%s: %v", owner, name, err)
	}
}

func callAuth(t *testing.T, app *zip.App, method, path, bearer string) (int, map[string]any) {
	t.Helper()
	r, _ := http.NewRequest(method, path, nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	res, err := testhttp.Do(app, r)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}
