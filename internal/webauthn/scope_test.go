// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package webauthn_test

// A passkey list is a list of somebody's CREDENTIALS. Which rows come back is
// decided here, on the server, from the caller — never by the page that renders
// them. A client that filters a wider answer down to the caller has not been
// authorized, it has been trusted to look away.

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

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/internal/routes"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const (
	kid  = "cert-hanzo"
	keys = "/v1/iam/webauthn-credentials"
)

type rig struct {
	app *zip.App
	key *rsa.PrivateKey
	db  orm.DB
}

func newRig(t *testing.T) *rig {
	t.Helper()
	_ = schema.Kinds()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "webauthn.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, store.AdminOrg, kid, pemOf(t, key))
	seedUser(t, db, "hanzo", "boss", true)   // administers hanzo
	seedUser(t, db, "hanzo", "alice", false) // a plain member
	seedUser(t, db, "hanzo", "bob", false)   // another plain member
	seedUser(t, db, "orgb", "carol", true)   // a different tenant
	seedUser(t, db, store.AdminOrg, "z", false)

	seedKey(t, db, "hanzo", "alice-laptop", "hanzo/alice")
	seedKey(t, db, "hanzo", "alice-phone", "hanzo/alice")
	seedKey(t, db, "hanzo", "bob-yubikey", "hanzo/bob")
	seedKey(t, db, "hanzo", "boss-laptop", "hanzo/boss")
	seedKey(t, db, "orgb", "carol-laptop", "orgb/carol")

	app := zip.New(zip.Config{AppName: "webauthn-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &rig{app: app, key: key, db: db}
}

// list drives one read and returns the status plus the credential names.
func (r *rig) list(t *testing.T, sub, query string) (int, []string, string) {
	t.Helper()
	req := httptest.NewRequest("GET", keys+query, nil)
	req.Host = "hanzo.id"
	req.Header.Set("Authorization", "Bearer "+r.bearer(t, sub))
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var out struct {
		WebauthnCredentials []struct {
			Name string `json:"name"`
			User string `json:"user"`
		} `json:"webauthnCredentials"`
	}
	names := []string{}
	if resp.StatusCode == 200 {
		if err := json.Unmarshal(b, &out); err != nil {
			t.Fatalf("decode %s: %v", b, err)
		}
		for _, c := range out.WebauthnCredentials {
			names = append(names, c.Name)
		}
	}
	return resp.StatusCode, names, string(b)
}

func (r *rig) bearer(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub,
		"iat": time.Now().Add(-time.Minute).Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	tok.Header["kid"] = kid
	s, err := tok.SignedString(r.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

func same(got []string, want ...string) bool {
	if len(got) != len(want) {
		return false
	}
	seen := map[string]bool{}
	for _, g := range got {
		seen[g] = true
	}
	for _, w := range want {
		if !seen[w] {
			return false
		}
	}
	return true
}

// A plain member gets THEIR OWN passkeys and nobody else's. This is the whole
// point: the answer is scoped where it is produced.
func TestList_aMemberSeesOnlyTheirOwn(t *testing.T) {
	r := newRig(t)

	status, got, body := r.list(t, "hanzo/alice", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if !same(got, "alice-laptop", "alice-phone") {
		t.Fatalf("alice got %v, want only her own two", got)
	}
	for _, leak := range []string{"bob-yubikey", "boss-laptop", "carol-laptop"} {
		if strings.Contains(body, leak) {
			t.Fatalf("the answer carried %s: %s", leak, body)
		}
	}
}

// Naming somebody else does not produce them. The caller decides nothing about
// scope.
func TestList_aMemberCannotNameAnother(t *testing.T) {
	r := newRig(t)

	_, got, body := r.list(t, "hanzo/alice", "?user=hanzo/bob")
	if strings.Contains(body, "bob-yubikey") {
		t.Fatalf("alice read bob's passkeys by naming him: %s", body)
	}
	if len(got) > 0 && !same(got, "alice-laptop", "alice-phone") {
		t.Fatalf("alice got %v, want her own or nothing", got)
	}
}

// An org's admin may read a member of their own org — that is the support path,
// and it is the same authority that already governs reading the user's record.
func TestList_anOrgAdminMayNameTheirOwnMember(t *testing.T) {
	r := newRig(t)

	status, got, body := r.list(t, "hanzo/boss", "?user=hanzo/alice")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if !same(got, "alice-laptop", "alice-phone") {
		t.Fatalf("boss got %v for alice, want her two", got)
	}
}

// ...and no further. A tenant's admin is not an authority in another tenant.
func TestList_anOrgAdminCannotReachAnotherTenant(t *testing.T) {
	r := newRig(t)

	_, _, body := r.list(t, "hanzo/boss", "?user=orgb/carol")
	if strings.Contains(body, "carol-laptop") {
		t.Fatalf("hanzo's admin read orgb's passkeys: %s", body)
	}
}

// An admin asking for nobody in particular gets their OWN, not the org's. A
// directory of everybody's credentials has no reader; the one screen that asked
// for this list filtered it down to the caller in the browser.
func TestList_anAdminDefaultsToTheirOwn(t *testing.T) {
	r := newRig(t)

	status, got, body := r.list(t, "hanzo/boss", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if !same(got, "boss-laptop") {
		t.Fatalf("boss got %v, want only their own", got)
	}
}

// No bearer, no list.
func TestList_unauthenticated(t *testing.T) {
	r := newRig(t)
	req := httptest.NewRequest("GET", keys, nil)
	req.Host = "hanzo.id"
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatalf("an unauthenticated request listed passkeys: %s", b)
	}
}

// ---- seeds ---------------------------------------------------------------

// seedCert files a certificate row and stages its key the way a deployment
// supplies one: the row is identity only, so the process signs with this key
// only because the ring holds it under the cert's name.
//
// Staged only for a reserved signing owner, which is the case under test rather
// than test bookkeeping: material is addressed by name because the name is the
// `kid`, so staging a tenant cert's key would hand it to the platform cert of the
// same name.
func seedCert(t *testing.T, db orm.DB, owner, name, privPEM string) {
	t.Helper()
	if store.IsSigningCertOwner(owner) {
		keyring.Set(name, privPEM)
		t.Cleanup(func() { keyring.Forget(name) })
	}
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	c.CryptoAlgorithm = "RS256"
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

func seedKey(t *testing.T, db orm.DB, owner, name, user string) {
	t.Helper()
	c := orm.New[schema.WebauthnCredential](db)
	c.Owner, c.Name, c.User = owner, name, user
	c.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
}

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}
