// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc_test

// Stepping into an organization is a privileged act, so every case here drives
// the REAL registered router with a REAL signed bearer and then reads the token
// that comes back. Two things are asserted of every answer: who the token says
// it is (always the operator, never the tenant), and which organizations it can
// reach.

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
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const (
	kid      = "cert-hanzo"
	clientID = "hanzo-console"
	assume   = "/v1/iam/assume"
	release  = "/v1/iam/release"
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
		Path:   filepath.Join(t.TempDir(), "masquerade.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, store.AdminOrg, kid, pemOf(t, key))
	seedApp(t, db, store.AdminOrg, "console", clientID, kid)
	seedUser(t, db, store.AdminOrg, "z", false) // the operator: reserved org IS SuperAdmin
	seedUser(t, db, "hanzo", "boss", true)      // administers hanzo, and nothing else
	seedUser(t, db, "hanzo", "nobody", false)   // administers nothing
	seedOrg(t, db, "hanzo")
	seedOrg(t, db, "acme")

	app := zip.New(zip.Config{AppName: "masquerade-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &rig{app: app, key: key, db: db}
}

// post drives one act and returns the status and the body VERBATIM.
func (r *rig) post(t *testing.T, path, sub, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+r.bearer(t, sub))
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// bearer signs an access token for sub, naming the console as the party it was
// issued to — the application the re-scoped token is minted under.
func (r *rig) bearer(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sub,
		"azp": clientID,
		"aud": clientID,
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

// answered decodes the envelope and the token inside it, and returns the claims
// the token actually carries.
func answered(t *testing.T, body string) (string, map[string]any) {
	t.Helper()
	var env struct {
		Status string `json:"status"`
		Data   struct {
			AccessToken string `json:"accessToken"`
			Assumed     string `json:"assumed"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &env); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if env.Data.AccessToken == "" {
		t.Fatalf("no token in %s", body)
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(env.Data.AccessToken, claims); err != nil {
		t.Fatalf("parse minted token: %v", err)
	}
	return env.Data.Assumed, claims
}

// orgsIn lists the organizations a token's `orgs` claim reaches.
func orgsIn(claims map[string]any) []string {
	raw, _ := claims["orgs"].([]any)
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		if m, ok := r.(map[string]any); ok {
			if s, ok := m["org"].(string); ok {
				out = append(out, s)
			}
		}
	}
	return out
}

func has(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// ---- who may -------------------------------------------------------------

// An operator steps in, and the token that comes back is still theirs. This is
// the whole design: the tenant becomes reachable, the actor does not change.
func TestAssume_operatorKeepsTheirOwnIdentity(t *testing.T) {
	r := newRig(t)

	status, body := r.post(t, assume, "admin/z", `{"org":"acme"}`)
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	org, claims := answered(t, body)
	if org != "acme" {
		t.Fatalf("answered assumed=%q, want acme", org)
	}
	if claims["assumed"] != "acme" {
		t.Fatalf("token assumed=%v, want acme", claims["assumed"])
	}
	if claims["name"] != "z" || claims["owner"] != store.AdminOrg {
		t.Fatalf("token names %v/%v, want admin/z — the operator is never replaced",
			claims["owner"], claims["name"])
	}
	if !has(orgsIn(claims), "acme") {
		t.Fatalf("orgs=%v, want acme among them — the tenant is reached through the org switch",
			orgsIn(claims))
	}
}

// An org admin administers ONE organization. Reading that flag here would let
// the admin of any tenant step into every other, which is the escalation this
// endpoint would otherwise be.
func TestAssume_orgAdminRefused(t *testing.T) {
	r := newRig(t)

	status, body := r.post(t, assume, "hanzo/boss", `{"org":"acme"}`)
	if status == 200 {
		t.Fatalf("an org admin stepped into another tenant: %s", body)
	}
	if status != 403 {
		t.Fatalf("status=%d, want 403: %s", status, body)
	}
}

// A regular member likewise.
func TestAssume_regularUserRefused(t *testing.T) {
	r := newRig(t)
	if status, body := r.post(t, assume, "hanzo/nobody", `{"org":"acme"}`); status != 403 {
		t.Fatalf("status=%d, want 403: %s", status, body)
	}
}

// No credential, no act.
func TestAssume_unauthenticated(t *testing.T) {
	r := newRig(t)
	req := httptest.NewRequest("POST", assume, strings.NewReader(`{"org":"acme"}`))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	resp, err := testhttp.Do(r.app, req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("an unauthenticated request stepped into a tenant")
	}
}

// ---- what it will step into ----------------------------------------------

func TestAssume_refusals(t *testing.T) {
	r := newRig(t)
	for _, c := range []struct {
		name, body string
		want       int
	}{
		{"an organization that does not exist", `{"org":"nosuchorg"}`, 404},
		{"a platform organization", `{"org":"admin"}`, 400},
		{"no organization named", `{}`, 400},
	} {
		t.Run(c.name, func(t *testing.T) {
			if status, body := r.post(t, assume, "admin/z", c.body); status != c.want {
				t.Fatalf("status=%d, want %d: %s", status, c.want, body)
			}
		})
	}
}

// ---- stepping back out ----------------------------------------------------

// Release returns the operator's ordinary credential: nothing assumed, and the
// tenant no longer reachable through it.
func TestRelease_dropsTheTenant(t *testing.T) {
	r := newRig(t)

	if status, body := r.post(t, assume, "admin/z", `{"org":"acme"}`); status != 200 {
		t.Fatalf("assume: status=%d body=%s", status, body)
	}
	status, body := r.post(t, release, "admin/z", `{}`)
	if status != 200 {
		t.Fatalf("release: status=%d body=%s, want 200", status, body)
	}
	org, claims := answered(t, body)
	if org != "" {
		t.Fatalf("answered assumed=%q, want empty", org)
	}
	if _, present := claims["assumed"]; present {
		t.Fatalf("released token still carries assumed=%v", claims["assumed"])
	}
	if has(orgsIn(claims), "acme") {
		t.Fatalf("orgs=%v still reaches acme after stepping out", orgsIn(claims))
	}
}

// ---- the trail ------------------------------------------------------------

// Every privileged act is recorded, and so is every refusal — an attempt to
// step into a tenant by somebody who may not is the row an auditor most wants.
// The row names the REAL actor, the organization, the time and the address.
func TestAssume_isRecorded(t *testing.T) {
	r := newRig(t)

	r.post(t, assume, "admin/z", `{"org":"acme"}`)
	r.post(t, release, "admin/z", `{}`)
	r.post(t, assume, "hanzo/boss", `{"org":"acme"}`) // refused

	rows, err := orm.TypedQuery[schema.AuditLog](r.db).GetAll(context.Background())
	if err != nil {
		t.Fatalf("read the trail: %v", err)
	}
	seen := map[string]*schema.AuditLog{}
	for _, row := range rows {
		seen[row.Action+"/"+row.User] = row
	}

	in := seen[schema.ActionAssumeOrg+"/admin/z"]
	if in == nil {
		t.Fatalf("the step in was not recorded: %+v", seen)
	}
	if in.Organization != "acme" || in.StatusCode != 200 {
		t.Fatalf("step in recorded org=%q status=%d, want acme/200", in.Organization, in.StatusCode)
	}
	if in.ClientIp != "203.0.113.7" {
		t.Fatalf("step in recorded no address (%q) — a record that cannot say where is half a record", in.ClientIp)
	}
	if in.Owner != "acme" {
		t.Fatalf("step in filed under %q, want acme so the tenant sees who was in it", in.Owner)
	}
	if in.CreatedTime == "" {
		t.Fatal("step in recorded no time")
	}

	if out := seen[schema.ActionReleaseOrg+"/admin/z"]; out == nil {
		t.Fatalf("the step out was not recorded: %+v", seen)
	}
	refused := seen[schema.ActionAssumeOrg+"/hanzo/boss"]
	if refused == nil {
		t.Fatalf("the refusal was not recorded: %+v", seen)
	}
	if refused.StatusCode != 403 {
		t.Fatalf("refusal recorded status=%d, want 403", refused.StatusCode)
	}
}

// The trail is the platform's own record, so the generic audit-log CRUD cannot
// create, alter or remove one — otherwise the org admin whose act it records
// could trim it.
func TestAssume_trailIsReserved(t *testing.T) {
	for _, action := range []string{schema.ActionAssumeOrg, schema.ActionReleaseOrg} {
		if !schema.PlatformWritten(action) {
			t.Fatalf("%s must be a reserved action, or the trail can be forged", action)
		}
	}
}

// ---- seeds ---------------------------------------------------------------

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

func seedApp(t *testing.T, db orm.DB, owner, name, client, cert string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name = owner, name
	a.ClientId = client
	a.Cert = cert
	a.Organization = owner
	a.SetId(owner + "/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app: %v", err)
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

func seedOrg(t *testing.T, db orm.DB, name string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = store.AdminOrg, name
	o.DisplayName = strings.ToUpper(name[:1]) + name[1:]
	o.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	o.SetId(store.AdminOrg + "/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
}

func pemOf(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	return string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k),
	}))
}
