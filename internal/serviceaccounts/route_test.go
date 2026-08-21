// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package serviceaccounts_test

// GET /v1/iam/service-accounts is a TYPED op, and a typed op reaches two seams a
// raw handler never did: zip's query binder, and the op-invoke authorizer
// (authz.Authorize). Both are silent when they work and fatal when they do not —
// a binder that missed ?organization= answers "organization is required", an
// authorizer that saw a target answers 403 — so every case here is a real request
// through the REAL registered router (routes.Route mounts the Guard, then this
// surface on the group carrying Authorize), asserted on the RAW BODY BYTES.
//
// The bytes are the point. This conversion is a projection, not a change: the same
// address, the same status, the same envelope, before and after.

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

const signingKid = "cert-hanzo"

const path = "/v1/iam/service-accounts"

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
		Path:   filepath.Join(t.TempDir(), "serviceaccounts.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, "admin", signingKid, pemOf(t, key))
	seedUser(t, db, "admin", "root", true, "") // SuperAdmin (org == admin)
	seedUser(t, db, "hanzo", "boss", true, "") // org-admin of hanzo
	seedUser(t, db, "orgb", "bob", true, "")   // org-admin of a second tenant
	// Two bots in hanzo, so a page of one is provably a PAGE and data2 is
	// provably the total rather than the page length.
	seedUser(t, db, "hanzo", "hanzo-alpha", false, "service-account")
	seedUser(t, db, "hanzo", "hanzo-beta", false, "service-account")

	app := zip.New(zip.Config{AppName: "serviceaccounts-test", DisableStartupMessage: true})
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

// get drives one read and returns the status and the body VERBATIM.
func (h *harness) get(t *testing.T, url, bearer string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", url, nil)
	req.Host = "hanzo.id"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// ---- cases -----------------------------------------------------------------

// The success envelope, byte for byte: 200 {status:"ok", msg:"", data:[…],
// data2:<TOTAL>}. data2 is the total and not the page length, which is the one
// thing a caller paging through this list depends on.
func TestList_ok(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	status, body := h.get(t, path+"?organization=hanzo", boss)
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if !strings.HasPrefix(body, `{"status":"ok","msg":"","data":[`) || !strings.HasSuffix(body, `],"data2":2}`) {
		t.Fatalf("body=%s, want the v1 envelope with data2=2", body)
	}
	if n := strings.Count(body, `"name":"hanzo-`); n != 2 {
		t.Fatalf("body carries %d bots, want 2: %s", n, body)
	}
	// A secret never leaves, not even as a digest.
	for _, leak := range []string{"accessSecret", "accessSecretHash", "passwordHash", "passwordSalt"} {
		if strings.Contains(body, `"`+leak+`":"`) {
			t.Fatalf("the list leaked %s: %s", leak, body)
		}
	}
}

// Paging binds off the query string, and the TOTAL is unaffected by it.
func TestList_pages(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	status, body := h.get(t, path+"?organization=hanzo&p=2&pageSize=1", boss)
	if status != 200 || !strings.HasSuffix(body, `],"data2":2}`) {
		t.Fatalf("page 2 status=%d body=%s, want 200 with data2=2", status, body)
	}
	if n := strings.Count(body, `"name":"hanzo-`); n != 1 {
		t.Fatalf("page of 1 carried %d rows: %s", n, body)
	}
	if !strings.Contains(body, `"name":"hanzo-beta"`) {
		t.Fatalf("page 2 of size 1 is the SECOND row by name: %s", body)
	}
	// A paging value that is not a number is "unset" — the whole list, exactly as
	// the hand-rolled parser this replaced answered. zip's binder leaves an int
	// field at its zero value when the query value will not parse.
	_, all := h.get(t, path+"?organization=hanzo&p=abc&pageSize=xyz", boss)
	if n := strings.Count(all, `"name":"hanzo-`); n != 2 {
		t.Fatalf("unparseable paging must return everything, got %d rows: %s", n, all)
	}
}

// The refusals, byte for byte: 400 carrying {status:"error", msg, data:null}.
func TestList_refusals(t *testing.T) {
	h := newHarness(t)
	for _, c := range []struct{ name, url, sub, want string }{
		{"no organization", path, "hanzo/boss",
			`{"status":"error","msg":"organization is required","data":null}`},
		{"cross-tenant", path + "?organization=orgb", "hanzo/boss",
			`{"status":"error","msg":"auth:Unauthorized operation","data":null}`},
		{"regular user", path + "?organization=hanzo", "hanzo/nobody",
			`{"status":"error","msg":"auth:Unauthorized operation","data":null}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			status, body := h.get(t, c.url, h.token(t, c.sub))
			if status != 400 || body != c.want {
				t.Fatalf("status=%d body=%s, want 400 %s", status, body, c.want)
			}
		})
	}
}

// The op-invoke authorizer admits this read because its input names no owner —
// `query` declares no Owner field and no AuthzTarget(). An unknown query key is
// therefore just an unknown query key: it is ignored by the binder and can never
// become the target the authorizer decides on. Give the input an Owner field and
// this is a 403, which is why the case is here rather than in a comment.
func TestList_ownerQueryIsNotATarget(t *testing.T) {
	h := newHarness(t)
	status, body := h.get(t, path+"?organization=hanzo&owner=orgb&name=whatever", h.token(t, "hanzo/boss"))
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200 — the read is authorized by read(), not by ?owner=", status, body)
	}
}

// Still gated: no bearer, no list.
func TestList_requiresAuth(t *testing.T) {
	h := newHarness(t)
	if status, body := h.get(t, path+"?organization=hanzo", ""); status != 401 {
		t.Fatalf("unauthenticated status=%d body=%s, want 401", status, body)
	}
}

// ---- helpers ---------------------------------------------------------------

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

func seedUser(t *testing.T, db orm.DB, owner, name string, admin bool, kind string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.IsAdmin = admin
	u.Type = kind
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

// send drives one write with a body and returns the status and the body VERBATIM.
func (h *harness) send(t *testing.T, method, url, body, bearer string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// Rotate and revoke take the organization from the BODY as well as the query.
//
// This is what makes them callable from a generated client at all. Both are raw
// handlers, so the organization they read never reaches this service's OpenAPI —
// only a TYPED handler's input struct becomes a documented parameter — and a
// client built from that document has no flag to send it with. The call then
// fails "organization and name are required" with no way for the caller to
// answer. `create` takes the org in its body and has always worked for exactly
// that reason; these two now agree with it.
func TestRotate_organizationFromBody(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	status, body := h.send(t, "POST", path+"/hanzo-alpha/keys", `{"organization":"hanzo"}`, boss)
	if status != 200 {
		t.Fatalf("rotate with org in body: status %d, body %s", status, body)
	}
	// The secret is minted and returned exactly once, so its presence is the
	// proof the handler ran rather than refused.
	if !strings.Contains(body, "accessSecret") {
		t.Fatalf("rotate answered without a secret: %s", body)
	}
}

// The query form still works, unchanged. The body is read ONLY when the query is
// absent, so nothing that called this before can start behaving differently.
func TestRotate_queryStillWins(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	status, body := h.send(t, "POST", path+"/hanzo-beta/keys?organization=hanzo", "", boss)
	if status != 200 {
		t.Fatalf("rotate with org in query: status %d, body %s", status, body)
	}
	if !strings.Contains(body, "accessSecret") {
		t.Fatalf("rotate answered without a secret: %s", body)
	}
}

// Neither form supplied is still a refusal, and it still says which two things
// it wanted.
func TestRotate_noOrganizationAnywhere(t *testing.T) {
	h := newHarness(t)
	status, body := h.send(t, "POST", path+"/hanzo-alpha/keys", `{}`, h.token(t, "hanzo/boss"))
	if status == 200 {
		t.Fatalf("rotate succeeded with no organization: %s", body)
	}
	if !strings.Contains(body, "organization and name are required") {
		t.Fatalf("unexpected refusal: %d %s", status, body)
	}
}

// A body that is not JSON is not an error of its own: the caller is simply one
// that supplied no organization, and gets the same refusal.
func TestRotate_malformedBodyIsJustNoOrganization(t *testing.T) {
	h := newHarness(t)
	status, body := h.send(t, "POST", path+"/hanzo-alpha/keys", `not json`, h.token(t, "hanzo/boss"))
	if status == 200 {
		t.Fatalf("rotate succeeded on a malformed body: %s", body)
	}
	if !strings.Contains(body, "organization and name are required") {
		t.Fatalf("unexpected refusal: %d %s", status, body)
	}
}

// The org in the body is a TARGET, not an authority: a tenant admin naming
// another tenant is still refused. The body must not become a way around the
// admin gate that the query form is held to.
func TestRotate_bodyOrganizationIsNotAnAuthority(t *testing.T) {
	h := newHarness(t)
	status, body := h.send(t, "POST", path+"/hanzo-alpha/keys", `{"organization":"hanzo"}`, h.token(t, "orgb/bob"))
	if status == 200 {
		t.Fatalf("cross-tenant rotate succeeded: %s", body)
	}
}
