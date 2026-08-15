// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

// POST /v1/iam/organizations/avatar is org self-service: whoever administers an
// organization sets how it appears. Nothing about that is reserved to the
// platform, and nothing about it is new authority — the organizations entity
// already answers a write with "does this principal administer this org", so the
// cases below drive the REAL registered router with a REAL bearer to show which
// principals that admits and which it turns away.

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
	signingKid = "cert-hanzo"
	avatarPath = "/v1/iam/organizations/avatar"
	inlinePNG  = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUg=="
)

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
		Path:   filepath.Join(t.TempDir(), "organizations.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	seedCert(t, db, "admin", signingKid, pemOf(t, key))
	seedUser(t, db, "admin", "root", true)    // SuperAdmin (org == admin)
	seedUser(t, db, "hanzo", "boss", true)    // administers hanzo
	seedUser(t, db, "hanzo", "nobody", false) // belongs to hanzo, administers nothing
	seedUser(t, db, "orgb", "bob", true)      // administers a different tenant

	// Every organization row is filed under the admin owner; the org's NAME is
	// the tenant. MasterPassword is seeded because it is what proves this write
	// touches two fields and no others.
	seedOrg(t, db, "hanzo")
	seedOrg(t, db, "orgb")

	app := zip.New(zip.Config{AppName: "organizations-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &harness{app: app, key: key, db: db}
}

// set posts a mark and returns the status and the body VERBATIM.
func (h *harness) set(t *testing.T, sub string, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("POST", avatarPath, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("POST %s: %v", avatarPath, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// stored reads the row back out of the store, past the response envelope.
func (h *harness) stored(t *testing.T, name string) *schema.Organization {
	t.Helper()
	org, err := orm.TypedQuery[schema.Organization](h.db).
		Filter("Owner=", "admin").Filter("Name=", name).First()
	if err != nil {
		t.Fatalf("read %s back: %v", name, err)
	}
	return org
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

// ---- who may set it --------------------------------------------------------

// An organization's own admin sets its mark. This is the whole point: it is
// self-service, decided by administering THAT org, not by membership of the
// reserved admin org.
func TestSetAvatar_orgAdminSetsItsOwnOrg(t *testing.T) {
	h := newHarness(t)

	status, body := h.set(t, "hanzo/boss", `{"owner":"admin","name":"hanzo","emoji":"🦁"}`)
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if got := h.stored(t, "hanzo").Emoji; got != "🦁" {
		t.Fatalf("stored emoji = %q, want 🦁", got)
	}
}

// A SuperAdmin may too — it may do anything — so the org admin case above is a
// widening of who can act, not a replacement.
func TestSetAvatar_superAdmin(t *testing.T) {
	h := newHarness(t)
	if status, body := h.set(t, "admin/root", `{"owner":"admin","name":"hanzo","emoji":"🦁"}`); status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
}

// Belonging to an organization is permission to see it, not to change how it
// appears to everyone else.
func TestSetAvatar_regularMemberRefused(t *testing.T) {
	h := newHarness(t)

	status, body := h.set(t, "hanzo/nobody", `{"owner":"admin","name":"hanzo","emoji":"🦁"}`)
	if status == 200 {
		t.Fatalf("a regular member set an org mark: status=%d body=%s", status, body)
	}
	if got := h.stored(t, "hanzo").Emoji; got != "" {
		t.Fatalf("stored emoji = %q after a refused write, want empty", got)
	}
}

// Administering one tenant is not authority over another. The mark is a tenant's
// own identity everywhere it appears, so this is the boundary that matters.
func TestSetAvatar_foreignOrgAdminRefused(t *testing.T) {
	h := newHarness(t)

	status, body := h.set(t, "orgb/bob", `{"owner":"admin","name":"hanzo","emoji":"🦁"}`)
	if status == 200 {
		t.Fatalf("orgb's admin set hanzo's mark: status=%d body=%s", status, body)
	}
	if got := h.stored(t, "hanzo").Emoji; got != "" {
		t.Fatalf("stored emoji = %q after a refused write, want empty", got)
	}
}

// A request with no bearer never reaches the handler.
func TestSetAvatar_unauthenticated(t *testing.T) {
	h := newHarness(t)
	req := httptest.NewRequest("POST", avatarPath, strings.NewReader(`{"owner":"admin","name":"hanzo","emoji":"🦁"}`))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == 200 {
		t.Fatal("an unauthenticated request set an org mark")
	}
	if got := h.stored(t, "hanzo").Emoji; got != "" {
		t.Fatalf("stored emoji = %q, want empty", got)
	}
}

// ---- what it writes --------------------------------------------------------

// One mark. Setting an image over an emoji leaves the image alone on the row, and
// setting an emoji over an image leaves the emoji alone — in both directions, so
// neither half is a value the other merely shadows.
func TestSetAvatar_isExclusiveInBothDirections(t *testing.T) {
	h := newHarness(t)

	if status, body := h.set(t, "hanzo/boss", `{"owner":"admin","name":"hanzo","emoji":"🦁"}`); status != 200 {
		t.Fatalf("emoji: status=%d body=%s", status, body)
	}
	if status, body := h.set(t, "hanzo/boss", `{"owner":"admin","name":"hanzo","avatar":"`+inlinePNG+`"}`); status != 200 {
		t.Fatalf("image: status=%d body=%s", status, body)
	}
	if org := h.stored(t, "hanzo"); org.Avatar != inlinePNG || org.Emoji != "" {
		t.Fatalf("after an image: avatar=%q emoji=%q, want the image and no emoji", org.Avatar, org.Emoji)
	}

	if status, body := h.set(t, "hanzo/boss", `{"owner":"admin","name":"hanzo","emoji":"⭐"}`); status != 200 {
		t.Fatalf("emoji again: status=%d body=%s", status, body)
	}
	if org := h.stored(t, "hanzo"); org.Emoji != "⭐" || org.Avatar != "" {
		t.Fatalf("after an emoji: avatar=%q emoji=%q, want the emoji and no image", org.Avatar, org.Emoji)
	}

	if status, body := h.set(t, "hanzo/boss", `{"owner":"admin","name":"hanzo"}`); status != 200 {
		t.Fatalf("clear: status=%d body=%s", status, body)
	}
	if org := h.stored(t, "hanzo"); org.Avatar != "" || org.Emoji != "" {
		t.Fatalf("after clearing: avatar=%q emoji=%q, want both empty", org.Avatar, org.Emoji)
	}
}

// A request carrying BOTH halves still leaves one on the row. This is the case a
// client actually produces — an editor holding a previously chosen emoji while
// somebody drops an image on it — and it is decided at the write so that no
// reader downstream ever holds two answers and has to rank them.
func TestSetAvatar_bothInOneRequestStoresTheImage(t *testing.T) {
	h := newHarness(t)

	status, body := h.set(t, "hanzo/boss",
		`{"owner":"admin","name":"hanzo","avatar":"`+inlinePNG+`","emoji":"🦁"}`)
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if org := h.stored(t, "hanzo"); org.Avatar != inlinePNG || org.Emoji != "" {
		t.Fatalf("avatar=%q emoji=%q, want the image alone", org.Avatar, org.Emoji)
	}
}

// It writes two fields onto the stored row and touches nothing else.
//
// This is why it is its own operation rather than a field on update. update
// REPLACES the record, and a record read back first arrives masked, so a client
// that read an org and posted it back with one field changed would persist "***"
// over the organization's own credential settings. Here the mark is applied to
// the row as it stands, so no other column can be carried in or out on this
// request.
func TestSetAvatar_touchesNothingElse(t *testing.T) {
	h := newHarness(t)
	before := h.stored(t, "hanzo")

	if status, body := h.set(t, "hanzo/boss", `{"owner":"admin","name":"hanzo","emoji":"🦁"}`); status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}

	after := h.stored(t, "hanzo")
	if after.MasterPassword != before.MasterPassword {
		t.Fatalf("masterPassword became %q, want it untouched at %q", after.MasterPassword, before.MasterPassword)
	}
	if after.DisplayName != before.DisplayName || after.Logo != before.Logo {
		t.Fatalf("displayName/logo moved: %q/%q, want %q/%q",
			after.DisplayName, after.Logo, before.DisplayName, before.Logo)
	}
	if after.PasswordType != before.PasswordType || after.CreatedTime != before.CreatedTime {
		t.Fatalf("passwordType/createdTime moved")
	}
}

// The answer is the same masked row every other organization read returns: the
// caller reads its new mark straight off it, and no secret rides along.
//
// The mask is also why this operation exists. `masterPassword` comes back "***",
// so a client that read an organization, changed one field and posted the whole
// record to update would write the mask over the real value.
func TestSetAvatar_answerIsTheMaskedRow(t *testing.T) {
	h := newHarness(t)

	status, body := h.set(t, "hanzo/boss", `{"owner":"admin","name":"hanzo","emoji":"🦁"}`)
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if strings.Contains(body, "hunter2") {
		t.Fatalf("the answer carried the master password: %s", body)
	}
	var got schema.Organization
	if err := json.Unmarshal([]byte(body), &got); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if got.Emoji != "🦁" {
		t.Fatalf("answered emoji = %q, want 🦁 — the caller reads the new mark off the answer", got.Emoji)
	}
	if got.MasterPassword != "***" {
		t.Fatalf("answered masterPassword = %q, want it masked", got.MasterPassword)
	}
}

// A value the row may not hold is refused, and the row is left as it was.
func TestSetAvatar_refusals(t *testing.T) {
	h := newHarness(t)

	for _, c := range []struct{ name, body string }{
		{"a script url", `{"owner":"admin","name":"hanzo","avatar":"javascript:alert(1)"}`},
		{"an svg", `{"owner":"admin","name":"hanzo","avatar":"data:image/svg+xml;base64,PHN2Zz4="}`},
		{"prose in the emoji", `{"owner":"admin","name":"hanzo","emoji":"hanzo"}`},
		{"two emoji", `{"owner":"admin","name":"hanzo","emoji":"🦁🐯"}`},
		{"no organization", `{"emoji":"🦁"}`},
	} {
		t.Run(c.name, func(t *testing.T) {
			if status, body := h.set(t, "hanzo/boss", c.body); status == 200 {
				t.Fatalf("accepted %s: status=%d body=%s", c.name, status, body)
			}
			if org := h.stored(t, "hanzo"); org.Avatar != "" || org.Emoji != "" {
				t.Fatalf("a refused write left avatar=%q emoji=%q", org.Avatar, org.Emoji)
			}
		})
	}

	if status, body := h.set(t, "hanzo/boss", `{"owner":"admin","name":"nosuchorg","emoji":"🦁"}`); status == 200 {
		t.Fatalf("an organization that does not exist answered 200: %s", body)
	}
}

// ---- seeds -----------------------------------------------------------------

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
	o.Logo = "https://s3.hanzo.ai/logos/" + name + ".svg"
	o.MasterPassword = "hunter2"
	o.PasswordType = "bcrypt"
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
