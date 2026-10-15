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
	db  orm.DB
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
	seedUser(t, db, "acme", "boss", true)  // org-admin of a customer tenant

	app := zip.New(zip.Config{AppName: "apporg-test", DisableStartupMessage: true})
	routes.Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
	return &orgHarness{app: app, key: key, db: db}
}

func (h *orgHarness) token(t *testing.T, sub string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"tokenType": "access-token", "iss": "https://hanzo.id", "aud": "hanzo-test",
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

// An account records the application that registered it by NAME, and sign-in
// reaches a person through the org that name resolves to. So a name names one
// application. A tenant holding a platform application's name would have its own
// registrations counted as the platform's: an address it registered would answer
// at the platform's sign-in, and the platform's own customer with that address
// would resolve to nobody.
func TestCreate_AnApplicationNameIsHeldOnce(t *testing.T) {
	h := newOrgHarness(t)
	root := h.token(t, "admin/root")
	acme := h.token(t, "acme/boss")

	if st := h.do(t, "POST", "/v1/iam/applications", root, `{"owner":"admin","name":"hanzo-cloud","organization":"hanzo","clientId":"hanzo-cloud"}`); st != 200 {
		t.Fatalf("platform app: status=%d, want 200", st)
	}
	if st := h.do(t, "POST", "/v1/iam/applications", acme, `{"owner":"acme","name":"hanzo-cloud","organization":"acme","clientId":"acme-cloud","enableSignUp":true}`); st != 409 {
		t.Fatalf("a tenant took a platform application's name: status=%d, want 409", st)
	}
	if st := h.do(t, "POST", "/v1/iam/applications", acme, `{"owner":"acme","name":"acme-cloud","organization":"acme","clientId":"acme-cloud"}`); st != 200 {
		t.Fatalf("a free name: status=%d, want 200", st)
	}
}

// spans lists every declaration that makes an application serve organizations
// other than its own (schema.Application.Spans), as a JSON fragment.
var spans = []struct{ name, body string }{
	{"isShared", `"isShared":true`},
	{"create", `"orgChoiceMode":"create"`},
	{"Select", `"orgChoiceMode":"Select"`},
	{"Input", `"orgChoiceMode":"Input"`},
}

// stored reads one application row back from the store.
func (h *orgHarness) stored(t *testing.T, id string) *schema.Application {
	t.Helper()
	app, err := orm.Get[schema.Application](h.db, id)
	if err != nil {
		t.Fatalf("read %s: %v", id, err)
	}
	return app
}

// An application that serves other organizations is a SuperAdmin's to create:
// a tenant admin is refused every declaration of it, and keeps the ordinary
// confined one ("" or "None").
func TestSpan_OnlyASuperAdminCreatesOne(t *testing.T) {
	h := newOrgHarness(t)
	boss := h.token(t, "acme/boss")
	root := h.token(t, "admin/root")

	for _, sp := range spans {
		name := "acme-" + strings.ToLower(sp.name)
		body := `{"owner":"acme","name":"` + name + `","organization":"acme","clientId":"` + name + `","redirectUris":["https://elsewhere.example/cb"],` + sp.body + `}`
		if st := h.do(t, "POST", "/v1/iam/applications", boss, body); st != 403 {
			t.Fatalf("a tenant admin created an application with %s: status=%d, want 403", sp.name, st)
		}
		if app, _ := orm.Get[schema.Application](h.db, "acme/"+name); app != nil {
			t.Fatalf("a refused create with %s left a row", sp.name)
		}
	}
	for _, mode := range []string{"", "None"} {
		name := "acme-confined" + strings.ToLower(mode)
		if st := h.do(t, "POST", "/v1/iam/applications", boss, `{"owner":"acme","name":"`+name+`","organization":"acme","clientId":"`+name+`","orgChoiceMode":"`+mode+`"}`); st != 200 {
			t.Fatalf("a tenant admin's confined application (orgChoiceMode %q): status=%d, want 200", mode, st)
		}
	}

	// A tenant admin cannot file a row under the platform owner either — the
	// owner tenant isolation reads (schema.Application.ServesAnyOrg).
	if st := h.do(t, "POST", "/v1/iam/applications", boss, `{"owner":"admin","name":"acme-platform","organization":"acme","clientId":"acme-platform"}`); st != 403 {
		t.Fatalf("a tenant admin filed an application under admin: status=%d, want 403", st)
	}

	for _, sp := range spans {
		name := "platform-" + strings.ToLower(sp.name)
		if st := h.do(t, "POST", "/v1/iam/applications", root, `{"owner":"admin","name":"`+name+`","organization":"hanzo","clientId":"`+name+`",`+sp.body+`}`); st != 200 {
			t.Fatalf("a SuperAdmin created a platform application with %s: status=%d, want 200", sp.name, st)
		}
		if !h.stored(t, "admin/"+name).ServesAnyOrg() {
			t.Fatalf("the SuperAdmin's platform application with %s does not serve every org", sp.name)
		}
	}
}

// A tenant admin edits an ordinary application freely, and cannot turn one into
// an application that serves other organizations; the stored row is untouched by
// the refused write.
func TestSpan_ATenantAdminCannotTurnItOn(t *testing.T) {
	h := newOrgHarness(t)
	boss := h.token(t, "acme/boss")

	const base = `"owner":"acme","name":"acme-app","organization":"acme","clientId":"acme-app"`
	if st := h.do(t, "POST", "/v1/iam/applications", boss, `{`+base+`,"redirectUris":["https://acme.example/cb"]}`); st != 200 {
		t.Fatalf("seed: status=%d", st)
	}
	if st := h.do(t, "PUT", "/v1/iam/applications/acme/acme-app", boss, `{`+base+`,"displayName":"Acme","orgChoiceMode":"None","redirectUris":["https://acme.example/cb","https://acme.example/cb2"]}`); st != 200 {
		t.Fatalf("a tenant admin's ordinary edit: status=%d, want 200", st)
	}
	if got := h.stored(t, "acme/acme-app"); got.DisplayName != "Acme" || len(got.RedirectUris) != 2 {
		t.Fatalf("the ordinary edit did not land: displayName=%q redirectUris=%v", got.DisplayName, got.RedirectUris)
	}
	for _, sp := range spans {
		if st := h.do(t, "PUT", "/v1/iam/applications/acme/acme-app", boss, `{`+base+`,"redirectUris":["https://elsewhere.example/cb"],`+sp.body+`}`); st != 403 {
			t.Fatalf("a tenant admin turned on %s: status=%d, want 403", sp.name, st)
		}
		if got := h.stored(t, "acme/acme-app"); got.Spans() || len(got.RedirectUris) != 2 {
			t.Fatalf("a refused %s write changed the row: spans=%v redirectUris=%v", sp.name, got.Spans(), got.RedirectUris)
		}
	}
}

// A tenant-owned application that serves other organizations — one a SuperAdmin
// made so, or one in the store from before — is a SuperAdmin's to write: a tenant
// admin may neither edit it, keeping the declaration, nor confine it.
func TestSpan_ATenantAdminCannotWriteOneThatServesOtherOrgs(t *testing.T) {
	h := newOrgHarness(t)
	boss := h.token(t, "acme/boss")
	root := h.token(t, "admin/root")

	for _, sp := range spans {
		name := "acme-" + strings.ToLower(sp.name)
		base := `"owner":"acme","name":"` + name + `","organization":"acme","clientId":"` + name + `"`
		if st := h.do(t, "POST", "/v1/iam/applications", root, `{`+base+`,`+sp.body+`}`); st != 200 {
			t.Fatalf("a SuperAdmin created a tenant application with %s: status=%d, want 200", sp.name, st)
		}
		for _, body := range []string{
			`{` + base + `,` + sp.body + `,"redirectUris":["https://elsewhere.example/cb"]}`,
			`{` + base + `,` + sp.body + `,"displayName":"Acme"}`,
			`{` + base + `,"displayName":"Acme"}`,
			`{` + base + `,"isShared":false,"orgChoiceMode":"None"}`,
		} {
			if st := h.do(t, "PUT", "/v1/iam/applications/acme/"+name, boss, body); st != 403 {
				t.Fatalf("a tenant admin wrote an application with %s (%s): status=%d, want 403", sp.name, body, st)
			}
		}
		if got := h.stored(t, "acme/"+name); !got.Spans() || len(got.RedirectUris) != 0 || got.DisplayName == "Acme" {
			t.Fatalf("a refused write changed the %s row: %+v", sp.name, got)
		}
		if st := h.do(t, "PUT", "/v1/iam/applications/acme/"+name, root, `{`+base+`,`+sp.body+`,"displayName":"Acme"}`); st != 200 {
			t.Fatalf("a SuperAdmin's edit of an application with %s: status=%d, want 200", sp.name, st)
		}
		if st := h.do(t, "PUT", "/v1/iam/applications/acme/"+name, root, `{`+base+`}`); st != 200 {
			t.Fatalf("a SuperAdmin confining an application with %s: status=%d, want 200", sp.name, st)
		}
		if st := h.do(t, "PUT", "/v1/iam/applications/acme/"+name, boss, `{`+base+`,"displayName":"Acme again"}`); st != 200 {
			t.Fatalf("a tenant admin's edit once it is confined: status=%d, want 200", st)
		}
	}
}

// The platform's own applications are the seed's to name: no API write makes an
// application the platform's or unmakes one, a SuperAdmin's included.
func TestPlatform_NoAPIWritesTheFlag(t *testing.T) {
	h := newOrgHarness(t)
	root := h.token(t, "admin/root")
	platform := func(id string) bool {
		app, err := orm.Get[schema.Application](h.db, id)
		if err != nil {
			t.Fatal(err)
		}
		return app.Platform
	}
	if st := h.do(t, "POST", "/v1/iam/applications", root, `{"owner":"acme","name":"acme-app","organization":"acme","clientId":"acme-app","platform":true}`); st != 200 {
		t.Fatalf("create: status=%d", st)
	}
	if platform("acme/acme-app") {
		t.Fatal("a create made an application the platform's")
	}
	if st := h.do(t, "PUT", "/v1/iam/applications/acme/acme-app", root, `{"owner":"acme","name":"acme-app","organization":"acme","clientId":"acme-app","platform":true}`); st != 200 {
		t.Fatalf("update: status=%d", st)
	}
	if platform("acme/acme-app") {
		t.Fatal("an update made an application the platform's")
	}
}

// A platform application is written and removed by a SuperAdmin only — its redirect
// URIs, secret and grants decide who holds its tokens — even by the admin of the
// org it serves, and a SuperAdmin's write keeps it the platform's.
func TestPlatform_RowIsWrittenBySuperAdminOnly(t *testing.T) {
	h := newOrgHarness(t)
	boss := h.token(t, "acme/boss")
	root := h.token(t, "admin/root")
	app := orm.New[schema.Application](h.db)
	app.Owner, app.Name, app.Organization, app.ClientId, app.Platform = "acme", "acme-style", "acme", "acme-style", true
	app.SetId("acme/acme-style")
	if err := app.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"owner":"acme","name":"acme-style","organization":"acme","clientId":"acme-style","platform":true,"redirectUris":["https://evil.example/cb"]}`,
		`{"owner":"acme","name":"acme-style","organization":"acme","clientId":"acme-style","redirectUris":["https://evil.example/cb"]}`,
	} {
		if st := h.do(t, "PUT", "/v1/iam/applications/acme/acme-style", boss, body); st != 403 {
			t.Fatalf("the org's admin wrote a platform app: status=%d, want 403", st)
		}
	}
	if st := h.do(t, "DELETE", "/v1/iam/applications/acme/acme-style", boss, ""); st != 403 {
		t.Fatalf("the org's admin removed a platform app: status=%d, want 403", st)
	}
	if st := h.do(t, "PUT", "/v1/iam/applications/acme/acme-style", root, `{"owner":"acme","name":"acme-style","organization":"acme","clientId":"acme-style","displayName":"Style"}`); st != 200 {
		t.Fatalf("a SuperAdmin's write: status=%d, want 200", st)
	}
	stored, _ := orm.Get[schema.Application](h.db, "acme/acme-style")
	if !stored.Platform {
		t.Fatal("a SuperAdmin's write that omitted the flag unmade a platform app")
	}
}
