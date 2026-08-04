// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package seed

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
)

func openDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds() // force schema init() (kind registration)
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "seed.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

const fixture = `{
  "organizations": [{"owner":"admin","name":"hanzo"}],
  "certs": [{"owner":"admin","name":"cert-hanzo","cryptoAlgorithm":"RS256","privateKey":"${TEST_CERT_KEY}"}],
  "providers": [{"owner":"admin","name":"provider-github","category":"OAuth","type":"GitHub","clientId":"${TEST_GH_ID}"}],
  "applications": [{"owner":"admin","name":"hanzo-console","clientId":"hanzo-console","organization":"hanzo","enablePassword":true}]
}`

func TestFromInitData_SeedsAndSubstitutesEnv(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()

	t.Setenv("TEST_CERT_KEY", "PEMDATA")
	t.Setenv("TEST_GH_ID", "Iv23-real-github-id")

	path := filepath.Join(t.TempDir(), "init_data.json")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}

	sum, err := FromInitData(ctx, db, path)
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	for _, kind := range []string{"organizations", "certs", "providers", "applications"} {
		if sum.Created[kind] != 1 {
			t.Fatalf("%s created = %d, want 1", kind, sum.Created[kind])
		}
	}

	// The application is resolvable and carries its fields.
	app, err := orm.Get[schema.Application](db, "admin/hanzo-console")
	if err != nil || app == nil {
		t.Fatalf("app not seeded: %v", err)
	}
	if app.ClientId != "hanzo-console" || app.Organization != "hanzo" || !app.EnablePassword {
		t.Fatalf("app fields wrong: clientId=%q org=%q pw=%v", app.ClientId, app.Organization, app.EnablePassword)
	}

	// ${VAR} was substituted from the environment (KMS-style injection).
	prov, err := orm.Get[schema.Provider](db, "admin/provider-github")
	if err != nil || prov == nil {
		t.Fatalf("provider not seeded: %v", err)
	}
	if prov.ClientId != "Iv23-real-github-id" {
		t.Fatalf("env not substituted: clientId=%q", prov.ClientId)
	}
	cert, _ := orm.Get[schema.Cert](db, "admin/cert-hanzo")
	if cert == nil || cert.PrivateKey != "PEMDATA" {
		t.Fatalf("cert key not substituted: %+v", cert)
	}
}

func TestFromInitData_NewOnlyIdempotent(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "init_data.json")
	_ = os.WriteFile(path, []byte(fixture), 0o600)

	if _, err := FromInitData(ctx, db, path); err != nil {
		t.Fatal(err)
	}
	// Second run: everything already exists → all skipped, nothing created.
	sum, err := FromInitData(ctx, db, path)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"organizations", "certs", "providers", "applications"} {
		if sum.Created[kind] != 0 || sum.Skipped[kind] != 1 {
			t.Fatalf("%s: created=%d skipped=%d, want 0/1 (new-only)", kind, sum.Created[kind], sum.Skipped[kind])
		}
	}
}

func TestSubstituteEnv_UnsetBecomesEmpty(t *testing.T) {
	os.Unsetenv("DEFINITELY_UNSET_VAR_XYZ")
	got := substituteEnv([]byte(`x=${DEFINITELY_UNSET_VAR_XYZ}y`))
	if string(got) != "x=y" {
		t.Fatalf("unset var: got %q, want %q", got, "x=y")
	}
}

// TestSeed_GeneratesSigningKeyForKeylessReservedCert proves the fix for the empty
// JWKS: a reserved-org signing cert arrives from init_data WITHOUT key material
// (secrets can't ride a ConfigMap), and the seed mints a parseable keypair so the
// JWKS endpoint publishes a key and iam can sign — while an SSL cert and a
// tenant-owned cert are deliberately left keyless.
func TestSeed_GeneratesSigningKeyForKeylessReservedCert(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	data := &initData{Certs: []*schema.Cert{
		{Owner: "admin", Name: "cert-hanzo", Type: "x509", CryptoAlgorithm: "RS256"}, // reserved, keyless → keyed
		{Owner: "admin", Name: "cert-es", Type: "x509", CryptoAlgorithm: "ES256"},    // reserved ECDSA → keyed
		{Owner: "admin", Name: "cert-ssl", Type: "SSL", CryptoAlgorithm: "RS256"},    // SSL → left keyless
		{Owner: "hanzo", Name: "cert-tenant", CryptoAlgorithm: "RS256"},              // tenant → left keyless
	}}
	if _, err := Apply(ctx, db, data); err != nil {
		t.Fatalf("apply: %v", err)
	}

	rsaCert, err := orm.Get[schema.Cert](db, "admin/cert-hanzo")
	if err != nil {
		t.Fatalf("get cert-hanzo: %v", err)
	}
	if rsaCert.PrivateKey == "" {
		t.Fatal("keyless reserved RS256 cert got no signing key → JWKS would be empty")
	}
	block, _ := pem.Decode([]byte(rsaCert.PrivateKey))
	if block == nil {
		t.Fatal("generated RSA key is not valid PEM")
	}
	if _, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		t.Fatalf("generated RSA key not parseable PKCS1: %v", err)
	}

	esCert, _ := orm.Get[schema.Cert](db, "admin/cert-es")
	if esCert == nil || esCert.PrivateKey == "" {
		t.Fatal("keyless reserved ES256 cert got no signing key")
	}
	if b, _ := pem.Decode([]byte(esCert.PrivateKey)); b == nil {
		t.Fatal("generated EC key is not valid PEM")
	}

	if ssl, _ := orm.Get[schema.Cert](db, "admin/cert-ssl"); ssl == nil || ssl.PrivateKey != "" {
		t.Error("SSL cert must not be given a signing key")
	}
	if ten, _ := orm.Get[schema.Cert](db, "hanzo/cert-tenant"); ten == nil || ten.PrivateKey != "" {
		t.Error("non-reserved tenant cert must not be given a signing key")
	}
}

// TestSeed_PreservesExplicitCertKey: a cert that already carries key material is
// left untouched (no rotation on re-seed → stable kid+key).
func TestSeed_PreservesExplicitCertKey(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	data := &initData{Certs: []*schema.Cert{
		{Owner: "admin", Name: "cert-explicit", Type: "x509", CryptoAlgorithm: "RS256", PrivateKey: "EXISTING-PEM"},
	}}
	if _, err := Apply(ctx, db, data); err != nil {
		t.Fatalf("apply: %v", err)
	}
	c, _ := orm.Get[schema.Cert](db, "admin/cert-explicit")
	if c == nil || c.PrivateKey != "EXISTING-PEM" {
		t.Fatalf("explicit cert key was overwritten: %q", c.PrivateKey)
	}
}

// ── declared application policy converges ────────────────────────────────────────

// Seeding is new-only, which is right for identity DATA but was wrong for
// application POLICY: with upsert skipping existing rows, flipping enableSignUp in
// init_data.json changed nothing on a seeded deployment. Production read
// enableSignUp=false — "the application does not allow to sign up new account" —
// while the declared state said otherwise, and only an out-of-band admin call could
// move it.
func TestSeed_DeclaredAppPolicyReconciles(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "init_data.json")

	// First boot: signup off.
	_ = os.WriteFile(path, []byte(fixture), 0o600)
	if _, err := FromInitData(ctx, db, path); err != nil {
		t.Fatal(err)
	}
	app, err := orm.Get[schema.Application](db, "admin/hanzo-console")
	if err != nil || app == nil {
		t.Fatalf("seed application: %v", err)
	}
	if app.EnableSignUp {
		t.Fatal("fixture should start with signup disabled")
	}

	// The operator declares signup on. A converging seed must apply it.
	on := `{
  "organizations": [{"owner":"admin","name":"hanzo"}],
  "applications": [{"owner":"admin","name":"hanzo-console","clientId":"hanzo-console","organization":"hanzo","enablePassword":true,"enableSignUp":true}]
}`
	_ = os.WriteFile(path, []byte(on), 0o600)
	sum, err := FromInitData(ctx, db, path)
	if err != nil {
		t.Fatal(err)
	}
	if sum.Reconciled["applications"] != 1 {
		t.Fatalf("reconciled=%d, want 1", sum.Reconciled["applications"])
	}
	app, _ = orm.Get[schema.Application](db, "admin/hanzo-console")
	if !app.EnableSignUp {
		t.Fatal("declared enableSignUp=true did not converge onto the existing row")
	}
}

// The reason reconcile merges the RAW declared object rather than saving the decoded
// struct: clientSecret is generated at first seed and never written back to
// init_data.json. Saving a decoded struct would blank it and lock every OAuth client
// out — the same de-secret hazard update-application had to fix. A field the file
// does not mention must keep its stored value.
func TestSeed_ReconcileKeepsUndeclaredFields(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	dir := t.TempDir()
	path := filepath.Join(dir, "init_data.json")
	_ = os.WriteFile(path, []byte(fixture), 0o600)
	if _, err := FromInitData(ctx, db, path); err != nil {
		t.Fatal(err)
	}

	// Stand in for the secret the deployment generates after the first seed.
	if _, err := orm.GetOrUpdate[schema.Application](db, "admin/hanzo-console", func(a *schema.Application) {
		a.ClientSecret = "generated-at-first-boot"
	}); err != nil {
		t.Fatal(err)
	}

	// init_data.json carries NO clientSecret — reconciling must not erase it.
	if _, err := FromInitData(ctx, db, path); err != nil {
		t.Fatal(err)
	}
	app, _ := orm.Get[schema.Application](db, "admin/hanzo-console")
	if app.ClientSecret != "generated-at-first-boot" {
		t.Fatalf("reconcile blanked an undeclared field: clientSecret=%q", app.ClientSecret)
	}
	// And a declared field is still authoritative.
	if !app.EnablePassword {
		t.Fatal("declared enablePassword=true should hold")
	}
}

// Measured against production: live applications legitimately carry redirect URIs
// and grants init_data.json does not list (hanzo-console alone had 4 extra
// redirects and 2 extra grants). Reconciling the WHOLE declared object would have
// deleted them and broken the very logins the flag change was meant to fix, so the
// reconcile is narrowed to policy keys. This is the guard on that.
func TestSeed_ReconcileNeverStripsRegistration(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "init_data.json")
	_ = os.WriteFile(path, []byte(fixture), 0o600)
	if _, err := FromInitData(ctx, db, path); err != nil {
		t.Fatal(err)
	}

	// Stand in for registration that drifted ahead of the file, as production had.
	if _, err := orm.GetOrUpdate[schema.Application](db, "admin/hanzo-console", func(a *schema.Application) {
		a.RedirectUris = []string{"https://console.hanzo.ai/callback", "https://admin.hanzo.ai/auth/callback"}
		a.GrantTypes = []string{"authorization_code", "refresh_token", "client_credentials"}
		a.ClientSecret = "generated-at-first-boot"
	}); err != nil {
		t.Fatal(err)
	}

	// The file declares neither, and now flips a policy flag.
	on := `{
  "organizations": [{"owner":"admin","name":"hanzo"}],
  "applications": [{"owner":"admin","name":"hanzo-console","clientId":"hanzo-console","organization":"hanzo","enablePassword":true,"enableSignUp":true}]
}`
	_ = os.WriteFile(path, []byte(on), 0o600)
	if _, err := FromInitData(ctx, db, path); err != nil {
		t.Fatal(err)
	}

	app, _ := orm.Get[schema.Application](db, "admin/hanzo-console")
	if !app.EnableSignUp {
		t.Fatal("declared policy must converge")
	}
	if len(app.RedirectUris) != 2 {
		t.Fatalf("registration must survive: redirectUris=%v", app.RedirectUris)
	}
	if len(app.GrantTypes) != 3 {
		t.Fatalf("registration must survive: grantTypes=%v", app.GrantTypes)
	}
	if app.ClientSecret != "generated-at-first-boot" {
		t.Fatalf("clientSecret must survive: %q", app.ClientSecret)
	}
}

// Passkeys must converge like every other declared policy flag.
//
// Regression, measured against production: init_data.json declared
// enableWebAuthn TRUE on 37 of 83 applications — hanzo-app, hanzo-chat,
// hanzo-cloud, hanzo-console, hanzo-id and hanzo-world among them — while
// /v1/iam/auth/methods answered `webauthn:false` for every one. upsert is
// new-only and enableWebAuthn was absent from appPolicyKeys, so the declared
// value never reached a seeded row. Two thirds of the estate was supposed to
// offer passkeys and no login screen ever did, with nothing logged: the only way
// to see it was to diff the ConfigMap against the live endpoint.
func TestSeed_ReconcileConvergesWebAuthn(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "init_data.json")

	// A seeded row with passkeys OFF — the production state.
	off := `{
  "organizations": [{"owner":"admin","name":"hanzo"}],
  "applications": [{"owner":"admin","name":"hanzo-console","clientId":"hanzo-console","organization":"hanzo","enablePassword":true,"enableWebAuthn":false}]
}`
	if err := os.WriteFile(path, []byte(off), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FromInitData(ctx, db, path); err != nil {
		t.Fatal(err)
	}
	app, err := orm.Get[schema.Application](db, "admin/hanzo-console")
	if err != nil || app == nil {
		t.Fatalf("seed application: %v", err)
	}
	if app.EnableWebAuthn {
		t.Fatal("fixture should start with passkeys disabled")
	}

	// The operator declares passkeys on. A converging seed must apply it.
	on := `{
  "organizations": [{"owner":"admin","name":"hanzo"}],
  "applications": [{"owner":"admin","name":"hanzo-console","clientId":"hanzo-console","organization":"hanzo","enablePassword":true,"enableWebAuthn":true}]
}`
	if err := os.WriteFile(path, []byte(on), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FromInitData(ctx, db, path); err != nil {
		t.Fatal(err)
	}
	app, _ = orm.Get[schema.Application](db, "admin/hanzo-console")
	if !app.EnableWebAuthn {
		t.Fatal("declared enableWebAuthn=true did not converge onto the existing row")
	}

	// ...and it converges BACK off, so the file stays authoritative in both
	// directions. A one-way flag would be a trapdoor, not a declaration.
	if err := os.WriteFile(path, []byte(off), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := FromInitData(ctx, db, path); err != nil {
		t.Fatal(err)
	}
	app, _ = orm.Get[schema.Application](db, "admin/hanzo-console")
	if app.EnableWebAuthn {
		t.Fatal("declared enableWebAuthn=false did not converge back off")
	}
}
