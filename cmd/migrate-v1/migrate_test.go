// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// Golden argon2id digest, mirrored VERBATIM from internal/cred/golden_v1_test.go.
// It was produced by v1's own Argon2idCredManager. Proving cred.Verify succeeds
// against the MIGRATED hash — a hash that entered the clean store only through
// this migrator — is the full end-to-end credential-parity assertion.
const (
	goldenPassword = "golden-test-password-1"
	goldenDigest   = "$argon2id$v=19$m=65536,t=1,p=2$oOen09XtFBqKnv2/K4q5mQ$iZKRwt09CdXDXr4E1CQtRoF/nWzgI810tMFUUiKHugo"
)

// newLegacyDB builds a tiny synthetic legacy Casdoor iam.db with snake_case
// columns (as xorm emits) — including the credential-critical `password` column
// and the Casdoor `id` UUID that the clean schema now carries verbatim as
// schema.User.Id (the continuity `sub`).
func newLegacyDB(t *testing.T, certPEM, keyPEM string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "iam.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open legacy: %v", err)
	}
	defer db.Close()

	stmts := []string{
		`CREATE TABLE organization (
			owner text, name text, created_time text, display_name text,
			password_type text, init_score integer, is_personal integer)`,
		`CREATE TABLE cert (
			owner text, name text, created_time text, type text,
			crypto_algorithm text, bit_size integer, certificate text, private_key text)`,
		`CREATE TABLE application (
			owner text, name text, created_time text, display_name text,
			organization text, cert text, client_id text, client_secret text,
			enable_password integer, redirect_uris text)`,
		`CREATE TABLE provider (
			owner text, name text, created_time text, category text, type text,
			client_id text, client_secret text, user_mapping text)`,
		`CREATE TABLE user (
			owner text, name text, created_time text, updated_time text, id text,
			password text, password_type text, password_salt text, email text,
			display_name text, is_admin integer, signup_application text, github text)`,
		`CREATE TABLE role (
			owner text, name text, created_time text, display_name text,
			users text, is_enabled integer)`,
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("create table: %v\n%s", err, s)
		}
	}

	exec := func(q string, args ...any) {
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	exec(`INSERT INTO organization VALUES(?,?,?,?,?,?,?)`,
		"admin", "hanzo", "2020-01-02T03:04:05Z", "Hanzo", "argon2id", 100, 0)
	exec(`INSERT INTO cert VALUES(?,?,?,?,?,?,?,?)`,
		"admin", "cert-hanzo", "2020-01-02T03:04:05Z", "x509", "RS256", 2048, certPEM, keyPEM)
	exec(`INSERT INTO application VALUES(?,?,?,?,?,?,?,?,?,?)`,
		"admin", "app-hanzo", "2020-01-02T03:04:05Z", "Hanzo App", "hanzo", "cert-hanzo",
		"client-abc", "secret-xyz", 1, `["https://hanzo.ai/callback"]`)
	exec(`INSERT INTO provider VALUES(?,?,?,?,?,?,?,?)`,
		"admin", "provider-github", "2020-01-02T03:04:05Z", "OAuth", "GitHub",
		"gh-id", "gh-secret", `{"id":"id","username":"login"}`)
	// User z: own password_type=argon2id.
	exec(`INSERT INTO user VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"hanzo", "z", "2020-01-02T03:04:05Z", "2020-02-02T03:04:05Z", "uuid-0001",
		goldenDigest, "argon2id", "the-salt", "z@hanzo.ai", "Z", 1, "app-hanzo", "z-gh")
	// User fallback: EMPTY password_type — verification must fall back to the org's.
	exec(`INSERT INTO user VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"hanzo", "fallback", "2020-01-03T03:04:05Z", "2020-02-03T03:04:05Z", "uuid-0002",
		goldenDigest, "", "", "fallback@hanzo.ai", "Fallback", 0, "app-hanzo", "")
	exec(`INSERT INTO role VALUES(?,?,?,?,?,?)`,
		"hanzo", "role-admin", "2020-01-02T03:04:05Z", "Admins", `["hanzo/z"]`, 1)

	return path
}

func genRSAPEM(t *testing.T) (certPEM, keyPEM string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{
		Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	// A stand-in certificate PEM — content is opaque to the migrator; what matters
	// is that the multi-line PEM survives byte-for-byte.
	certPEM = "-----BEGIN CERTIFICATE-----\nMIIB=stub=cert=material=\nfor=jwks=parity=test\n-----END CERTIFICATE-----\n"
	return certPEM, keyPEM
}

func openDest(t *testing.T) (orm.DB, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := store.Open("sqlite", filepath.Join(dir, "iam2.db"))
	if err != nil {
		t.Fatalf("open dest: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db, dir
}

func TestMigrate_PreservesCredentialsAndKeysVerbatim(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM := genRSAPEM(t)
	srcPath := newLegacyDB(t, certPEM, keyPEM)

	src, err := sql.Open("sqlite", srcPath)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()

	dst, _ := openDest(t)

	results, err := Migrate(ctx, src, dst, nil, options{})
	if err != nil {
		t.Fatalf("migrate: %v", err)
	}
	byEntity := indexResults(results)

	// ---- Organization: password_type must survive (it is the fallback scheme). ----
	org, err := store.GetOrganizationByName(ctx, dst, "hanzo")
	if err != nil || org == nil {
		t.Fatalf("org not migrated: %v", err)
	}
	if org.PasswordType != "argon2id" {
		t.Errorf("org.PasswordType = %q, want argon2id", org.PasswordType)
	}
	if org.CreatedTime != "2020-01-02T03:04:05Z" {
		t.Errorf("org.CreatedTime = %q, want the v1 stamp verbatim", org.CreatedTime)
	}
	if org.InitScore != 100 {
		t.Errorf("org.InitScore = %d, want 100", org.InitScore)
	}

	// ---- Cert: PrivateKey + Certificate byte-for-byte (JWKS parity). ----
	cert, err := store.GetCert(ctx, dst, "admin", "cert-hanzo")
	if err != nil || cert == nil {
		t.Fatalf("cert not migrated: %v", err)
	}
	if cert.PrivateKey != keyPEM {
		t.Fatalf("cert.PrivateKey NOT verbatim:\n got %q\nwant %q", cert.PrivateKey, keyPEM)
	}
	if cert.Certificate != certPEM {
		t.Fatalf("cert.Certificate NOT verbatim:\n got %q\nwant %q", cert.Certificate, certPEM)
	}
	if cert.BitSize != 2048 || cert.CryptoAlgorithm != "RS256" {
		t.Errorf("cert metadata drift: bitSize=%d alg=%q", cert.BitSize, cert.CryptoAlgorithm)
	}

	// ---- User z: PasswordHash verbatim, and cred.Verify succeeds end-to-end. ----
	u, err := store.GetUserByName(ctx, dst, "hanzo", "z")
	if err != nil || u == nil {
		t.Fatalf("user z not migrated: %v", err)
	}
	if u.PasswordHash != goldenDigest {
		t.Fatalf("user.PasswordHash NOT verbatim:\n got %q\nwant %q", u.PasswordHash, goldenDigest)
	}
	if u.PasswordType != "argon2id" {
		t.Errorf("user.PasswordType = %q, want argon2id", u.PasswordType)
	}
	if u.PasswordSalt != "the-salt" {
		t.Errorf("user.PasswordSalt = %q, want the-salt", u.PasswordSalt)
	}
	if !u.IsAdmin {
		t.Error("user.IsAdmin = false, want true (bool 1 -> true)")
	}
	if u.GitHub != "z-gh" {
		t.Errorf("user.GitHub = %q, want z-gh (federated connector column)", u.GitHub)
	}
	if u.Email != "z@hanzo.ai" {
		t.Errorf("user.Email = %q", u.Email)
	}
	// SUB CONTINUITY: the Casdoor per-row UUID migrates verbatim into User.Id — the
	// value the OIDC `sub` will carry, so a migrated user's sub is byte-identical
	// across the cutover.
	if u.Id != "uuid-0001" {
		t.Errorf("user.Id = %q, want uuid-0001 (the migrated continuity sub)", u.Id)
	}
	// THE assertion that matters: the migrated hash verifies under the clean
	// verifier, resolving the scheme from the row exactly as login does.
	typ := cred.Resolve(u.PasswordType, org.PasswordType)
	if !cred.Verify(typ, goldenPassword, u.PasswordHash) {
		t.Fatal("cred.Verify REJECTED the migrated argon2id hash — login would fail at cutover")
	}
	if cred.Verify(typ, "wrong-password", u.PasswordHash) {
		t.Fatal("cred.Verify ACCEPTED a wrong password against the migrated hash")
	}

	// ---- User fallback: empty type resolves through the org's argon2id. ----
	fb, err := store.GetUserByName(ctx, dst, "hanzo", "fallback")
	if err != nil || fb == nil {
		t.Fatalf("user fallback not migrated: %v", err)
	}
	if fb.PasswordType != "" {
		t.Errorf("fallback user should keep empty PasswordType, got %q", fb.PasswordType)
	}
	fbType := cred.Resolve(fb.PasswordType, org.PasswordType)
	if fbType != "argon2id" {
		t.Fatalf("org fallback resolve = %q, want argon2id", fbType)
	}
	if !cred.Verify(fbType, goldenPassword, fb.PasswordHash) {
		t.Fatal("org-fallback verification of migrated hash failed")
	}

	// ---- Application + Provider round-trip (incl. a JSON-typed column). ----
	app, err := store.GetApplicationByName(ctx, dst, "admin", "app-hanzo")
	if err != nil || app == nil {
		t.Fatalf("app not migrated: %v", err)
	}
	if app.ClientId != "client-abc" || app.Cert != "cert-hanzo" || app.Organization != "hanzo" {
		t.Errorf("app fields drift: clientId=%q cert=%q org=%q", app.ClientId, app.Cert, app.Organization)
	}
	if len(app.RedirectUris) != 1 || app.RedirectUris[0] != "https://hanzo.ai/callback" {
		t.Errorf("app.RedirectUris JSON column not decoded: %#v", app.RedirectUris)
	}
	prov, err := store.GetProvider(ctx, dst, "admin", "provider-github")
	if err != nil || prov == nil {
		t.Fatalf("provider not migrated: %v", err)
	}
	wantMap := map[string]string{"id": "id", "username": "login"}
	if !reflect.DeepEqual(prov.UserMapping, wantMap) {
		t.Errorf("provider.UserMapping = %#v, want %#v", prov.UserMapping, wantMap)
	}

	// ---- The Casdoor `id` UUID now has a clean home (User.Id): it must NOT be a gap. ----
	if got := byEntity["users"]; got == nil || contains(got.UnmappedCols, "id") {
		t.Errorf("legacy user column 'id' must now be MAPPED to User.Id (the continuity sub), still reported unmapped: %v",
			gapCols(got))
	}
	if fb, _ := store.GetUserByName(ctx, dst, "hanzo", "fallback"); fb == nil || fb.Id != "uuid-0002" {
		t.Errorf("fallback user.Id = %v, want uuid-0002 (every casdoor row's UUID carries)", fb)
	}

	// ---- Row counts: everything read was created. ----
	assertCounts(t, byEntity["users"], 2, 2, 0, 0)
	assertCounts(t, byEntity["organizations"], 1, 1, 0, 0)
	assertCounts(t, byEntity["certs"], 1, 1, 0, 0)
	assertCounts(t, byEntity["applications"], 1, 1, 0, 0)
	assertCounts(t, byEntity["providers"], 1, 1, 0, 0)
}

func TestMigrate_Idempotent(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM := genRSAPEM(t)
	srcPath := newLegacyDB(t, certPEM, keyPEM)

	src, err := sql.Open("sqlite", srcPath)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()

	dst, _ := openDest(t)

	if _, err := Migrate(ctx, src, dst, nil, options{}); err != nil {
		t.Fatalf("first pass: %v", err)
	}
	firstCounts := kindCounts(ctx, t, dst)

	// Second pass must be a pure no-op: nothing created, nothing updated.
	results, err := Migrate(ctx, src, dst, nil, options{})
	if err != nil {
		t.Fatalf("second pass: %v", err)
	}
	for _, r := range results {
		if r.Created != 0 || r.Updated != 0 {
			t.Errorf("%s: re-run not idempotent (created=%d updated=%d), want 0/0",
				r.Entity, r.Created, r.Updated)
		}
		if r.Read != r.Unchanged {
			t.Errorf("%s: read=%d but unchanged=%d — re-run should classify every row unchanged",
				r.Entity, r.Read, r.Unchanged)
		}
	}

	// No duplicate rows: per-kind counts are identical after the second pass.
	secondCounts := kindCounts(ctx, t, dst)
	if !reflect.DeepEqual(firstCounts, secondCounts) {
		t.Errorf("row counts changed on re-run: %v -> %v", firstCounts, secondCounts)
	}

	// And the hash is still exact after two passes.
	u, err := store.GetUserByName(ctx, dst, "hanzo", "z")
	if err != nil || u == nil || u.PasswordHash != goldenDigest {
		t.Fatalf("hash drifted after re-run: %v", err)
	}
}

func TestMigrate_DryRunWritesNothing(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM := genRSAPEM(t)
	srcPath := newLegacyDB(t, certPEM, keyPEM)

	src, err := sql.Open("sqlite", srcPath)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()

	dst, _ := openDest(t)

	results, err := Migrate(ctx, src, dst, nil, options{dryRun: true})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	// Dry-run predicts creates but writes nothing.
	for _, r := range results {
		if r.TableMissing {
			continue
		}
		if r.Created != r.Read {
			t.Errorf("%s: dry-run should predict create for every row (read=%d created=%d)",
				r.Entity, r.Read, r.Created)
		}
	}
	counts := kindCounts(ctx, t, dst)
	for kind, n := range counts {
		if n != 0 {
			t.Errorf("dry-run wrote %d rows of kind %q, want 0", n, kind)
		}
	}
	// Second (real) run after a dry-run still creates everything.
	real, err := Migrate(ctx, src, dst, nil, options{})
	if err != nil {
		t.Fatalf("real after dry: %v", err)
	}
	for _, r := range indexResultsSlice(real) {
		if r.TableMissing {
			continue
		}
		if r.Created != r.Read {
			t.Errorf("%s: real run after dry-run should create every row", r.Entity)
		}
	}
}

func TestMigrate_OnlySelectsSubset(t *testing.T) {
	ctx := context.Background()
	certPEM, keyPEM := genRSAPEM(t)
	srcPath := newLegacyDB(t, certPEM, keyPEM)

	src, err := sql.Open("sqlite", srcPath)
	if err != nil {
		t.Fatalf("open src: %v", err)
	}
	defer src.Close()

	dst, _ := openDest(t)

	results, err := Migrate(ctx, src, dst, []string{"users", "orgs"}, options{})
	if err != nil {
		t.Fatalf("migrate subset: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 entities migrated, got %d", len(results))
	}
	// certs must NOT have been touched.
	if c, _ := store.GetCert(ctx, dst, "admin", "cert-hanzo"); c != nil {
		t.Error("--only users,orgs should not migrate certs")
	}
	if u, _ := store.GetUserByName(ctx, dst, "hanzo", "z"); u == nil {
		t.Error("--only users,orgs must migrate users")
	}

	// An unknown selector is a hard error, never a silent skip.
	if _, err := Migrate(ctx, src, dst, []string{"widgets"}, options{}); err == nil {
		t.Error("unknown --only entity must error")
	}
}

// --- helpers ---

func indexResults(rs []*EntityResult) map[string]*EntityResult {
	m := map[string]*EntityResult{}
	for _, r := range rs {
		m[r.Entity] = r
	}
	return m
}

func indexResultsSlice(rs []*EntityResult) []*EntityResult { return rs }

func assertCounts(t *testing.T, r *EntityResult, read, created, updated, unchanged int) {
	t.Helper()
	if r == nil {
		t.Fatalf("nil result")
	}
	if r.Read != read || r.Created != created || r.Updated != updated || r.Unchanged != unchanged {
		t.Errorf("%s counts = read %d/created %d/updated %d/unchanged %d, want %d/%d/%d/%d",
			r.Entity, r.Read, r.Created, r.Updated, r.Unchanged, read, created, updated, unchanged)
	}
}

func kindCounts(ctx context.Context, t *testing.T, db orm.DB) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	for _, kind := range schema.Kinds() {
		n, err := db.Query(kind).Count(ctx)
		if err != nil {
			t.Fatalf("count %s: %v", kind, err)
		}
		if n > 0 {
			out[kind] = int64(n)
		}
	}
	return out
}

func contains(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}

func gapCols(r *EntityResult) []string {
	if r == nil {
		return nil
	}
	return r.UnmappedCols
}
