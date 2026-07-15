// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package seed

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam2/internal/schema"
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
