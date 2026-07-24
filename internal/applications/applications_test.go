// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package applications

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/schema"
)

func memDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	dir := t.TempDir()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(dir, "apptest.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// The clientId global-uniqueness guard on create: a create may not take a clientId
// already held by a DIFFERENT (owner,name), so a tenant can never register a row that
// collides with a platform console's confidential-client key. This is the store-layer
// enforcement of the invariant the mint/Basic-auth gates rely on (a JSON-document
// store has no column for a DB UNIQUE index). A background ctx carries no principal,
// so authorizeOrganization is the trusted server-internal path and the guard is
// exercised in isolation.
func TestCreate_RejectsDuplicateClientId(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	create := Create(db)

	// The legit platform console.
	if _, err := create(ctx, &schema.Application{Owner: "admin", Name: "hanzo-console", ClientId: "hanzo-console"}); err != nil {
		t.Fatalf("seed console: %v", err)
	}

	// A tenant tries to register a DIFFERENT (owner,name) with the SAME clientId.
	if _, err := create(ctx, &schema.Application{Owner: "evil", Name: "evil-console", ClientId: "hanzo-console"}); err == nil {
		t.Fatal("HIGH REOPENED: a colliding clientId was accepted on create")
	}

	// A distinct clientId under a tenant is fine (no false positive).
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "hanzo-app", ClientId: "hanzo-app"}); err != nil {
		t.Fatalf("a distinct clientId must be accepted: %v", err)
	}

	// A public app (no clientId) never collides with another public app.
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "pub-a"}); err != nil {
		t.Fatalf("empty clientId #1: %v", err)
	}
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "pub-b"}); err != nil {
		t.Fatalf("empty clientId #2 must not collide with #1: %v", err)
	}
}

// Update may keep its OWN clientId (the self-row is skipped, never a self-collision)
// but must not steal another app's.
func TestUpdate_ClientIdCollision(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	create, update := Create(db), Update(db)

	if _, err := create(ctx, &schema.Application{Owner: "admin", Name: "hanzo-console", ClientId: "hanzo-console"}); err != nil {
		t.Fatalf("seed console: %v", err)
	}
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "hanzo-app", ClientId: "hanzo-app"}); err != nil {
		t.Fatalf("seed tenant app: %v", err)
	}

	// hanzo-app keeps its own clientId on update — allowed (self-row skipped).
	if _, err := update(ctx, &schema.Application{Owner: "hanzo", Name: "hanzo-app", ClientId: "hanzo-app", DisplayName: "renamed"}); err != nil {
		t.Fatalf("keeping own clientId on update must be allowed: %v", err)
	}

	// hanzo-app tries to STEAL the console's clientId — rejected.
	if _, err := update(ctx, &schema.Application{Owner: "hanzo", Name: "hanzo-app", ClientId: "hanzo-console"}); err == nil {
		t.Fatal("HIGH REOPENED: an update stole another app's clientId")
	}
}

// seedCert persists a bare cert row under (owner, name) so the binding gate can
// resolve ownership. The key material is irrelevant to the ownership check.
func seedCert(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name = owner, name
	c.SetId(owner + "/" + name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert %s/%s: %v", owner, name, err)
	}
}

// The signing-cert binding gate on create: the Cert an app names is the key IAM
// signs that app's tokens with (oidc.signerFor → store.GetSigningCert, trusted only
// under admin/built-in). A tenant app may bind ONLY a cert its OWN org owns — naming
// a platform (admin/built-in) signing cert is the cert half of the SuperAdmin-forgery
// chain and is refused. A platform-owned app keeps binding a platform cert; a
// certless app is untouched. Background ctx = the trusted server-internal path, so
// the gate is a structural invariant, not a per-principal authz decision.
func TestCreate_CertBindingIsScoped(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	create := Create(db)

	seedCert(t, db, "admin", "cert-platform")    // a trusted platform signing cert
	seedCert(t, db, "hanzo", "cert-hanzo-local") // a tenant-owned cert

	// Tenant app naming the PLATFORM cert → refused (the poisoning vector).
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "poison", Cert: "cert-platform"}); err == nil {
		t.Fatal("HIGH: a tenant app bound the PLATFORM signing cert (cert poisoning)")
	}
	// Tenant app naming a cert its org does NOT own (cross-owner / absent) → refused.
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "ghost", Cert: "cert-nope"}); err == nil {
		t.Fatal("a tenant app bound a cert its org does not own")
	}
	// Tenant app with NO cert → allowed (mints nothing).
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "plain"}); err != nil {
		t.Fatalf("a certless tenant app must be allowed: %v", err)
	}
	// Tenant app naming its OWN-ORG cert → allowed.
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "local", Cert: "cert-hanzo-local"}); err != nil {
		t.Fatalf("a same-org cert must be allowed: %v", err)
	}
	// Platform (admin-owned) app naming a platform cert → allowed (the carve-out).
	if _, err := create(ctx, &schema.Application{Owner: "admin", Name: "console-app", Cert: "cert-platform"}); err != nil {
		t.Fatalf("a platform app binding a platform cert must be allowed: %v", err)
	}
}

// The same binding gate on update: a tenant app cannot be re-pointed at a platform
// signing cert after the fact.
func TestUpdate_CertBindingIsScoped(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	create, update := Create(db), Update(db)
	seedCert(t, db, "admin", "cert-platform")

	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "app"}); err != nil {
		t.Fatalf("seed tenant app: %v", err)
	}
	if _, err := update(ctx, &schema.Application{Owner: "hanzo", Name: "app", Cert: "cert-platform"}); err == nil {
		t.Fatal("HIGH: update bound a tenant app to the PLATFORM signing cert")
	}
}
