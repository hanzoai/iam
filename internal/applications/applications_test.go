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

// The signing-cert binding gate on create. The Cert an app names is the key IAM
// signs that app's tokens with — oidc.signerFor resolves it via store.GetSigningCert
// over admin/built-in, by NAME, ignoring the app's owner. authorizeCert must gate by
// that SAME resolution: a tenant app may not name a cert that resolves to a trusted
// platform signing cert. The decisive case is the DECOY — a same-named cert planted
// under the tenant's own org must NOT launder the platform kid.
func TestCreate_CertBindingIsScoped(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	create := Create(db)

	seedCert(t, db, "admin", "cert-platform")    // a trusted platform signing cert (a JWKS kid)
	seedCert(t, db, "hanzo", "cert-platform")    // R1: a same-NAMED decoy under the tenant's OWN org
	seedCert(t, db, "hanzo", "cert-hanzo-local") // a genuinely tenant-owned, non-kid cert

	// R1 core: a tenant app naming a platform kid is refused EVEN with a same-named
	// decoy under its own org — the gate resolves the name the way the signer does,
	// so the decoy is irrelevant. Fail-before (own-org GetCert gate): the decoy PASSED.
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "poison", Cert: "cert-platform"}); err == nil {
		t.Fatal("HIGH: a tenant app bound the PLATFORM signing cert via a same-named decoy (trust-anchor confusion)")
	}
	// A tenant-owned, non-kid cert name → allowed: it resolves to no signing key
	// (GetSigningCert ignores non-reserved owners), so the app mints nothing.
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "inert", Cert: "cert-hanzo-local"}); err != nil {
		t.Fatalf("a tenant-owned non-signing cert must be allowed (inert): %v", err)
	}
	// An unknown cert name → allowed (also inert).
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "unknown", Cert: "cert-does-not-exist"}); err != nil {
		t.Fatalf("an unknown cert name must be allowed (inert): %v", err)
	}
	// A certless app is fine.
	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "plain"}); err != nil {
		t.Fatalf("a certless tenant app must be allowed: %v", err)
	}
	// A platform (admin-owned) app naming a platform cert → allowed (the carve-out).
	if _, err := create(ctx, &schema.Application{Owner: "admin", Name: "console-app", Cert: "cert-platform"}); err != nil {
		t.Fatalf("a platform app binding a platform cert must be allowed: %v", err)
	}
}

// The same binding gate on update, decoy included: a tenant app cannot be re-pointed
// at a platform signing cert after the fact, even with a same-named own-org decoy.
func TestUpdate_CertBindingIsScoped(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	create, update := Create(db), Update(db)
	seedCert(t, db, "admin", "cert-platform") // the trusted platform kid
	seedCert(t, db, "hanzo", "cert-platform") // the decoy under the tenant's own org

	if _, err := create(ctx, &schema.Application{Owner: "hanzo", Name: "app"}); err != nil {
		t.Fatalf("seed tenant app: %v", err)
	}
	if _, err := update(ctx, &schema.Application{Owner: "hanzo", Name: "app", Cert: "cert-platform"}); err == nil {
		t.Fatal("HIGH: update bound a tenant app to the PLATFORM signing cert (decoy laundered the kid)")
	}
}
