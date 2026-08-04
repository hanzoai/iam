// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
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
