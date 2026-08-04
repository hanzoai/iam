// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// putApp inserts a raw application row (bypassing the applications create guard) to
// model a duplicate clientId that a heap-ordered backend could return in ANY order —
// the precondition the deterministic, admin-preferring resolve must defeat.
func putApp(t *testing.T, db orm.DB, owner, name, clientID, secret string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId, a.ClientSecret = owner, name, clientID, secret
	a.SetId(owner + "/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app %s/%s: %v", owner, name, err)
	}
}

// GetApplicationByClientId is deterministic and ADMIN-PREFERRING: with a duplicate
// clientId across a platform (admin) row and a tenant (evil) row, the platform row
// ALWAYS resolves — closing the collidable-mint vector (First() with no ORDER BY,
// safe on dev sqlite by rowid but UNSPECIFIED on Postgres heap order).
func TestGetApplicationByClientId_AdminPreferring(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	// Insert the tenant row FIRST (so a naive rowid/insertion order would surface it
	// first), then the platform row.
	putApp(t, db, "evil", "hanzo-console", "hanzo-console", "attacker-knows-this")
	putApp(t, db, "admin", "hanzo-console", "hanzo-console", "real-secret")

	got, err := GetApplicationByClientId(ctx, db, "hanzo-console")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.Owner != "admin" {
		t.Fatalf("admin-preferring resolution failed: got %+v, want the admin-owned row", got)
	}
	if got.ClientSecret != "real-secret" {
		t.Fatalf("resolved the WRONG secret %q — an attacker row won resolution", got.ClientSecret)
	}

	// built-in is also a signing owner — it outranks a tenant too.
	db2 := memDB(t)
	putApp(t, db2, "zoo", "shared", "shared", "tenant")
	putApp(t, db2, "built-in", "shared", "shared", "platform")
	if got, _ := GetApplicationByClientId(ctx, db2, "shared"); got == nil || got.Owner != "built-in" {
		t.Fatalf("a built-in signing owner must outrank a tenant: got %+v", got)
	}

	// ListApplicationsByClientId sees BOTH rows (it backs the uniqueness guard).
	all, err := ListApplicationsByClientId(ctx, db, "hanzo-console")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListApplicationsByClientId = %d rows, want 2", len(all))
	}

	// Not-found and empty inputs preserve the (nil, nil) contract.
	if got, _ := GetApplicationByClientId(ctx, db, "nope"); got != nil {
		t.Fatalf("unknown clientId must resolve nil, got %+v", got)
	}
	if all, _ := ListApplicationsByClientId(ctx, db, ""); all != nil {
		t.Fatalf("empty clientId must list nil, got %v", all)
	}
}
