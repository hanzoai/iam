// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

// An organization is filed under the admin owner and named by its slug. The name
// is the tenant identity — store.GetOrganizationByName resolves a name there, the
// list here reads there, and authz decides an organization write on its
// reserved-owner branch — so the owner half is a value with one legal setting.
// A row filed anywhere else would carry a name the rest of the system already
// answers with another row.

import (
	"context"
	"net/http"
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/pkg/store"
)

// A create naming any other owner is refused. Nothing resolves such a row, so
// admitting it would only put a second answer under a name that has one.
func TestCreate_FilesOnlyUnderTheRegistryOwner(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()

	for _, owner := range []string{"acme", "built-in", "hanzo", "Admin"} {
		in := createIn(owner, "victim")
		got, err := api.Create(ctx, in)
		if err == nil {
			t.Fatalf("owner %q: created (%q,%q); an organization is filed under %s",
				owner, got.Owner, got.Name, policy.AdminOrg)
		}
		if c := code(t, err); c != http.StatusBadRequest {
			t.Fatalf("owner %q: status %d, want %d", owner, c, http.StatusBadRequest)
		}
	}

	// And nothing was written, so a name nobody has taken is still free.
	if org, err := store.GetOrganizationByName(ctx, db, "victim"); err != nil || org != nil {
		t.Fatalf("a refused create left a row: %+v (%v)", org, err)
	}
}

// The positive control. The one legal owner still creates, the name resolves back
// to exactly that row, and the row is keyed by its natural key — so a second row
// under one (owner, name) is not something a later writer can reach.
func TestCreate_UnderTheRegistryOwnerResolvesByName(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()

	created, err := api.Create(ctx, createIn(policy.AdminOrg, "acme"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Owner != policy.AdminOrg || created.Name != "acme" {
		t.Fatalf("created (%q,%q)", created.Owner, created.Name)
	}

	got, err := store.GetOrganizationByName(ctx, db, "acme")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.Owner != policy.AdminOrg || got.Name != "acme" {
		t.Fatalf("a name did not resolve to the organization it names: %+v", got)
	}
	if id := got.Id(); id != policy.AdminOrg+"/acme" {
		t.Fatalf("row key = %q, want %q", id, policy.AdminOrg+"/acme")
	}
}
