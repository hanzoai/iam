// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The person a create names as Founder is the new org's first owner, and a
// Founder naming no live person creates nothing.
func TestCreate_TheFounderOwnsTheOrg(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Id = "hanzo", "ann", "uuid-ann"
	u.SetId("hanzo/ann")
	if err := u.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}

	in := createIn("admin", "acme")
	in.Founder = "uuid-ann"
	if _, err := api.Create(ctx, in); err != nil {
		t.Fatal(err)
	}
	if owners, err := store.Owners(ctx, db, "acme"); err != nil || len(owners) != 1 || owners[0] != "hanzo/ann" {
		t.Fatalf("owners = %v (err=%v), want [hanzo/ann]", owners, err)
	}
	if k, err := orm.Get[schema.Key](db, "acme/acme-app"); err != nil || k.Application != "acme-app" {
		t.Fatalf("the new org's publishable key = %+v (err=%v), want one naming acme-app", k, err)
	}

	bad := createIn("admin", "ghost")
	bad.Founder = "uuid-nobody"
	if _, err := api.Create(ctx, bad); code(t, err) != http.StatusBadRequest {
		t.Fatalf("a founder naming nobody: %v, want 400", err)
	}
	if o, _ := store.GetOrganizationByName(ctx, db, "ghost"); o != nil {
		t.Fatal("an org was created for a founder naming nobody")
	}
}
