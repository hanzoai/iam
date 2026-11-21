// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/pkg/schema"
)

// A NAME IN THE RESERVED TABLE IS NEVER CREATABLE. An org's issuer lives at
// `<tenant origin>/<org>`, so a name the hanzo.ai site, its edge or IAM's root answers to
// must not become an organization. This fails when any name in schema.ReservedSlugs()
// that has the shape of an org name can be created through the handler.
func TestCreate_refusesEveryReservedSlug(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	shaped := 0
	for _, n := range schema.ReservedSlugs() {
		if schema.OrgName(n) != nil {
			continue // not an org name to begin with
		}
		shaped++
		if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, n)))); got != 400 {
			t.Errorf("Create(%q): status=%d, want 400: a reserved slug was creatable", n, got)
		}
	}
	if shaped < 150 {
		t.Fatalf("only %d reserved slugs have an org name's shape; the table lost entries", shaped)
	}
	// A name beside the table is still free.
	if _, err := api.Create(ctx, createIn(policy.AdminOrg, "pricing-acme")); err != nil {
		t.Fatalf("a free name was refused: %v", err)
	}
}
