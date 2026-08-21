// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package applications

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// THE ADMIN ROUND-TRIP MUST NOT DE-SECRET AN APP.
//
// update-application is a full REPLACE and every read MASKS the client secret, so
// "read the record, change one field, write it back" — the only shape an admin UI
// or an operator has — posts ClientSecret:"" for an app that holds one, so the
// write would blank it and silently turn a confidential client public. The token
// endpoint reads a stored empty secret as "public client, demand no client auth",
// so the blast radius is every flow that app serves.

func seedConfidential(t *testing.T, db orm.DB, name, secret string) *schema.Application {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name = "admin", name
	a.ClientId, a.ClientSecret = name, secret
	a.Organization = "hanzo"
	a.SetId("admin/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
	return a
}

// The regression: a write echoing a MASKED read preserves the credential.
func TestUpdate_MaskedRoundTripPreservesTheSecret(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedConfidential(t, db, "hanzo-console", "s3cret-do-not-lose-me")

	// Exactly what an admin round-trip carries: the record as READ (secret masked
	// to ""), with one unrelated field changed.
	echoed := &schema.Application{
		Owner: "admin", Name: "hanzo-console", ClientId: "hanzo-console",
		Organization: "hanzo", ClientSecret: "", EnableSignUp: false,
	}
	if _, err := Update(db)(ctx, echoed); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err := orm.Get[schema.Application](db, "admin/hanzo-console")
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if got.ClientSecret != "s3cret-do-not-lose-me" {
		t.Fatalf("the admin round-trip DE-SECRETED the app: ClientSecret = %q, want it preserved.\n"+
			"An empty secret is what the token endpoint reads as 'public client, no client auth'.",
			got.ClientSecret)
	}
	if got.EnableSignUp {
		t.Errorf("the field the caller actually meant to change did not land")
	}
}

// Rotation stays possible — it just has to be deliberate.
func TestUpdate_ExplicitSecretStillRotates(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedConfidential(t, db, "rotate-me", "old-secret")

	in := &schema.Application{
		Owner: "admin", Name: "rotate-me", ClientId: "rotate-me",
		Organization: "hanzo", ClientSecret: "brand-new-secret",
	}
	if _, err := Update(db)(ctx, in); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := orm.Get[schema.Application](db, "admin/rotate-me")
	if got.ClientSecret != "brand-new-secret" {
		t.Fatalf("deliberate rotation was swallowed: %q", got.ClientSecret)
	}
}

// An app that genuinely has no secret stays that way — preserving "" is not the
// same as minting one.
func TestUpdate_PublicClientStaysPublic(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedConfidential(t, db, "public-spa", "")

	in := &schema.Application{
		Owner: "admin", Name: "public-spa", ClientId: "public-spa",
		Organization: "hanzo", ClientSecret: "",
	}
	if _, err := Update(db)(ctx, in); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ := orm.Get[schema.Application](db, "admin/public-spa")
	if got.ClientSecret != "" {
		t.Fatalf("a public client was handed a secret it never had: %q", got.ClientSecret)
	}
}
