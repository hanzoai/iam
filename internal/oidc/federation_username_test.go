// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The dedupe walk against a real store: the first free name wins, so the second
// person whose address starts with "z" gets "z2" rather than taking "z" from the
// first, and neither gets a random suffix.
func TestProvisionFederatedUser_DedupesWithANumericSuffix(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	app := &schema.Application{Organization: "hanzo"}
	app.Name = "console"
	prov := &schema.Provider{Type: "Google"}
	prov.Name = "google"
	binding, ok := connectorFor(prov.Type)
	if !ok {
		t.Fatalf("no connector binding for %q", prov.Type)
	}

	// The name a human already holds. A social signup must not be handed it.
	if _, err := users.New(db).Create(ctx, &users.CreateInput{User: schema.User{Owner: "hanzo", Name: "z"}}); err != nil {
		t.Fatalf("seed hanzo/z: %v", err)
	}

	for i, want := range []string{"z2", "z3"} {
		id := federatedIdentity{
			subject:     string(rune('a'+i)) + "-idp-subject",
			email:       "z@example.com",
			displayName: "Grace Hopper", // the trap: never a username
		}
		u, err := provisionFederatedUser(ctx, db, app, prov, binding, id)
		if err != nil {
			t.Fatalf("provision %d: %v", i, err)
		}
		if u.Name != want {
			t.Fatalf("provisioned username %q, want %q", u.Name, want)
		}
		if u.DisplayName != "Grace Hopper" {
			t.Fatalf("display name = %q; it belongs on DisplayName, unchanged", u.DisplayName)
		}
	}

	// The seeded human still owns "z", under every spelling of it.
	for _, spelling := range []string{"z", "Z"} {
		got, err := store.GetUserByName(ctx, db, "hanzo", spelling)
		if err != nil || got == nil || got.Name != "z" {
			t.Fatalf("hanzo/%s = %v, %v; the original holder must keep the name", spelling, got, err)
		}
	}
	// And no account is named after the human.
	for _, spelling := range []string{"Grace Hopper", "zachkelling", "Grace Hopper"} {
		if u, _ := store.GetUserByName(ctx, db, "hanzo", spelling); u != nil {
			t.Fatalf("an account named %q was created from the IdP display name", spelling)
		}
	}
}
