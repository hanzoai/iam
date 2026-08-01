// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
	"github.com/hanzoai/iam/internal/users"
)

// A social signup gets its username from the ADDRESS. The IdP hands over a
// profile display name too — "Zach Kelling" is what Google returns for z@hanzo.ai
// — and it reaches DisplayName and nothing else. If it could reach the username,
// this repo would hold an account literally named "Zach Kelling", which is the
// second of the two ways the wrong principal could have ended up on a token.
func TestFederatedUsername_DerivesFromEmail(t *testing.T) {
	for _, tc := range []struct {
		name     string
		email    string
		provider string
		attempt  int
		want     string
	}{
		{"the local part", "z@hanzo.ai", "google", 1, "z"},
		{"case folded", "Zach.Kelling@hanzo.ai", "google", 1, "zach.kelling"},
		{"subaddress dropped", "z+ci@hanzo.ai", "github", 1, "zci"},
		// Dedupe is a NUMERIC suffix on the name a person would have chosen. It
		// replaced a random 8-hex suffix on every name ("z-3f9ab21c"), which made
		// collisions impossible by making every username unrecognisable.
		{"second attempt", "z@hanzo.ai", "google", 2, "z2"},
		{"tenth attempt", "z@hanzo.ai", "google", 10, "z10"},
		// No usable address: the provider TYPE, never the display name.
		{"no address falls back to provider", "", "google", 1, "google"},
		{"unusable address falls back to provider", "!!!@hanzo.ai", "github", 1, "github"},
		{"nothing usable at all", "", "", 1, "user"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := federatedUsername(tc.email, tc.provider, tc.attempt)
			if got != tc.want {
				t.Fatalf("federatedUsername(%q, %q, %d) = %q, want %q", tc.email, tc.provider, tc.attempt, got, tc.want)
			}
			// Whatever it derives must be storable as-is.
			if _, err := schema.Username(got); err != nil {
				t.Fatalf("derived %q, which the username rule refuses: %v", got, err)
			}
		})
	}
}

// The dedupe walk against a real store: the first free name wins, so the second
// person whose address starts with "z" gets "z2" rather than taking "z" from the
// first, and neither gets a random suffix.
func TestProvisionFederatedUser_DedupesWithANumericSuffix(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"))
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
			displayName: "Zach Kelling", // the trap: never a username
		}
		u, err := provisionFederatedUser(ctx, db, app, prov, binding, id)
		if err != nil {
			t.Fatalf("provision %d: %v", i, err)
		}
		if u.Name != want {
			t.Fatalf("provisioned username %q, want %q", u.Name, want)
		}
		if u.DisplayName != "Zach Kelling" {
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
	for _, spelling := range []string{"Zach Kelling", "zachkelling", "zach kelling"} {
		if u, _ := store.GetUserByName(ctx, db, "hanzo", spelling); u != nil {
			t.Fatalf("an account named %q was created from the IdP display name", spelling)
		}
	}
}
