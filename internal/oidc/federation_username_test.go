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
	for _, spelling := range []string{"Grace Hopper", "gracehopper", "Grace Hopper"} {
		if u, _ := store.GetUserByName(ctx, db, "hanzo", spelling); u != nil {
			t.Fatalf("an account named %q was created from the IdP display name", spelling)
		}
	}
}

// A provider that keeps a handle (GitHub's login) names the new account after it,
// lowercased, when nobody holds it; one that is held is not numbered into a name
// that reads as another person's ("octocat2"), and the address's name is used
// instead; a provider with no handle (Google) names it from the address as before.
func TestProvisionFederatedUser_TakesTheProvidersHandleWhenFree(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	app := &schema.Application{Organization: "hanzo"}
	app.Name = "console"
	provision := func(typ, subject string, id federatedIdentity) *schema.User {
		t.Helper()
		prov := &schema.Provider{Type: typ}
		prov.Name = "provider-" + typ
		binding, ok := connectorFor(prov.Type)
		if !ok {
			t.Fatalf("no connector binding for %q", prov.Type)
		}
		id.subject = subject
		u, err := provisionFederatedUser(ctx, db, app, prov, binding, id)
		if err != nil {
			t.Fatalf("provision %s/%s: %v", typ, subject, err)
		}
		return u
	}

	// GitHub, its login free: the account is named after it, and the profile name stays the display name.
	u := provision("GitHub", "92065535", federatedIdentity{email: "wbin90620@gmail.com", displayName: "Darkhorse7stars", handle: "Darkhorse7stars"})
	if u.Name != "darkhorse7stars" {
		t.Fatalf("GitHub signup named %q, want its login %q", u.Name, "darkhorse7stars")
	}
	if u.DisplayName != "Darkhorse7stars" {
		t.Fatalf("display name = %q, want the profile's", u.DisplayName)
	}

	// GitHub, its login already held here: the address's name, never "octocat2".
	if _, err := users.New(db).Create(ctx, &users.CreateInput{User: schema.User{Owner: "hanzo", Name: "octocat"}}); err != nil {
		t.Fatalf("seed hanzo/octocat: %v", err)
	}
	u = provision("GitHub", "583231", federatedIdentity{email: "mona@example.com", displayName: "The Octocat", handle: "octocat"})
	if u.Name != "mona" {
		t.Fatalf("GitHub signup with a held login named %q, want the address's %q", u.Name, "mona")
	}

	// GitHub with no usable login, and Google, which keeps none: the address's name.
	u = provision("GitHub", "1", federatedIdentity{email: "ada@example.com", displayName: "Ada Lovelace", handle: ""})
	if u.Name != "ada" {
		t.Fatalf("GitHub signup with no login named %q, want %q", u.Name, "ada")
	}
	u = provision("Google", "google-sub-1", federatedIdentity{email: "grace@example.com", displayName: "Grace Hopper"})
	if u.Name != "grace" {
		t.Fatalf("Google signup named %q, want the address's %q", u.Name, "grace")
	}
	if got, _ := store.GetUserByName(ctx, db, "hanzo", "grace hopper"); got != nil {
		t.Fatal("an account was named from a display name")
	}
}
