// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keys

import (
	"context"
	"slices"
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A client that mints a person's keys in a tenant reads that person's keys back
// there, and nothing else of the tenant's: not its whole set, not its
// integrations (keys that name nobody), not another person's.
//
// Before, the read was pinned to the tenant the client serves while the mint was
// not, so a key minted for a person in their own org was invisible to the
// client that minted it, and its next mint rotated the live key away.
func TestList_AMinterReadsBackOneHoldersKeys(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedUser(t, db, "acme", "ada")
	seedUser(t, db, "acme", "bob")
	if _, err := store.EnsureMembership(ctx, db, "agency/josh", "acme", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	minter := principal.Bind(ctx, &principal.Principal{App: &policy.App{Name: "hanzo-console", Owner: policy.AdminOrg}, Org: "hanzo"})
	for _, k := range []schema.Key{
		{Owner: "acme", Name: "ada-qualified", User: "acme/ada"},
		{Owner: "acme", Name: "ada-bare", User: "ada"},
		{Owner: "acme", Name: "bob-key", User: "acme/bob"},
		{Owner: "acme", Name: "josh-key", User: "agency/josh"},
		{Owner: "acme", Name: "integration"},
	} {
		if _, err := create(db)(minter, &k); err != nil {
			t.Fatalf("mint %s: %v", k.Name, err)
		}
	}
	names := func(who context.Context, in *ListRequest) ([]string, error) {
		out, err := list(db)(who, in)
		if err != nil {
			return nil, err
		}
		var got []string
		for _, k := range out.Keys {
			if k.AccessSecret != "" {
				t.Fatalf("a read disclosed %s's secret", k.Name)
			}
			got = append(got, k.Name)
		}
		slices.Sort(got)
		return got, nil
	}

	for _, c := range []struct {
		user string
		want []string
	}{
		{"acme/ada", []string{"ada-bare", "ada-qualified"}},
		{"ada", []string{"ada-bare", "ada-qualified"}},
		{"agency/josh", []string{"josh-key"}},
		{"acme/nobody", nil},
	} {
		got, err := names(minter, &ListRequest{Owner: "acme", User: c.user})
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("the minter reading %q's keys in acme = %v, %v; want %v", c.user, got, err, c.want)
		}
	}

	// The tenant's whole key set stays the tenant's.
	if _, err := names(minter, &ListRequest{Owner: "acme"}); err == nil || status(t, err) != 403 {
		t.Errorf("the minter listed acme's whole key set: %v", err)
	}
	// A user that names no one is not a way to reach the keys that name no one.
	for _, u := range []string{"acme/", "/ada", "/"} {
		if _, err := names(minter, &ListRequest{Owner: "acme", User: u}); err == nil || status(t, err) != 400 {
			t.Errorf("user %q was read as a holder: %v", u, err)
		}
	}
	// The reserved org stays unreadable.
	if _, err := names(minter, &ListRequest{Owner: policy.AdminOrg, User: "admin/z"}); err == nil {
		t.Error("the minter read keys in the reserved admin org")
	}
	// Naming a holder widens nothing for a person: the tenant rule still decides.
	alice := principal.Bind(ctx, &principal.Principal{Org: "hanzo", User: "alice"})
	if _, err := names(alice, &ListRequest{Owner: "acme", User: "acme/ada"}); err == nil || status(t, err) != 403 {
		t.Errorf("a person of another org read ada's keys: %v", err)
	}
	// And inside a tenant it may read, a holder only narrows.
	boss := principal.Bind(ctx, &principal.Principal{Org: "acme", User: "boss", Admin: true})
	if got, err := names(boss, &ListRequest{Owner: "acme", User: "acme/bob"}); err != nil || !slices.Equal(got, []string{"bob-key"}) {
		t.Errorf("acme's admin narrowing to bob = %v, %v; want [bob-key]", got, err)
	}
}
