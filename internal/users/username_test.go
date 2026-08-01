// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package users

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Create is the ONE write every account-creation path reaches — password signup,
// social federation, SCIM, the legacy add-user verb, the typed CRUD create and the
// embedder seam. Before the rule lived here, exactly one of those validated the
// name it wrote and the other five persisted whatever bytes arrived, so the rule
// is pinned at the choke point rather than once per caller.
func TestCreate_NormalizesAndValidatesUsername(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   string
		want  string // "" = must be refused
		stays bool   // the refused name must not exist under any spelling
	}{
		{name: "display name refused", raw: "Zach Kelling", stays: true},
		{name: "case is folded", raw: "Z", want: "z"},
		{name: "mixed case is folded", raw: "Alice", want: "alice"},
		{name: "padding is trimmed", raw: "  bob  ", want: "bob"},
		{name: "email refused", raw: "z@hanzo.ai", stays: true},
		{name: "slash refused", raw: "foo/bar", stays: true},
		{name: "tab refused", raw: "a\tb", stays: true},
		{name: "handle survives", raw: "z.kelling-1", want: "z.kelling-1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			api, closeDB := openUsersTestDB(t)
			defer closeDB()

			out, err := api.Create(ctx, &CreateInput{
				User:     schema.User{Owner: "hanzo", Name: tc.raw, Email: "u@hanzo.ai"},
				Password: "correct horse battery staple",
			})
			if tc.want == "" {
				if err == nil {
					t.Fatalf("Create(%q) succeeded as %q; want refusal", tc.raw, out.Name)
				}
				if tc.stays {
					for _, spelling := range []string{tc.raw, strings.ToLower(tc.raw)} {
						if u, _ := store.GetUserByName(ctx, api.db, "hanzo", spelling); u != nil {
							t.Errorf("a user named %q exists after the refusal", spelling)
						}
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("Create(%q): %v", tc.raw, err)
			}
			if out.Name != tc.want {
				t.Fatalf("Create(%q) stored %q, want %q", tc.raw, out.Name, tc.want)
			}
			// What was STORED is what resolves: the row is reachable under the
			// normalized name, and under the raw spelling too.
			got, err := store.GetUserByName(ctx, api.db, "hanzo", tc.want)
			if err != nil || got == nil {
				t.Fatalf("stored user %q does not resolve: %v, %v", tc.want, got, err)
			}
			if got, err := store.GetUserByName(ctx, api.db, "hanzo", tc.raw); err != nil || got == nil {
				t.Fatalf("user is not reachable under the spelling %q it was created with", tc.raw)
			}
		})
	}
}

// Case does not make a second person. The uniqueness check used to run a
// case-SENSITIVE query, so "Alice" was admitted next to "alice" and the two rows
// were one principal to every human and two to the store.
func TestCreate_CaseVariantIsTheSamePrincipal(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	if _, err := api.Create(ctx, &CreateInput{User: schema.User{Owner: "hanzo", Name: "alice"}}); err != nil {
		t.Fatalf("create alice: %v", err)
	}
	if _, err := api.Create(ctx, &CreateInput{User: schema.User{Owner: "hanzo", Name: "Alice"}}); err == nil {
		t.Fatal("\"Alice\" was created alongside \"alice\" — one principal, two rows")
	}
	// A different org is a different tenant, so the same name is free there.
	if _, err := api.Create(ctx, &CreateInput{User: schema.User{Owner: "lux", Name: "Alice"}}); err != nil {
		t.Fatalf("create lux/Alice: %v", err)
	}
}

// A legacy row keeps the spelling it was stored with — renaming it would move a
// real principal — so the RESOLUTION is what tolerates case. This writes a
// mixed-case row the way a pre-rule path did, then resolves it both ways.
func TestGetUserByName_ResolvesLegacyMixedCase(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	legacy := &schema.User{Owner: "hanzo", Name: "Zed"}
	legacy.Init(api.db)
	if err := legacy.Create(); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	for _, spelling := range []string{"Zed", "zed", "ZED"} {
		got, err := store.GetUserByName(ctx, api.db, "hanzo", spelling)
		if err != nil {
			t.Fatalf("GetUserByName(%q): %v", spelling, err)
		}
		if got == nil {
			t.Fatalf("GetUserByName(%q) found nothing; the legacy row is unreachable", spelling)
		}
		if got.Name != "Zed" {
			t.Fatalf("GetUserByName(%q) = %q; the stored spelling must be returned unchanged", spelling, got.Name)
		}
	}
}

// Two legacy rows that differ only in case make "which one?" unanswerable, so the
// fold FAILS CLOSED rather than handing back the storage engine's arbitrary first
// row — otherwise whoever registered the second one could be resolved as the
// first. An exact match still wins, so neither row loses access to itself.
func TestGetUserByName_AmbiguousFoldFailsClosed(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	for _, name := range []string{"Ann", "ANN"} {
		u := &schema.User{Owner: "hanzo", Name: name}
		u.Init(api.db)
		if err := u.Create(); err != nil {
			t.Fatalf("seed %q: %v", name, err)
		}
	}
	if _, err := store.GetUserByName(ctx, api.db, "hanzo", "ann"); err == nil {
		t.Fatal("an ambiguous fold resolved to a row; it must refuse")
	}
	for _, exact := range []string{"Ann", "ANN"} {
		got, err := store.GetUserByName(ctx, api.db, "hanzo", exact)
		if err != nil || got == nil || got.Name != exact {
			t.Fatalf("exact %q must still resolve to itself, got %v, %v", exact, got, err)
		}
	}
}
