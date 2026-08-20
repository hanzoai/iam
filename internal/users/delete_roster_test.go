// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Deleting an account takes it off every roster it was on. The rows are what an
// org's member list is built from, so an account deleted while they remain is a
// person who no longer exists still listed as able to act.
//
// This drives API.Delete rather than store.ForgetUser, so it is the CALL that is
// under test: removing the cleanup from Delete must fail here, which asserting on
// the store helper alone would not catch.
func TestDelete_TakesTheAccountOffEveryRoster(t *testing.T) {
	ctx := context.Background()
	db := consentTestDB(t)
	api := New(db)

	for _, name := range []string{"dave", "boss"} {
		if _, err := api.Create(ctx, &CreateInput{
			User: schema.User{Owner: "hanzo", Name: name},
			Type: "normal-user",
		}); err != nil {
			t.Fatalf("create %s: %v", name, err)
		}
	}
	// dave belongs to his home org and two teams; boss shares one of them.
	for _, org := range []string{"hanzo", "team-x", "team-y"} {
		if _, err := store.EnsureMembership(ctx, db, "hanzo/dave", org, store.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.EnsureMembership(ctx, db, "hanzo/boss", "team-x", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	out, err := api.Delete(ctx, &Ref{Owner: "hanzo", Name: "dave"})
	if err != nil || out == nil || !out.Deleted {
		t.Fatalf("delete: out=%+v err=%v", out, err)
	}

	for _, org := range []string{"hanzo", "team-x", "team-y"} {
		rows, err := store.MembershipsByOrg(ctx, db, org)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			if r.User == "hanzo/dave" {
				t.Errorf("GHOST: deleted account still on the %s roster", org)
			}
		}
	}

	// THE BYSTANDER: deleting one account must not empty a shared roster.
	rows, err := store.MembershipsByOrg(ctx, db, "team-x")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].User != "hanzo/boss" {
		t.Fatalf("team-x roster = %+v, want only hanzo/boss — forgetting one account is not a purge", rows)
	}
}

// Deleting an account that holds no membership rows is unremarkable: the cleanup
// removes nothing and the delete still reports success.
func TestDelete_WithNoMembershipsStillSucceeds(t *testing.T) {
	ctx := context.Background()
	db := consentTestDB(t)
	api := New(db)

	if _, err := api.Create(ctx, &CreateInput{
		User: schema.User{Owner: "hanzo", Name: "solo"},
		Type: "normal-user",
	}); err != nil {
		t.Fatal(err)
	}
	out, err := api.Delete(ctx, &Ref{Owner: "hanzo", Name: "solo"})
	if err != nil || out == nil || !out.Deleted {
		t.Fatalf("delete: out=%+v err=%v", out, err)
	}
}
