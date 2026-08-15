// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The identity CLASS — schema.User.Type, and the org-admin bit — is not a profile
// field, it is a money rule. store.BillingAccount answers "org:<slug>" for a row
// that is EITHER machine-typed OR an admin of its home org; IAM signs that as the
// `billing_account` claim; and account.Payer honours a signed claim above every
// other signal. In the shared signup org that account is the platform's own
// balance, so either field, stated by a request, is a written claim on it.
//
// Both user writes are FULL-ROW writes that bind a whole schema.User from the
// body, and both are reachable by any org admin over any member of their org — via
// the typed CRUD (POST /v1/iam/users, /v1/iam/users/update) and via the legacy
// add-user/update-user verbs, which land on these same two functions. So the rule
// belongs here, at the one write they share, and it is the same rule SCIM already
// states for itself: the class comes from the calling CODE, never the body.
//
// billingClaim asks the money question exactly as the token mint asks it
// (identityOf → store.BillingAccount over store.MemberOrgRefs).
func billingClaim(t *testing.T, api *API, name string) string {
	t.Helper()
	ctx := context.Background()
	u, err := api.lookup(ctx, "hanzo", name)
	if err != nil || u == nil {
		t.Fatalf("read back %s: %v", name, err)
	}
	return store.BillingAccount(u, store.MemberOrgRefs(ctx, api.db, u))
}

// A body cannot PLANT a pool-spending row. This is the sharper half of the defect:
// machine-typing alone reaches the pool with isAdmin left false, so a created row
// spends the platform balance while showing nothing on an admin roster.
func TestCreate_BodyCannotChooseItsClass(t *testing.T) {
	db := consentTestDB(t)
	api := New(db)

	created, err := api.Create(context.Background(), &CreateInput{
		User: schema.User{
			Owner: "hanzo", Name: "planted",
			Type:    "service-account", // the body asks to be a machine
			IsAdmin: true,              // and an admin, for good measure
		},
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Type != "" || created.IsAdmin {
		t.Fatalf("body chose its own class: type=%q isAdmin=%v", created.Type, created.IsAdmin)
	}
	if got := billingClaim(t, api, "planted"); got != "" {
		t.Fatalf("a created row named the pool: billing_account=%q, want \"\"", got)
	}
}

// A body cannot RE-CLASS an existing member. An org admin editing a colleague's
// profile must not be able to turn them into a machine, or into an admin.
func TestUpdate_BodyCannotReclassAMember(t *testing.T) {
	db := consentTestDB(t)
	api := New(db)
	seedMember(t, api, "victim", nil)

	updated, err := api.Update(context.Background(), &UpdateInput{
		User: schema.User{
			Owner: "hanzo", Name: "victim",
			Type:        "service-account",
			IsAdmin:     true,
			DisplayName: "Victim", // a real profile edit rides along
		},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.Type != "" || updated.IsAdmin {
		t.Fatalf("body re-classed a member: type=%q isAdmin=%v", updated.Type, updated.IsAdmin)
	}
	if updated.DisplayName != "Victim" {
		t.Fatalf("the profile edit was lost: %q", updated.DisplayName)
	}
	if got := billingClaim(t, api, "victim"); got != "" {
		t.Fatalf("an edited row named the pool: billing_account=%q, want \"\"", got)
	}
}

// The positive controls. Refusing the BODY must not disarm the CODE — SCIM's
// SuperAdmin path raises the admin bit through the in-process field, and signup
// states the person class the same way. Without these, "ignore the class" could be
// satisfied by ignoring it always, which would silently un-admin every operator.
func TestClassIsStatedByTheCallingCode(t *testing.T) {
	db := consentTestDB(t)
	api := New(db)

	// Create: the caller states the class (signup / federation say "normal-user").
	person, err := api.Create(context.Background(), &CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "alice"},
		Password: "correct horse battery staple",
		Type:     "normal-user",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if person.Type != "normal-user" {
		t.Fatalf("the calling code's class was dropped: %q", person.Type)
	}

	// Update: a caller that has checked it may (SCIM under authz.IsSuper) raises
	// the bit, and THAT is what legitimately names the org pool.
	yes := true
	promoted, err := api.Update(context.Background(), &UpdateInput{
		User:  schema.User{Owner: "hanzo", Name: "alice"},
		Admin: &yes,
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !promoted.IsAdmin {
		t.Fatal("an in-process caller could not raise the admin bit")
	}
	if got := billingClaim(t, api, "alice"); got != "org:hanzo" {
		t.Fatalf("a real org admin lost its pool claim: %q, want org:hanzo", got)
	}

	// And nil means "leave it as stored" — a later profile edit must not lower it.
	edited, err := api.Update(context.Background(), &UpdateInput{
		User: schema.User{Owner: "hanzo", Name: "alice", DisplayName: "Alice"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !edited.IsAdmin || edited.Type != "normal-user" {
		t.Fatalf("a profile edit changed the class: type=%q isAdmin=%v", edited.Type, edited.IsAdmin)
	}
}
