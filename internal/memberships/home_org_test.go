// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package memberships_test

// A revoke must not report one it did not perform. A (user, org)
// pair whose org is the user's OWN home org names tenancy MemberOrgRefs grants
// from the user row, so deleting the row subtracts nothing from the `orgs` claim:
// the person kept the org on every token minted afterwards while the roster showed
// them gone. The verb now refuses that pair and names the operation that ends the
// access.
//
// The refusal is about what the relation can express, not about who is asking, so
// it applies to a SuperAdmin exactly as it does to an org admin.

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

const notRevocable = "this account belongs to that organization, so its access comes from the account and not from a membership row — disable or delete the user to end it"

// The home-org pair is refused, the row is LEFT ALONE, and the message names the
// operation that works. Refusing while deleting would be the same lie in a
// different envelope.
func TestDeleteMembership_homeOrgIsRefusedAndTheRowSurvives(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	seedMembership(t, h.db, "hanzo/alice", "hanzo", store.RoleMember)

	// 400 + the error envelope: the same shape every other refusal on this
	// surface answers with (httpx.Err), so a client needs no new branch.
	status, e := h.del(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/alice", "org": "hanzo"}, super)
	if status != 400 || e.Status != "error" {
		t.Fatalf("home-org delete status=%d env=%+v, want 400 + the error envelope", status, e)
	}
	if e.Msg != notRevocable {
		t.Fatalf("msg = %q, want the home-org refusal", e.Msg)
	}
	if !strings.Contains(e.Msg, "disable or delete the user") {
		t.Fatalf("refusal must name the operation that ends the access, got %q", e.Msg)
	}
	// The roster row is untouched: it is the org's membership list, and the
	// refusal is that the CLAIM cannot be changed here, not that the row is bad.
	if m, _ := store.GetMembership(context.Background(), h.db, "hanzo/alice", "hanzo"); m == nil {
		t.Fatal("refused delete removed the row anyway")
	}
}

// A SuperAdmin is refused too. This is not an authority the reserved org can
// override — the claim would be unchanged for them as well.
func TestDeleteMembership_homeOrgRefusedForSuperAdminToo(t *testing.T) {
	h := newHarness(t)
	seedMembership(t, h.db, "hanzo/alice", "hanzo", store.RoleAdmin)

	for _, caller := range []struct{ who, sub string }{
		{"super", "admin/root"},
		{"org admin", "hanzo/boss"},
	} {
		_, e := h.del(t, "/v1/iam/memberships",
			map[string]string{"user": "hanzo/alice", "org": "hanzo"}, h.token(t, caller.sub))
		if e.Status != "error" || e.Msg != notRevocable {
			t.Errorf("%s: env=%+v, want the home-org refusal", caller.who, e)
		}
	}
}

// THE REGRESSION GUARD: a TEAM-org revoke is the case that actually reaches the
// claim, and it must keep working exactly as before — removed=true, row gone,
// still idempotent.
func TestDeleteMembership_teamOrgStillRevokes(t *testing.T) {
	h := newHarness(t)
	super := h.token(t, "admin/root")
	seedMembership(t, h.db, "hanzo/alice", "team-x", store.RoleAdmin)

	status, e := h.del(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/alice", "org": "team-x"}, super)
	if status != 200 || e.Status != "ok" || !parseBool(t, e) {
		t.Fatalf("team-org delete status=%d env=%+v, want 200 ok removed=true", status, e)
	}
	if m, _ := store.GetMembership(context.Background(), h.db, "hanzo/alice", "team-x"); m != nil {
		t.Fatal("team membership survived delete")
	}
	// And the resolver agrees — the row is what granted team-x, so it is gone.
	u, err := store.GetUserByName(context.Background(), h.db, "hanzo", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if u != nil {
		for _, r := range store.MemberOrgRefs(context.Background(), h.db, u) {
			if r.Org == "team-x" {
				t.Fatal("team-x still in the resolved membership set after delete")
			}
		}
	}
}

// The refusal sits AFTER the authorization gate, so it is not an oracle: a caller
// with no authority over the org is told it is unauthorized and learns nothing
// about whose home org it is.
func TestDeleteMembership_unauthorizedCallerLearnsNothingAboutHomeOrgs(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss") // admin of hanzo, NOT of orgb
	seedMembership(t, h.db, "orgb/bob", "orgb", store.RoleMember)

	_, e := h.del(t, "/v1/iam/memberships",
		map[string]string{"user": "orgb/bob", "org": "orgb"}, boss)
	if e.Status != "error" {
		t.Fatalf("cross-tenant home-org delete env=%+v, want an error", e)
	}
	if e.Msg != "auth:Unauthorized operation" {
		t.Fatalf("msg = %q, want the unauthorized refusal — the home-org reason must not leak "+
			"to a caller with no authority over that org", e.Msg)
	}
}

// The predicate itself: the owner segment of the natural key IS the home org.
// Nothing else in the pair matters, and a malformed key names no home org.
func TestIsHomeOrg(t *testing.T) {
	for _, tc := range []struct {
		user, org string
		want      bool
	}{
		{"hanzo/alice", "hanzo", true},
		{"hanzo/alice", "team-x", false},
		{"orgb/bob", "hanzo", false},
		{"alice", "hanzo", false},    // no owner segment
		{"/alice", "", false},        // empty owner never matches
		{"hanzo/a/b", "hanzo", true}, // owner is the FIRST segment
	} {
		if got := store.IsHomeOrg(tc.user, tc.org); got != tc.want {
			t.Errorf("IsHomeOrg(%q, %q) = %v, want %v", tc.user, tc.org, got, tc.want)
		}
	}
}
