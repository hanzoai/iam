// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package authz_test

// Platform authority is MEMBERSHIP of the reserved org, and these drive it through
// the real router so the claim is about what a request gets, not about a struct.
//
// Home is where an identity is ANCHORED — its billing, its default scope. An
// operator is someone an existing SuperAdmin put IN the reserved org, and most are
// anchored in a brand org because they also do ordinary work there. The two
// questions have different answers for the same person, so the guard has to ask
// the second one.

import (
	"context"
	"strings"
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/pkg/store"
)

// grant puts user IN org with role, the way an existing SuperAdmin does.
func grant(t *testing.T, h *harness, user, org, role string) {
	t.Helper()
	if _, err := store.EnsureMembership(context.Background(), h.db, user, org, role); err != nil {
		t.Fatalf("grant %s in %s: %v", user, org, err)
	}
}

// listsEveryTenant reports whether sub reaches the cross-tenant certs listing —
// the SuperAdmin-only surface, since Scope binds everyone else to their own org.
func listsEveryTenant(t *testing.T, h *harness, sub string) bool {
	t.Helper()
	status, body := h.doBody(t, "GET", "/v1/iam/certs", h.token(t, sub), nil)
	return status == 200 && strings.Contains(body, signingKid)
}

// THE CASE THE HOME ORG CANNOT ANSWER: an operator whose account lives in a brand
// org, holding a membership in the reserved one. Reading the home org calls this
// person a tenant user and the reserved org becomes unreachable in practice.
func TestSudoFollowsMembershipNotTheHomeOrg(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "op", false, false, false)
	grant(t, h, "hanzo/op", policy.AdminOrg, store.RoleAdmin)

	if !listsEveryTenant(t, h, "hanzo/op") {
		t.Fatal("an operator anchored in a brand org, holding a membership in the reserved org, was refused platform scope")
	}
}

// The grant is the whole of it. The same account without the membership row is an
// ordinary tenant user, so the predicate is membership and not "anyone in hanzo".
func TestWithoutTheGrantTheSameAccountIsATenantUser(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "op", false, false, false)

	if listsEveryTenant(t, h, "hanzo/op") {
		t.Fatal("a user with no membership in the reserved org reached every tenant")
	}
}

// Anchoring in the reserved org still answers, without a read: the seeded
// admin/root holds platform scope, and a membership only ever adds to that set.
func TestAnchoringInTheReservedOrgStillAnswers(t *testing.T) {
	h := newHarness(t)
	if !listsEveryTenant(t, h, "admin/root") {
		t.Fatal("a user anchored in the reserved org lost platform scope")
	}
}

// ONE reserved org confers it, not the reserved SET. built-in owns signing certs
// and app owns service principals — both are platform trust material and neither
// is the operator scope, so widening the predicate to IsReservedOrg would hand
// platform sudo to every identity filed under a system org.
func TestOnlyTheReservedAdminOrgConfersIt(t *testing.T) {
	h := newHarness(t)
	if listsEveryTenant(t, h, "built-in/svc") {
		t.Fatal("a built-in-org account reached every tenant — the reserved SET is not the operator scope")
	}

	seedUser(t, h.db, "hanzo", "sideways", false, false, false)
	grant(t, h, "hanzo/sideways", "built-in", store.RoleAdmin)
	if listsEveryTenant(t, h, "hanzo/sideways") {
		t.Fatal("a membership in built-in conferred platform scope")
	}

	seedUser(t, h.db, "hanzo", "neighbour", false, false, false)
	grant(t, h, "hanzo/neighbour", "orgb", store.RoleAdmin)
	if listsEveryTenant(t, h, "hanzo/neighbour") {
		t.Fatal("a membership in another tenant conferred platform scope")
	}
}
