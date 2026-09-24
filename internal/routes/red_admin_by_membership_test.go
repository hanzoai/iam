// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// THE COMBINATION. z is the SuperAdmin: account in hanzo, made an operator by an
// admin-org membership. mallory joined hanzo from a personal account with an admin
// membership — a legitimate way to be an org admin under this branch. Widening org
// admin to membership means mallory now passes the org-admin gate for hanzo's
// rows, and hanzo/z is one of hanzo's rows. Without the superadmin-target gate
// (users.Authorize), mallory resets the platform operator's password.
func TestRed_AdminByMembershipCannotResetTheSuperAdmin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	seedUser(t, h.db, "hanzo", "z", false) // the operator's account lives here
	if _, err := store.EnsureMembership(ctx, h.db, "hanzo/z", "admin", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if super, err := store.IsSuperAdmin(ctx, h.db, "hanzo", "z"); err != nil || !super {
		t.Fatalf("hanzo/z is not a SuperAdmin (%v,%v)", super, err)
	}

	seedUser(t, h.db, "mallory", "mallory", false) // a personal account
	if _, err := store.EnsureMembership(ctx, h.db, "mallory/mallory", "hanzo", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	reset := `{"user":{"email":"attacker@evil.test"},"password":"a whole new password"}`
	status, body := h.put(t, "mallory/mallory", "/v1/iam/users/hanzo/z", reset)

	u, err := store.GetUserByName(ctx, h.db, "hanzo", "z")
	if err != nil {
		t.Fatal(err)
	}
	if status == 200 || u.PasswordHash != secretUserHash {
		t.Fatalf("an admin-by-membership of hanzo reset the SuperAdmin: status=%d hash=%q body=%s",
			status, u.PasswordHash, body)
	}
}

// The narrower half, which SHOULD hold on this branch: an admin-by-membership of
// an ORDINARY org resets that org's ordinary user. This is the intended widening.
func TestRed_AdminByMembershipRunsAnOrdinaryOrg(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	seedUser(t, h.db, "acme", "worker", false)
	seedUser(t, h.db, "dana", "dana", false)
	if _, err := store.EnsureMembership(ctx, h.db, "dana/dana", "acme", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if status, body := h.put(t, "dana/dana", "/v1/iam/users/acme/worker",
		`{"user":{"displayName":"Worker"}}`); status != 200 {
		t.Fatalf("acme's admin-by-membership could not edit its worker: %d %s", status, body)
	}
	// A plain member of acme edits nobody.
	seedUser(t, h.db, "sam", "sam", false)
	if _, err := store.EnsureMembership(ctx, h.db, "sam/sam", "acme", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if status, _ := h.put(t, "sam/sam", "/v1/iam/users/acme/worker",
		`{"user":{"displayName":"Hijacked"}}`); status != 403 {
		t.Errorf("a plain member of acme edited its worker: %d", status)
	}
}
