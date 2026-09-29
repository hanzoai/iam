// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/internal/testdb"
	"github.com/hanzoai/iam/pkg/store"
)

// THE COMBINATION. admin/z is the SuperAdmin and also works in hanzo by a
// membership. mallory joined hanzo from a personal account with an admin
// membership — a legitimate way to be an org admin. Neither mallory's hold on
// hanzo nor an admin-org membership mallory might be given reaches the operator's
// account: it lives in the admin org, which only a SuperAdmin writes.
func TestRed_AdminByMembershipCannotResetTheSuperAdmin(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()

	seedUser(t, h.db, "admin", "z", false) // the operator's account lives here
	seedUser(t, h.db, "mallory", "mallory", false)
	for _, m := range [][3]string{
		{"admin/z", "hanzo", store.RoleMember},
		{"mallory/mallory", "hanzo", store.RoleAdmin},
		{"mallory/mallory", "admin", store.RoleAdmin},
	} {
		if err := testdb.Member(ctx, h.db, m[0], m[1], m[2]); err != nil {
			t.Fatal(err)
		}
	}

	reset := `{"user":{"email":"attacker@evil.test"},"password":"a whole new password"}`
	status, body := h.put(t, "mallory/mallory", "/v1/iam/users/admin/z", reset)

	u, err := store.GetUserByName(ctx, h.db, "admin", "z")
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
