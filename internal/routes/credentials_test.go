// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// In an org whose name the platform holds, an admin is not its members'
// credential administrator: hanzo's admin changes no member's password, address,
// phone or second factor. The person does, and a SuperAdmin does on the trail.
// A customer org's admin still administers its own members.
func TestAHeldOrgsAdminChangesNoMembersCredentials(t *testing.T) {
	h := newHarness(t)
	boss, root, bob := h.person(t, "hanzo/boss"), h.person(t, "admin/root"), h.person(t, "orgb/bob")
	seedUser(t, h.db, "orgb", "carol", false)

	for _, body := range []string{
		`{"user":{},"password":"a whole new password"}`,
		`{"user":{"email":"taken@evil.test"}}`,
		`{"user":{"phone":"+15550100"}}`,
	} {
		if status, resp := h.send(t, boss, "PUT", "/v1/iam/users/hanzo/alice", body); status != 403 {
			t.Fatalf("hanzo's admin changed a member's sign-in with %s: %d %s", body, status, resp)
		}
	}
	if status, resp := h.send(t, boss, "DELETE", "/v1/iam/mfa", `{"owner":"hanzo","name":"alice"}`); status != 403 {
		t.Fatalf("hanzo's admin turned off a member's second factor: %d %s", status, resp)
	}
	// A profile edit that leaves sign-in alone is still the admin's.
	if status, resp := h.send(t, boss, "PUT", "/v1/iam/users/hanzo/alice", `{"user":{"displayName":"Alice"}}`); status != 200 {
		t.Fatalf("hanzo's admin could not edit a member's profile: %d %s", status, resp)
	}

	if status, resp := h.send(t, root, "PUT", "/v1/iam/users/hanzo/alice", `{"user":{"displayName":"Alice"},"password":"a whole new password"}`); status != 200 {
		t.Fatalf("a SuperAdmin could not reset a member: %d %s", status, resp)
	}
	rows, err := orm.TypedQuery[schema.AuditLog](h.db).Filter("Action=", schema.ActionSuperAdmin).GetAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, r := range rows {
		seen = seen || (r.User == "hanzo/alice" && strings.Contains(r.Object, "credentials:password"))
	}
	if !seen {
		t.Fatal("a SuperAdmin's credential change left no audit row")
	}

	if status, resp := h.send(t, bob, "PUT", "/v1/iam/users/orgb/carol", `{"user":{},"password":"a whole new password"}`); status != 200 {
		t.Fatalf("a customer org's admin could not reset its member: %d %s", status, resp)
	}
}
