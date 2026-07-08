// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package object

import (
	"testing"

	"github.com/hanzoai/iam/conf"
)

// TestIsApproved locks the waitlist gate's fail-OPEN contract: absence of the
// property ⇒ approved (so no existing user is ever locked out — the safety
// guardrail), and ONLY an explicit "pending" tag gates access. Admins are always
// approved. If a future edit makes absent/"" gate access, every pre-existing user
// gets locked out of the console — this test is the tripwire.
func TestIsApproved(t *testing.T) {
	admOrg := conf.AdminOrg
	cases := []struct {
		name string
		u    *User
		want bool
	}{
		{"nil user", nil, false},
		{"no properties -> approved (fail-open, existing users)", &User{Owner: "hanzo", Name: "a"}, true},
		{"empty properties -> approved", &User{Owner: "hanzo", Properties: map[string]string{}}, true},
		{"explicit approved", &User{Owner: "hanzo", Properties: map[string]string{ApprovalStatusProperty: ApprovalApproved}}, true},
		{"explicit pending -> gated", &User{Owner: "hanzo", Properties: map[string]string{ApprovalStatusProperty: ApprovalPending}}, false},
		{"rejected (not pending) -> approved-by-fallthrough", &User{Owner: "hanzo", Properties: map[string]string{ApprovalStatusProperty: "rejected"}}, true},
		{"pending but global admin -> approved", &User{Owner: admOrg, Properties: map[string]string{ApprovalStatusProperty: ApprovalPending}}, true},
		{"pending but org admin -> approved", &User{Owner: "hanzo", IsAdmin: true, Properties: map[string]string{ApprovalStatusProperty: ApprovalPending}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.u.IsApproved(); got != tc.want {
				t.Fatalf("IsApproved() = %v; want %v", got, tc.want)
			}
		})
	}
}

// TestApplyDefaultApprovalStatus is the guard-leak tripwire. AddUser is the ONE
// common creation path; every self-service route (password / SSO / social / web3
// wallet / email-code / OAuth token) flows through it. If a self-registering
// end-user does NOT get stamped "pending" here, IsApproved fail-open treats them
// as approved and they walk straight through the waitlist-guard (Red's finding).
// Trusted/provisioned identities must stay approved so they are never waitlisted.
func TestApplyDefaultApprovalStatus(t *testing.T) {
	adm := conf.AdminOrg
	cases := []struct {
		name string
		u    *User
		want string // expected approvalStatus after applyDefaultApprovalStatus
	}{
		// GATED — the customer self-service routes must all land pending.
		{"password/SSO self-signup (normal user)", &User{Owner: "hanzo", Name: "x", Type: "normal-user", RegisterType: "Application Signup"}, ApprovalPending},
		{"web3 wallet signup", &User{Owner: "lux", Name: "w", Type: "normal-user", RegisterType: "Web3 Signup"}, ApprovalPending},
		{"email-code signup, no register type", &User{Owner: "zoo", Name: "e", Type: "normal-user"}, ApprovalPending},
		// EXEMPT — provisioned/trusted identities stay approved.
		{"caller already decided approved (invited)", &User{Owner: "hanzo", Properties: map[string]string{ApprovalStatusProperty: ApprovalApproved}}, ApprovalApproved},
		{"caller already decided pending is preserved", &User{Owner: "hanzo", Properties: map[string]string{ApprovalStatusProperty: ApprovalPending}}, ApprovalPending},
		{"admin user", &User{Owner: "hanzo", IsAdmin: true}, ApprovalApproved},
		{"admin-org user", &User{Owner: adm, Name: "z"}, ApprovalApproved},
		{"service account", &User{Owner: "hanzo", Type: "service-account"}, ApprovalApproved},
		{"LDAP-synced user", &User{Owner: "hanzo", Ldap: "ldap-server-1"}, ApprovalApproved},
		{"admin-provisioned (Add User)", &User{Owner: "hanzo", RegisterType: "Add User"}, ApprovalApproved},
		{"anonymous guest", &User{Owner: "hanzo", RegisterType: "Guest Signup"}, ApprovalApproved},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.u.applyDefaultApprovalStatus()
			got := ""
			if tc.u.Properties != nil {
				got = tc.u.Properties[ApprovalStatusProperty]
			}
			if got != tc.want {
				t.Fatalf("applyDefaultApprovalStatus -> %q; want %q", got, tc.want)
			}
			wantApproved := tc.want != ApprovalPending
			if tc.u.IsApproved() != wantApproved {
				t.Fatalf("IsApproved()=%v; want %v (status=%q)", tc.u.IsApproved(), wantApproved, got)
			}
		})
	}
}

// TestSetApprovalStatus verifies the setter allocates the map and is a plain
// upsert.
func TestSetApprovalStatus(t *testing.T) {
	u := &User{Owner: "hanzo", Name: "b"}
	u.SetApprovalStatus(ApprovalPending)
	if u.Properties[ApprovalStatusProperty] != ApprovalPending {
		t.Fatalf("expected pending, got %q", u.Properties[ApprovalStatusProperty])
	}
	if u.IsApproved() {
		t.Fatal("pending user must not be approved")
	}
	u.SetApprovalStatus(ApprovalApproved)
	if !u.IsApproved() {
		t.Fatal("approved user must be approved")
	}
}
