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
