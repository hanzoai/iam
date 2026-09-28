// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"testing"

	policy "github.com/hanzoai/authz"
)

// SuperAdmin is a PERSON whose own org is the admin org. The row is the whole
// input: a membership cannot reach it, a machine is never one, and an owner that
// only looks like the admin org is an ordinary tenant.
func TestSuperAdminIsAPersonWhoseOrgIsAdmin(t *testing.T) {
	for _, c := range []struct {
		name string
		u    *User
		want bool
	}{
		{"a person in the admin org", &User{Owner: policy.AdminOrg, Name: "z"}, true},
		{"a person in the admin org who is not its org admin", &User{Owner: policy.AdminOrg, Name: "ops", IsAdmin: false}, true},
		{"a brand org's admin", &User{Owner: "hanzo", Name: "z", IsAdmin: true}, false},
		{"a service account in the admin org", &User{Owner: policy.AdminOrg, Name: "svc", Type: ServiceAccount}, false},
		{"a program in the admin org", &User{Owner: policy.AdminOrg, Name: "kms", Type: Program}, false},
		{"a program spelled with padding and case", &User{Owner: policy.AdminOrg, Name: "kms", Type: " Service-Account "}, false},
		{"the signing owner", &User{Owner: "built-in", Name: "root"}, false},
		{"the service org", &User{Owner: "app", Name: "root"}, false},
		{"no row", nil, false},
	} {
		if got := c.u.SuperAdmin(); got != c.want {
			t.Errorf("%s: SuperAdmin() = %v, want %v", c.name, got, c.want)
		}
	}
}

// The owner is compared verbatim, like every org comparison: folding case,
// space or script would make an org someone can self-serve the reserved one.
func TestSuperAdminRejectsNearMissOwners(t *testing.T) {
	for _, owner := range []string{"Admin", "ADMIN", "admin ", " admin", "аdmin", "admin​", ""} {
		if (&User{Owner: owner, Name: "root"}).SuperAdmin() {
			t.Errorf("owner %q read as the admin org", owner)
		}
	}
}
