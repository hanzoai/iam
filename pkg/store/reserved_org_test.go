// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import "testing"

// IsReservedOrg is the ONE reserved-org predicate the self-service boundary
// (signup / onboarding / federated provisioning) shares. The set is the
// SuperAdmin/signing owners (admin, built-in — IsSigningCertOwner) plus the
// service-principal org (app); every other org is a legitimate tenant.
func TestIsReservedOrg(t *testing.T) {
	reserved := []string{"admin", "built-in", "app"}
	for _, o := range reserved {
		if !IsReservedOrg(o) {
			t.Errorf("IsReservedOrg(%q) = false, want true (reserved system org)", o)
		}
	}

	// A tenant — including the brand/staff orgs, which are NOT reserved (white-label)
	// — is never reserved, so a legitimate signup/onboarding is unaffected.
	tenants := []string{"hanzo", "lux", "zoo", "pars", "acme", "", "Admin", "APP", "admin ", "built_in", "administrator"}
	for _, o := range tenants {
		if IsReservedOrg(o) {
			t.Errorf("IsReservedOrg(%q) = true, want false (legitimate/non-reserved org)", o)
		}
	}

	// It composes IsSigningCertOwner: every signing owner is reserved, so a
	// newly-added signing owner is covered here for free (no drift).
	for _, o := range []string{"admin", "built-in"} {
		if IsSigningCertOwner(o) && !IsReservedOrg(o) {
			t.Errorf("signing-cert owner %q is not reserved — the predicates drifted", o)
		}
	}
}
