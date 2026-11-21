// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "testing"

// An org holds an issuer of its own only if no platform org, brand, directory or
// host-root path word is its name.
func TestTenantOrg(t *testing.T) {
	for _, ok := range []string{"acme", "gg-prosperity-test", "a1"} {
		if err := TenantOrg(ok); err != nil {
			t.Errorf("TenantOrg(%q) = %v", ok, err)
		}
	}
	for _, no := range []string{
		"", "a", "Acme", "a/b", "a.b", "-a", "admin", "built-in", "app", "hanzo", "lux", "zoo", "pars", "platform",
		"hanzo-id", "lux-id", "hanzoai", "luxfi", "hanzo-inc", "adnexus", "bootnode", "osage", "z24",
		"v1", "login", "healthz", "metrics", "api", "iam",
	} {
		if TenantOrg(no) == nil {
			t.Errorf("TenantOrg(%q) = nil, want a refusal", no)
		}
	}
}

func TestCertTenant(t *testing.T) {
	if !(&Cert{Scope: CertTenant}).Tenant() || (&Cert{Scope: "JWT"}).Tenant() || (*Cert)(nil).Tenant() {
		t.Fatal("Tenant() misreads the scope")
	}
}
