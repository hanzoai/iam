// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import (
	"slices"
	"testing"
)

// The table is one sorted, unique, lowercase list, and every name in it is both reserved
// and refused an issuer; a name beside it is neither.
func TestReservedSlugTable(t *testing.T) {
	if !slices.IsSorted(reservedSlugs) {
		t.Error("the reserved table is not sorted: keep it one ordered list")
	}
	seen := map[string]bool{}
	for _, n := range reservedSlugs {
		if seen[n] {
			t.Errorf("%q is in the reserved table twice", n)
		}
		seen[n] = true
		if n != toLower(n) {
			t.Errorf("%q is not lowercase", n)
		}
		if !ReservedSlug(n) {
			t.Errorf("ReservedSlug(%q) = false", n)
		}
		if OrgName(n) == nil && TenantOrg(n) == nil {
			t.Errorf("%q has an org name's shape and may hold an issuer", n)
		}
	}
	// Sources named in the table's comment, spot-checked: a site page, a static
	// directory, an edge path, IAM's own, and a platform name.
	for _, n := range []string{"pricing", "download", "signup", "login", "v1", "api", "images", "about", "careers", "hanzo", "admin", "built-in", "lux", "zoo", "pars", "oidc", "oauth", "healthz"} {
		if !ReservedSlug(n) || TenantOrg(n) == nil {
			t.Errorf("%q must be reserved and issuer-less", n)
		}
	}
	for _, n := range []string{"acme", "gg-prosperity-test", "pricing-acme"} {
		if ReservedSlug(n) {
			t.Errorf("%q is reserved", n)
		}
	}
}

func toLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}
