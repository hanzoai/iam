// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"
)

// THE RESERVED SET IS EXACT, AND EXACTNESS IS THE WHOLE SECURITY. A signing cert
// is trusted only under a reserved owner, and the `kid` a token names is resolved
// under those owners in order — so if any spelling a tenant can self-serve
// ("Admin", "admin ", a Cyrillic look-alike) were folded to a reserved owner, that
// tenant could file a cert under the colliding name, have it published in the
// JWKS, and forge tokens the whole estate verifies. The predicates compare
// VERBATIM for exactly this reason; this pins that they never start folding.
//
// It supersedes the owner-spelling half of the deleted reserved_org_test.go: the
// predicates moved to hanzoai/authz, but the boundary they draw is IAM's to hold,
// so IAM tests it.
func TestKidCollisionAcrossOwnerSpellings(t *testing.T) {
	// The real reserved owners, and what each is.
	if !policy.IsSigningOwner("admin") || !policy.IsSigningOwner("built-in") {
		t.Fatal("a real signing owner is not recognized — every token would fail to verify")
	}
	if !policy.IsReservedOrg("admin") || !policy.IsReservedOrg("built-in") || !policy.IsReservedOrg("app") {
		t.Fatal("a real reserved org is not recognized")
	}
	// "app" is reserved (no self-service principal lands there) but is NOT a signing
	// owner (it holds no token-signing cert), and that distinction must hold.
	if policy.IsSigningOwner("app") {
		t.Error(`"app" must not be a signing owner`)
	}

	// Near-misses of a reserved owner. Every one is a DISTINCT identifier a tenant
	// could try to register under, and every one must be neither a signing owner
	// nor a reserved org — otherwise it shadows the platform.
	nearMisses := []struct {
		name, spelling string
	}{
		{"capitalized", "Admin"},
		{"upper", "ADMIN"},
		{"trailing space", "admin "},
		{"leading space", " admin"},
		{"tab", "admin\t"},
		{"newline", "admin\n"},
		{"zero-width space", "admin​"},
		{"cyrillic a", "аdmin"}, // U+0430 CYRILLIC SMALL LETTER A
		{"dotless i", "admın"},  // U+0131 LATIN SMALL LETTER DOTLESS I
		{"fullwidth", "ａdmin"},  // U+FF41 FULLWIDTH LATIN SMALL A
		{"trailing null", "admin\x00"},
		{"nbsp", "admin "},
		{"builtin no dash", "builtin"},
		{"builtin underscore", "built_in"},
		{"builtin capitalized", "Built-In"},
		{"builtin trailing space", "built-in "},
		{"app trailing space", "app "},
		{"app capitalized", "App"},
		{"empty", ""},
	}
	for _, tc := range nearMisses {
		t.Run(tc.name, func(t *testing.T) {
			if policy.IsSigningOwner(tc.spelling) {
				t.Errorf("IsSigningOwner(%q) = true — a tenant could shadow a platform signing kid", tc.spelling)
			}
			if policy.IsReservedOrg(tc.spelling) {
				t.Errorf("IsReservedOrg(%q) = true — a customer flow would be refused, or a platform org impersonated", tc.spelling)
			}
		})
	}
}

// SuperAdmin follows the SAME verbatim boundary. Anchoring in "admin" is platform
// authority; a near-miss of it is a tenant, and holds none — nor does it become
// one through a membership set it never has.
func TestSuperAdminRejectsNearMissOwners(t *testing.T) {
	ctx := context.Background()
	db := memDB(t)

	// The genuine anchor answers true without any read.
	if super, err := IsSuperAdmin(ctx, db, "admin", "root"); err != nil || !super {
		t.Fatalf("admin/root is a SuperAdmin (super=%v err=%v)", super, err)
	}

	for _, spelling := range []string{"Admin", "ADMIN", "admin ", " admin", "аdmin", "admin​", "app", "built-in"} {
		super, err := IsSuperAdmin(ctx, db, spelling, "root")
		if err != nil {
			t.Fatalf("IsSuperAdmin(%q): %v", spelling, err)
		}
		if super {
			t.Errorf("IsSuperAdmin(%q, root) = true — a non-admin owner was read as platform sudo", spelling)
		}
	}
}
