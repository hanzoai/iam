// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package principal_test

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/principal"
)

// Scope is what a write is bound to. An org the caller administers by
// membership is theirs to name; an org they merely belong to is not, and neither
// is one they have nothing to do with. Belonging opens reads (ScopeRead), never
// writes.
func TestScopeNamesOnlyAnOrgTheCallerAdministers(t *testing.T) {
	sam := &principal.Principal{Org: "sam", User: "sam", Admin: true,
		Orgs: map[string]policy.Role{"webby": policy.Owner, "lux": policy.Member}}
	ctx := principal.Bind(context.Background(), sam)

	for _, c := range []struct {
		asked, want string
		ok          bool
	}{
		{"", "sam", true},        // naming none is the caller's own
		{"sam", "sam", true},     // its own, by name
		{"webby", "webby", true}, // an org it owns by membership
		{"lux", "", false},       // an org it merely belongs to
		{"acme", "", false},      // an org it has nothing to do with
		{"admin", "", false},     // the reserved org
	} {
		got, err := principal.Scope(ctx, c.asked)
		if (err == nil) != c.ok || got != c.want {
			t.Errorf("Scope(%q) = %q, %v; want %q, ok=%v", c.asked, got, err, c.want, c.ok)
		}
	}
	// ScopeRead still opens what belonging opens.
	if got, err := principal.ScopeRead(ctx, "lux"); err != nil || got != "lux" {
		t.Errorf("ScopeRead(lux) = %q, %v; a member reads the org they belong to", got, err)
	}
}
