// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package factor

// Copy is the ONE declaration of which columns are multi-factor state, and every
// writer agrees with it by construction — so a column it forgets is a column that
// travels in neither direction. users.Update carries the stored factors onto the
// incoming full row through it; a column missing there is one the update writes
// back empty, and for MfaItems that is the per-user policy saying which factor is
// REQUIRED. Losing it turns a required second factor into an optional one.

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// Every multi-factor column crosses, MfaItems included.
func TestCopy_carriesEveryFactorColumn(t *testing.T) {
	src := &schema.User{
		PreferredMfaType:    App,
		RecoveryCodes:       []string{"one", "two"},
		TotpSecret:          "seed",
		MfaPhoneEnabled:     true,
		MfaEmailEnabled:     true,
		MfaRadiusEnabled:    true,
		MfaRadiusUsername:   "alice",
		MfaRadiusProvider:   "radius",
		MfaPushEnabled:      true,
		MfaPushReceiver:     "phone",
		MfaPushProvider:     "push",
		MfaRememberDeadline: "2026-01-01T00:00:00Z",
		MfaRememberDigest:   "digest",
		MfaItems:            []*schema.MfaItem{{Name: App, Rule: "Required"}},
	}
	dst := &schema.User{}
	Copy(dst, src)

	if len(dst.MfaItems) != 1 || dst.MfaItems[0].Name != App || dst.MfaItems[0].Rule != "Required" {
		t.Fatalf("MfaItems did not cross: %#v", dst.MfaItems)
	}
	if dst.TotpSecret != src.TotpSecret || dst.PreferredMfaType != src.PreferredMfaType {
		t.Fatalf("a factor column did not cross: %#v", dst)
	}
}

// The policy is what decides whether sign-in must divert to enrollment, so a
// dropped column is a required factor silently becoming optional. Prompt reads it,
// which is what makes the loss observable rather than merely absent.
func TestCopy_keepsARequiredFactorRequired(t *testing.T) {
	org := &schema.Organization{}
	stored := &schema.User{MfaItems: []*schema.MfaItem{{Name: Email, Rule: "Required"}}}
	if !Prompt(org, stored) {
		t.Fatal("the stored user should be prompted to enrol the required factor")
	}

	incoming := &schema.User{} // a profile edit that mentions no factor at all
	Copy(incoming, stored)
	if !Prompt(org, incoming) {
		t.Fatal("the carry dropped the policy: a required factor became optional")
	}
}
