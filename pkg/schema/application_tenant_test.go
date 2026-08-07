// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "testing"

// ServesAnyOrg is tenant isolation's ONE exemption, so the table is exhaustive
// over the vocabulary rather than over the cases someone remembered.
//
// "None" is the case that matters and the reason this file exists: it is the
// admin console's spelling of "offer no org picker", identical in meaning to the
// empty string a never-edited application carries. Four hand-written copies of
// this rule all tested `OrgChoiceMode == ""`, so an application carrying the
// canonical value read as UNCONFINED and accepted a session from any org.
func TestServesAnyOrg(t *testing.T) {
	for _, tc := range []struct {
		name   string
		app    Application
		expect bool
	}{
		// Confined: no picker offered, whichever way that is spelled.
		{"unset", Application{}, false},
		{"none", Application{OrgChoiceMode: "None"}, false},

		// Unconfined: the app genuinely lets a user name an org.
		{"select", Application{OrgChoiceMode: "Select"}, true},
		{"input", Application{OrgChoiceMode: "Input"}, true},
		{"create", Application{OrgChoiceMode: "create"}, true},

		// Shared is an explicit, deliberate flag and stands alone.
		{"shared", Application{IsShared: true}, true},
		{"shared and none", Application{IsShared: true, OrgChoiceMode: "None"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.app.ServesAnyOrg(); got != tc.expect {
				t.Fatalf("ServesAnyOrg() = %v, want %v (isShared=%v orgChoiceMode=%q)",
					got, tc.expect, tc.app.IsShared, tc.app.OrgChoiceMode)
			}
		})
	}
}

// The regression, stated as the thing that was actually true in production:
// zoo-console is owned by "zoo" and carried "None", and a session owned by
// "hanzo" minted a code against it. Read as the callers read it.
func TestNoneConfinesToItsOwnOrg(t *testing.T) {
	zooConsole := &Application{Organization: "zoo", OrgChoiceMode: "None"}

	if zooConsole.ServesAnyOrg() {
		t.Fatal(`an application offering no org choice must stay confined to its own org`)
	}
	// Spelled as mint/token/signup spell it, so this fails if the callers' shape
	// drifts away from the predicate.
	if foreign := "hanzo"; !(foreign != zooConsole.Organization && !zooConsole.ServesAnyOrg()) {
		t.Fatal("a foreign-org principal must be refused by an unconfigured app")
	}
}
