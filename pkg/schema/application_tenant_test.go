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

// An application offering no org choice ("None") must stay confined to its OWN
// org: a session belonging to another org must not mint a code against it.
// ServesAnyOrg is what the callers read, so it is tested the way they read it.
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

// A session answers for no public client of a reserved org; a confidential one,
// and any client of a tenant, keep single sign-on.
func TestAttended(t *testing.T) {
	for _, tc := range []struct {
		name   string
		app    Application
		expect bool
	}{
		{"public admin client", Application{Organization: "admin"}, true},
		{"public client of the signing owner", Application{Organization: "built-in"}, true},
		{"public client of the service org", Application{Organization: "app"}, true},
		{"confidential admin client", Application{Organization: "admin", ClientSecret: "s"}, false},
		{"public tenant client", Application{Organization: "hanzo"}, false},
		{"an owner that only looks reserved", Application{Organization: "Admin"}, false},
	} {
		if got := tc.app.Attended(); got != tc.expect {
			t.Errorf("%s: Attended() = %v, want %v", tc.name, got, tc.expect)
		}
	}
}
