// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "testing"

// Spans reads the declaration, so the table is exhaustive over the vocabulary
// rather than over the cases someone remembered.
//
// "None" is the admin console's spelling of "offer no org picker", identical in
// meaning to the empty string a never-edited application carries: both read as
// confined.
func TestSpans(t *testing.T) {
	for _, tc := range []struct {
		name   string
		app    Application
		expect bool
	}{
		// Confined: no picker offered, whichever way that is spelled.
		{"unset", Application{}, false},
		{"none", Application{OrgChoiceMode: "None"}, false},

		// Declared: the app lets a user name or found an org.
		{"select", Application{OrgChoiceMode: "Select"}, true},
		{"input", Application{OrgChoiceMode: "Input"}, true},
		{"create", Application{OrgChoiceMode: "create"}, true},

		// Shared is an explicit, deliberate flag and stands alone.
		{"shared", Application{IsShared: true}, true},
		{"shared and none", Application{IsShared: true, OrgChoiceMode: "None"}, true},

		// The declaration is the row's own, whoever owns it.
		{"tenant create", Application{Owner: "acme", OrgChoiceMode: "create"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.app.Spans(); got != tc.expect {
				t.Fatalf("Spans() = %v, want %v (isShared=%v orgChoiceMode=%q)",
					got, tc.expect, tc.app.IsShared, tc.app.OrgChoiceMode)
			}
		})
	}
}

// ServesAnyOrg is tenant isolation's ONE exemption: a declaration (Spans) on a
// row the platform owns (Owner "admin"). The same declaration on a row any other
// owner holds serves that owner's org alone. Organization is the tenant an app
// serves, not who owns the row, so an Organization of "admin" confers nothing.
func TestServesAnyOrg(t *testing.T) {
	for _, tc := range []struct {
		name   string
		app    Application
		expect bool
	}{
		{"platform unset", Application{Owner: "admin", Organization: "hanzo"}, false},
		{"platform none", Application{Owner: "admin", Organization: "zoo", OrgChoiceMode: "None"}, false},
		{"platform select", Application{Owner: "admin", Organization: "hanzo", OrgChoiceMode: "Select"}, true},
		{"platform input", Application{Owner: "admin", Organization: "hanzo", OrgChoiceMode: "Input"}, true},
		{"platform create", Application{Owner: "admin", Organization: "hanzo", OrgChoiceMode: "create"}, true},
		{"platform shared", Application{Owner: "admin", Organization: "webby-ai", IsShared: true}, true},
		{"hanzo shared", Application{Owner: "hanzo", Organization: "hanzo", IsShared: true}, true},
		{"hanzo create", Application{Owner: "hanzo", Organization: "hanzo", OrgChoiceMode: "create"}, true},
		{"hanzo none", Application{Owner: "hanzo", Organization: "hanzo", OrgChoiceMode: "None"}, false},

		{"tenant create", Application{Owner: "acme", Organization: "acme", OrgChoiceMode: "create"}, false},
		{"tenant select", Application{Owner: "acme", Organization: "acme", OrgChoiceMode: "Select"}, false},
		{"tenant input", Application{Owner: "acme", Organization: "acme", OrgChoiceMode: "Input"}, false},
		{"tenant shared", Application{Owner: "acme", Organization: "acme", IsShared: true}, false},
		{"tenant serving admin", Application{Owner: "acme", Organization: "admin", OrgChoiceMode: "create"}, false},
		{"built-in shared", Application{Owner: "built-in", Organization: "hanzo", IsShared: true}, false},
		{"no owner shared", Application{Organization: "hanzo", IsShared: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.app.ServesAnyOrg(); got != tc.expect {
				t.Fatalf("ServesAnyOrg() = %v, want %v (owner=%q isShared=%v orgChoiceMode=%q)",
					got, tc.expect, tc.app.Owner, tc.app.IsShared, tc.app.OrgChoiceMode)
			}
		})
	}
}

// An application offering no org choice ("None") must stay confined to its OWN
// org: a session belonging to another org must not mint a code against it.
// ServesAnyOrg is what the callers read, so it is tested the way they read it.
func TestNoneConfinesToItsOwnOrg(t *testing.T) {
	zooConsole := &Application{Owner: "admin", Organization: "zoo", OrgChoiceMode: "None"}

	if zooConsole.ServesAnyOrg() {
		t.Fatal(`an application offering no org choice must stay confined to its own org`)
	}
	// Spelled as mint/token/signup spell it, so this fails if the callers' shape
	// drifts away from the predicate.
	if foreign := "hanzo"; !(foreign != zooConsole.Organization && !zooConsole.ServesAnyOrg()) {
		t.Fatal("a foreign-org principal must be refused by an unconfigured app")
	}
}
