// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz_test

import "testing"

// THE SECOND SPELLING MUST NOT COME BACK.
//
// IAM served each kind at two addresses: a noun (/v1/iam/users) and a verb
// (/v1/iam/users), the latter a Casdoor-shaped alias kept while consumers
// migrated. Every one of those is gone, and this is what keeps them gone —
// re-adding one is how the estate ends up with two ways to read a user again,
// and the two do not stay in agreement. They already did not: the verb ran
// authz.Scope and the noun does not, so the same credential asking the same
// question got a refusal from one and rows from the other.
//
// It reads the ROUTER'S OWN DECLARATION rather than issuing requests. A request
// answering 404 proves a path is unrouted; it does not prove nothing registered
// it, because a route can exist and still 404 from inside its handler. The
// declaration is the register itself, so absence here is absence.
//
// Two live spellings are deliberately NOT in this list. `resolve-key` and
// `resolve-user` turn an opaque key into what it authorizes; they are operations
// rather than a second address for a kind, and there is no noun surface that
// expresses them.
func TestRetiredSpellingsAreGone(t *testing.T) {
	h := newHarness(t)

	retired := []string{
		"get-application", "get-applications", "get-cert", "get-certs",
		"get-global-users", "get-invitations", "get-organization",
		"get-organizations", "get-organization-projects",
		"get-organization-workspaces", "get-permission", "get-permissions",
		"get-provider", "get-providers", "get-records", "get-role", "get-roles",
		"get-user", "get-users", "update-user", "add-user", "add-organization",
		"add-project",
		// the one singular kind, retired with them
		"application",
		// the native verb-nouns, each replaced by the noun its own canonical
		// constant names (internal/oidc/canonical.go, internal/mfa).
		"get-account", "get-app-login", "update-preferences", "send-verification-code",
		"issue-user-token", "mint-user-keys", "revoke-user-keys",
		"delete-mfa", "set-preferred-mfa",
		// the last three, retired once DELETE /v1/iam/memberships existed to
		// carry the revoke, and `resolve-key`, now `keys/org` beside its twin.
		"get-memberships", "add-membership", "delete-membership", "resolve-key",
	}
	gone := make(map[string]bool, len(retired))
	for _, v := range retired {
		gone["/v1/iam/"+v] = true
	}

	// A control: if the declaration cannot see a route we know exists, an empty
	// answer below would mean the probe is broken rather than the surface clean.
	var sawControl bool
	const control = "/v1/iam/users"

	for _, r := range h.app.Routes() {
		if r.Pattern == control {
			sawControl = true
		}
		if gone[r.Pattern] {
			t.Errorf("%s %s is registered again; it was retired with the second spelling "+
				"of every kind, and a caller that finds it will diverge from the noun surface",
				r.Method, r.Pattern)
		}
	}
	if !sawControl {
		t.Fatalf("the route declaration does not contain %s, so it cannot show what is absent "+
			"either — this test proves nothing until that is fixed", control)
	}
}
