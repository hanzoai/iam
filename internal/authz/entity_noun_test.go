// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz

import (
	"testing"

	policy "github.com/hanzoai/authz"
)

// entityNoun is the fold that makes both surfaces name the same entity. Pin it
// directly: this is the mapping the whole compat authorization surface rides on.
func TestEntityNoun_FoldsVerbSpellingOntoTheEntity(t *testing.T) {
	for seg, want := range map[string]string{
		"get-application":   "applications",
		"add-organization":  "organizations",
		"update-user":       "users",
		"delete-membership": "memberships", // already plural, left alone
		"get-cert":          "certs",
		"get-users":         "users",
		"applications":      "applications", // native noun, unchanged
		"certs":             "certs",
		"organizations":     "organizations",
		"get-":              "",
		"":                  "",
	} {
		if got := entityNoun(seg); got != want {
			t.Errorf("entityNoun(%q) = %q, want %q", seg, got, want)
		}
	}
}

// Every key route must name the SAME entity, so a capability keyed on it is live on
// all of them. The keys package used to serve its list at /v1/iam/keys and every other
// op at /v1/iam/key, which entityOf reads as two different entities ("keys" and
// "key") — so any capability granted for keys was dead on whichever half you did not
// name. This is the same defect entityNoun fixes for the legacy verb spellings,
// arrived at from the other direction: an inconsistent NOUN rather than a verb.
func TestEntityOf_EveryKeyRouteNamesOneEntity(t *testing.T) {
	for _, path := range []string{
		"/v1/iam/keys",
		"/v1/iam/keys/get",
		"/v1/iam/keys/update",
		"/v1/iam/keys/delete",
	} {
		if got := entityOf(path); got != "keys" {
			t.Errorf("entityOf(%q) = %q, want \"keys\" — a capability keyed on keys is dead on this path", path, got)
		}
	}
}

// The read that makes a user's own key list truthful: the confidential client
// already trusted to MINT, ROTATE and REVOKE a user's credential may also READ the
// key set it manages. Strictly less disclosure than the mint it already holds, and
// safe on its own because every key read is masked (schema.Key.Mask blanks the sk-
// half).
//
// Asserted through the SEAM rather than against the capability table, because the
// two halves have to meet: the key routes must all name one entity (above), and
// that entity must be the one the minter's capability reaches.
func TestKeysAreReachableByTheCredentialMinter(t *testing.T) {
	t.Setenv(policy.CapKeyMint.Env, "hanzo-console")
	keys := entityOf("/v1/iam/keys")

	minter := &Principal{App: &policy.App{Name: "hanzo-console", Owner: "admin"}, Org: "hanzo"}
	if !authorize(minter, "GET", keys, "acme", "k") {
		t.Fatal("an allow-listed, admin-owned minter cannot read the keys it manages — the ONE key list is then SuperAdmin-only and a user cannot see their own")
	}
	// Fail-secure either side of it: the owner-pin denies a tenant app reusing the
	// allow-listed name, and an unlisted app holds nothing.
	spoof := &Principal{App: &policy.App{Name: "hanzo-console", Owner: "acme"}, Org: "acme"}
	if authorize(spoof, "GET", keys, "acme", "k") {
		t.Fatal("a tenant app reusing an allow-listed name read the key set")
	}
	other := &Principal{App: &policy.App{Name: "other-app", Owner: "admin"}, Org: "hanzo"}
	if authorize(other, "GET", keys, "acme", "k") {
		t.Fatal("an app that is not on the allow-list read the key set")
	}
}
