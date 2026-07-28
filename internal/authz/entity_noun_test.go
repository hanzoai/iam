// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package authz

import "testing"

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
// name. This is the same defect entityNoun fixes for the Casdoor verb spellings,
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

// The read that makes a user's own key list truthful: the confidential client already
// trusted to MINT, ROTATE and REVOKE a user's credential may also READ the key set it
// manages. Strictly less disclosure than the mint it already holds, and safe on its
// own because every key read is masked (schema.Key.Mask blanks the sk- half).
func TestCapFor_KeysMapsToTheMintCapability(t *testing.T) {
	if capFor("keys") != CapKeyMint {
		t.Fatalf("capFor(\"keys\") = %+v, want CapKeyMint — without it the ONE key list is SuperAdmin-only and a user cannot see their own keys", capFor("keys"))
	}
	// Still fail-secure: holding it requires being ON the allow-list, under a reserved
	// signing owner. The capability is a grant to a named platform app, not to apps.
	t.Setenv(CapKeyMint.Env, "hanzo-console")
	if !Allowed(&Principal{App: "hanzo-console", AppOwner: "admin"}, capFor("keys")) {
		t.Fatal("an allow-listed, admin-owned minter must be able to read the keys it manages")
	}
	if Allowed(&Principal{App: "hanzo-console", AppOwner: "acme"}, capFor("keys")) {
		t.Fatal("the owner-pin must deny a tenant app that reuses an allow-listed name")
	}
	if Allowed(&Principal{App: "other-app", AppOwner: "admin"}, capFor("keys")) {
		t.Fatal("an app that is not on the allow-list must hold nothing")
	}
}
