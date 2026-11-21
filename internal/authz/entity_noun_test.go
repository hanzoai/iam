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
