// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import "testing"

// TestProtectedOrgs verifies brand orgs are unconditionally protected
// regardless of name pattern.
func TestProtectedOrgs(t *testing.T) {
	p := protectedOrgs("admin")
	for _, name := range []string{"admin", "hanzo", "lux", "zoo", "pars", "adnexus", "bootnode"} {
		if !p[name] {
			t.Errorf("expected %q to be protected", name)
		}
	}
	// Sanity: not all names protected.
	if p["spamco42"] {
		t.Error("non-protected name flagged as protected")
	}
}

// TestNumericSuffixDetection checks the regex matches the canonical
// spam pattern but not legitimate names.
func TestNumericSuffixDetection(t *testing.T) {
	cases := map[string]bool{
		"hanzo42":   true,
		"myorg123":  true,
		"a1":        true,
		"42":        true,
		"hanzo":     false,
		"myorg":     false,
		"42-hanzo":  false, // digits not at end
		"hanzo-42a": false,
	}
	for name, want := range cases {
		got := numericSuffixRE.MatchString(name)
		if got != want {
			t.Errorf("numericSuffixRE(%q) = %v, want %v", name, got, want)
		}
	}
}

// TestReservedWordCollisions exercises the known-bad-name list.
func TestReservedWordCollisions(t *testing.T) {
	for _, name := range []string{"hanzowoo", "my-hanzo", "hanzo-new", "superuser"} {
		if !reservedWordCollisions[name] {
			t.Errorf("expected %q in reserved-word collisions", name)
		}
	}
	// Confirm legitimate names are NOT in the list.
	for _, name := range []string{"hanzo", "myorg"} {
		if reservedWordCollisions[name] {
			t.Errorf("unexpected: %q in reserved-word collisions", name)
		}
	}
}

// TestParseIAMTime exercises the time formats IAM emits.
func TestParseIAMTime(t *testing.T) {
	cases := []string{
		"2026-05-18T12:00:00Z",
		"2026-05-18T12:00:00.123456789Z",
		"2026-05-18T12:00:00",
	}
	for _, s := range cases {
		if _, err := parseIAMTime(s); err != nil {
			t.Errorf("parseIAMTime(%q): %v", s, err)
		}
	}
	if _, err := parseIAMTime("not-a-time"); err == nil {
		t.Error("expected error for bogus input")
	}
}
