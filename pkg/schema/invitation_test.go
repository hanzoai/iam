// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "testing"

func TestBareAddress(t *testing.T) {
	for s, want := range map[string]bool{
		"ada@example.com":                      true,
		"ada+hanzo@example.co.uk":              true,
		`"Hanzo Billing" <victim@example.com>`: false,
		"<victim@example.com>":                 false,
		"a@example.com, b@example.com":         false,
		"a@b@example.com":                      false,
		"ada@example.com\r\nBcc: x@evil.com":   false,
		"ada‮@example.com":                     false,
		"ada@localhost":                        false,
		"":                                     false,
	} {
		if got := BareAddress(s); got != want {
			t.Errorf("BareAddress(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestInviteCode(t *testing.T) {
	for code, ok := range map[string]bool{
		"K7PQ2M9XRT":             true,
		"acme_team-2026":         true,
		"acme-7f3k":              false, // nine characters
		"AAAAAAAAAAAA":           false, // one character, repeated
		"ABABABABAB":             false, // two
		"K7PQ2M9XRT K7":          false, // a space
		"K7PQ2M9XRT/x":           false, // a slash
		string(make([]byte, 65)): false,
	} {
		if err := InviteCode(code); (err == nil) != ok {
			t.Errorf("InviteCode(%q) = %v, want ok=%v", code, err, ok)
		}
	}
}
