// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package httpx

import "testing"

// The visitor is the hop Cloudflare appended, never one the client wrote.
func TestVisitor(t *testing.T) {
	for _, tc := range []struct{ chain, want string }{
		{"203.0.113.9, 173.245.48.1", "203.0.113.9"},
		{"6.6.6.6, 203.0.113.9, 173.245.48.1", "203.0.113.9"},
		{"6.6.6.6,7.7.7.7,203.0.113.9,173.245.48.1", "203.0.113.9"},
		{"203.0.113.7", "203.0.113.7"},
		{" 203.0.113.7 ", "203.0.113.7"},
	} {
		if got := Visitor(tc.chain); got != tc.want {
			t.Errorf("Visitor(%q) = %q, want %q", tc.chain, got, tc.want)
		}
	}
}
