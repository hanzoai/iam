// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package httpx

import (
	"net/netip"
	"testing"
)

// The client is the address the edge reports: CF-Connecting-IP, else the hop the
// nearest proxy appended. What the client wrote before that hop is never read.
func TestClient(t *testing.T) {
	for _, tc := range []struct {
		connecting, forwarded, want string
	}{
		{"203.0.113.9", "10.0.0.1", "203.0.113.9"},
		{" 203.0.113.9 ", "", "203.0.113.9"},
		{"", "10.0.0.1, 198.51.100.7", "198.51.100.7"},
		{"", "198.51.100.7", "198.51.100.7"},
		{"", "::ffff:198.51.100.7", "198.51.100.7"},
		{"", "2001:db8::1", "2001:db8::1"},
		{"", "198.51.100.7, forged", ""},
		{"not-an-address", "198.51.100.7", ""},
		{"", "", ""},
	} {
		got := Client(tc.connecting, tc.forwarded)
		want := netip.Addr{}
		if tc.want != "" {
			want = netip.MustParseAddr(tc.want)
		}
		if got != want {
			t.Fatalf("Client(%q, %q) = %v, want %v", tc.connecting, tc.forwarded, got, want)
		}
	}
}
