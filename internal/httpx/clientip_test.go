// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package httpx

// The client-address rule, and the attack it exists to stop: the LEFT-MOST
// X-Forwarded-For entry is whatever the caller typed, so reading it as "the
// client" lets one host present a million addresses to a per-address velocity
// counter and write a chosen address into a durable audit row.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/zap-proto/zip"
)

var ourProxies = parseProxySet("10.0.0.0/8,127.0.0.0/8,0.0.0.0/32,::1/128")

func xff(lines ...string) [][]byte {
	out := make([][]byte, 0, len(lines))
	for _, l := range lines {
		out = append(out, []byte(l))
	}
	return out
}

func TestClientAddr(t *testing.T) {
	cases := []struct {
		name string
		peer string
		fwd  [][]byte
		want string
	}{
		{"a forged left-most entry is ignored", "10.0.0.5", xff("1.2.3.4, 203.0.113.9"), "203.0.113.9"},
		{"a whole forged chain is ignored", "10.0.0.5", xff("1.2.3.4, 5.6.7.8, 203.0.113.9"), "203.0.113.9"},
		{"a forged second header line does not hide the real hop", "10.0.0.5", xff("1.2.3.4", "203.0.113.9"), "203.0.113.9"},
		{"internal hops are skipped", "10.0.0.5", xff("203.0.113.9, 10.0.0.6"), "203.0.113.9"},
		{"a direct caller is its own peer", "198.51.100.4", xff("1.2.3.4"), "198.51.100.4"},
		{"an in-cluster caller has no client address", "10.0.0.5", nil, ""},
		{"a chain of only our own hops has no client address", "10.0.0.5", xff("10.0.0.6, 127.0.0.1"), ""},
		{"an unparseable entry is skipped, not keyed", "10.0.0.5", xff("not-an-ip, 203.0.113.9"), "203.0.113.9"},
		{"an IPv4-mapped address is the same key as its IPv4 form", "10.0.0.5", xff("::ffff:203.0.113.9"), "203.0.113.9"},
		{"an entry with a port is the address without it", "10.0.0.5", xff("203.0.113.9:44321"), "203.0.113.9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := clientAddr(tc.peer, tc.fwd, ourProxies); got != tc.want {
				t.Fatalf("clientAddr(%q, %q) = %q, want %q", tc.peer, tc.fwd, got, tc.want)
			}
		})
	}
}

// The walk is bounded, from the right, so it can only ever discard the least
// trustworthy end of a chain.
func TestClientAddr_ChainIsBounded(t *testing.T) {
	long := strings.Repeat("1.2.3.4, ", maxForwardedHops*4) + "203.0.113.9"
	if got := clientAddr("10.0.0.5", xff(long), ourProxies); got != "203.0.113.9" {
		t.Fatalf("got %q, want the right-most hop", got)
	}
}

// The default set trusts our own space and nothing public.
func TestDefaultTrustedProxies(t *testing.T) {
	s := parseProxySet(strings.Join(defaultTrustedProxies, ","))
	for _, ours := range []string{"10.42.0.1", "172.16.5.5", "192.168.1.1", "127.0.0.1", "0.0.0.0", "fd00::1"} {
		a, ok := parseClientAddr(ours)
		if !ok || !s.has(a) {
			t.Fatalf("%s must be trusted by default (ours)", ours)
		}
	}
	for _, theirs := range []string{"203.0.113.9", "198.51.100.4", "2001:db8::1"} {
		a, ok := parseClientAddr(theirs)
		if !ok || s.has(a) {
			t.Fatalf("%s must NOT be trusted by default (public)", theirs)
		}
	}
}

// End to end over a real request on the process default set.
func TestClientIP_OverARealRequest(t *testing.T) {
	var got string
	app := zip.New(zip.Config{})
	app.Get("/probe", func(c *zip.Ctx) error {
		got = ClientIP(c)
		return c.JSON(http.StatusOK, map[string]string{"ok": "1"})
	})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Add("X-Forwarded-For", "1.2.3.4")
	req.Header.Add("X-Forwarded-For", "203.0.113.9, 10.0.0.6")
	if _, err := app.Fiber().Test(req); err != nil {
		t.Fatal(err)
	}
	if got != "203.0.113.9" {
		t.Fatalf("ClientIP = %q, want the right-most untrusted hop", got)
	}
}
