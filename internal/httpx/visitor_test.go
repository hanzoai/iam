// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package httpx

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/testhttp"
)

// Visitor reads only the verified ingress/proxy edge address: CF-Connecting-IP,
// else the rightmost X-Forwarded-For hop appended by the nearest proxy. Client-
// prepended X-Forwarded-For prefixes and non-IP garbage are never trusted.
func TestVisitor_SpoofResistance(t *testing.T) {
	for _, tc := range []struct {
		name, connecting, forwarded, want string
	}{
		{"cloudflare beats xff", "203.0.113.9", "198.51.100.1, 198.51.100.2", "203.0.113.9"},
		{"rightmost xff hop beats spoofed prefix", "", "1.2.3.4, 5.6.7.8, 198.51.100.7", "198.51.100.7"},
		{"single xff hop", "", "198.51.100.7", "198.51.100.7"},
		{"ipv4 mapped ipv6 normalized", "", "::ffff:198.51.100.7", "198.51.100.7"},
		{"ipv6 preserved", "", "2001:db8::42", "2001:db8::42"},
		{"forged trailing xff rejected", "", "198.51.100.7, forged-ip", ""},
		{"forged cf header rejected without falling back to xff", "not-an-ip", "198.51.100.7", ""},
		{"both empty", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Visitor(tc.connecting, tc.forwarded); got != tc.want {
				t.Fatalf("Visitor(%q, %q) = %q, want %q", tc.connecting, tc.forwarded, got, tc.want)
			}
		})
	}
}

// ClientIP binds Visitor onto HTTP requests and falls back to the socket peer
// address when headers are absent or unparseable — never returning a client-
// spoofed X-Forwarded-For prefix or garbage string.
func TestClientIP_SpoofResistance(t *testing.T) {
	app := zip.New(zip.Config{AppName: "clientip-test", DisableStartupMessage: true})
	app.Group("").Raw(http.MethodGet, "/ip", func(c *zip.Ctx) error {
		return c.String(200, ClientIP(c))
	})
	if err := app.Build(); err != nil {
		t.Fatal(err)
	}

	ask := func(cf, xff string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/ip", nil)
		if cf != "" {
			req.Header.Set("CF-Connecting-IP", cf)
		}
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		resp, err := testhttp.Do(app, req)
		if err != nil {
			t.Fatalf("request: %v", err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return string(b)
	}

	if got := ask("203.0.113.9", "10.0.0.1, 198.51.100.7"); got != "203.0.113.9" {
		t.Fatalf("CF-Connecting-IP: got %q, want 203.0.113.9", got)
	}
	if got := ask("", "6.6.6.6, 198.51.100.7"); got != "198.51.100.7" {
		t.Fatalf("spoofed XFF prefix: got %q, want 198.51.100.7", got)
	}
	if got := ask("", "6.6.6.6, not-an-ip"); got == "6.6.6.6" || got == "not-an-ip" || got == "6.6.6.6, not-an-ip" {
		t.Fatalf("forged XFF must fall back to socket peer, got %q", got)
	}
	if got := ask("", ""); got == "" {
		t.Fatal("missing proxy headers must fall back to socket peer")
	}
}
