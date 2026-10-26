// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"strings"
	"testing"

	wc "github.com/luxwallet/connect/go/walletconnect"
)

// page is the site a person signs in on, and callback the redirect URI its
// application registers there. IAM answers at host (hanzo.id), as api.hanzo.ai
// answers for hanzo.ai in production.
const (
	page     = "https://hanzo.ai"
	callback = page + "/auth/callback"
)

// The challenge names the page's site exactly when the clientId names an
// application that registers the page's origin; every other request gets the
// host it arrived on, as before.
func TestNonceSite(t *testing.T) {
	app, db := newServer(t)
	seed(t, db, opts{signup: true, redirects: []string{callback}})
	q := "chain=evm&address=" + addr

	for _, tc := range []struct {
		name, query string
		hdr         map[string]string
		domain, uri string
	}{
		{"registered origin", q + "&clientId=hanzo-cloud", map[string]string{"Origin": page},
			"hanzo.ai", "https://hanzo.ai/login"},
		{"unregistered origin", q + "&clientId=hanzo-cloud", map[string]string{"Origin": "https://evil.example"},
			host, "https://" + host + "/login"},
		{"no clientId", q, map[string]string{"Origin": page},
			host, "https://" + host + "/login"},
		{"unknown clientId", q + "&clientId=nope", map[string]string{"Origin": page},
			host, "https://" + host + "/login"},
		{"no origin", q + "&clientId=hanzo-cloud", nil,
			host, "https://" + host + "/login"},
		{"referer is never read", q + "&clientId=hanzo-cloud", map[string]string{"Referer": page + "/login"},
			host, "https://" + host + "/login"},
		{"origin with a path", q + "&clientId=hanzo-cloud", map[string]string{"Origin": page + "/"},
			host, "https://" + host + "/login"},
		{"forwarded host is never read", q + "&clientId=hanzo-cloud",
			map[string]string{"Origin": "https://evil.example", "X-Forwarded-Host": "hanzo.ai"},
			host, "https://" + host + "/login"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := mintAt(t, app, tc.query, tc.hdr)
			if ch.Domain != tc.domain || ch.URI != tc.uri {
				t.Fatalf("challenge = (%q, %q), want (%q, %q)", ch.Domain, ch.URI, tc.domain, tc.uri)
			}
			for _, row := range challenges(t, db) {
				if row.Name == ch.Nonce && row.Domain != tc.domain {
					t.Fatalf("stored domain = %q, want %q: verify re-checks the row", row.Domain, tc.domain)
				}
			}
		})
	}
}

// The whole flow at the page's site: the wallet signs a message naming hanzo.ai,
// and verify, re-deriving the site from the same application and Origin, signs
// the person in.
func TestSiteRoundTrip(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, redirects: []string{callback}})
	origin := map[string]string{"Origin": page}

	ch := mintAt(t, app, "chain=evm&address="+addr+"&clientId="+a.ClientId, origin)
	if ch.Domain != "hanzo.ai" {
		t.Fatalf("minted domain = %q, want hanzo.ai", ch.Domain)
	}
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	if !strings.HasPrefix(msg, "hanzo.ai wants you to sign in") {
		t.Fatalf("signed message does not name the page's site:\n%s", msg)
	}
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), origin)
	if got := okData(t, code, m); got != "hanzo/"+name(wc.ChainEVM, addr) {
		t.Fatalf("login data = %q, want the provisioned identity", got)
	}
	if n := len(wallets(t, db)); n != 1 {
		t.Fatalf("wallets = %d, want 1", n)
	}
}

// A challenge bound to the page's site redeems only from that page. Posted with
// no Origin, or from another one, verify derives the host, which the burned row
// does not name.
func TestSiteChallengeNeedsItsOrigin(t *testing.T) {
	for _, tc := range []struct {
		name string
		hdr  map[string]string
	}{
		{"no origin", nil},
		{"another origin", map[string]string{"Origin": "https://evil.example"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			a := seed(t, db, opts{signup: true, redirects: []string{callback}})

			ch := mintAt(t, app, "chain=evm&address="+addr+"&clientId="+a.ClientId, map[string]string{"Origin": page})
			msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
			code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), tc.hdr)
			errorIs(t, code, m, "domain mismatch")
			if n := len(users(t, db)); n != 0 {
				t.Fatalf("users = %d, want 0", n)
			}
		})
	}
}

// A browser sends no Origin on a same-origin GET, so a page that reaches IAM
// through its own host mints a host-bound challenge and then posts verify with
// its Origin. That challenge still redeems: the host it was minted at is the host
// verify arrives on.
func TestHostChallengeFromRegisteredOrigin(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true, redirects: []string{callback}})

	ch := mintAt(t, app, "chain=evm&address="+addr+"&clientId="+a.ClientId, nil)
	if ch.Domain != host {
		t.Fatalf("minted domain = %q, want %q", ch.Domain, host)
	}
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), map[string]string{"Origin": page})
	if got := okData(t, code, m); got != "hanzo/"+name(wc.ChainEVM, addr) {
		t.Fatalf("login data = %q, want the provisioned identity", got)
	}
}

// The nonce bounds address as verify does, before anything is written.
func TestNonceOversizedAddress(t *testing.T) {
	app, db := newServer(t)

	code, m := get(t, app, PathNonce+"?chain=evm&address="+strings.Repeat("a", maxAddress+1))
	errorIs(t, code, m, "oversized address")
	if n := len(challenges(t, db)); n != 0 {
		t.Fatalf("challenges = %d, want 0: a refused nonce writes no row", n)
	}
	if code, m := get(t, app, PathNonce+"?chain=evm&address="+strings.Repeat("a", maxAddress)); code != 200 || m["status"] != "ok" {
		t.Fatalf("address at the bound refused: %d %v", code, m)
	}
}
