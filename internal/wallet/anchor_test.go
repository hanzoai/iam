// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package wallet

import (
	"testing"

	wc "github.com/luxwallet/connect/go/walletconnect"
)

// Anchoring is optional, and "optional" has to mean the link path is
// indistinguishable with it off — otherwise every deployment that has not
// configured a registry is running a second, untested code path.

// No settings, no registry. The link path calls Report on the nil value, and a
// nil *did.Registry has to tolerate that: it is what keeps a branch out of the
// handler.
func TestAnchorIsOffWithoutSettings(t *testing.T) {
	if r := registry(); r != nil {
		t.Fatalf("a registry was built with no settings named: controller %s", r.Controller())
	}
}

// The whole link, with no registry: the wallet is bound, the caller is signed
// in, and nothing waited on a chain. This is the state every deployment is in
// until one is configured, so it is the state that has to be pinned.
func TestLinkSucceedsWithNoRegistry(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: false})
	u, tok := bearer(t, db, a, "hanzo", "alice")

	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), map[string]string{
		"Origin":        "https://" + host,
		"Authorization": "Bearer " + tok,
	})
	if got := okData(t, code, m); got != "hanzo/alice" {
		t.Fatalf("data = %q, want the session identity", got)
	}
	w := wallets(t, db)
	if len(w) != 1 || w[0].User != u.Name || w[0].Address != addr {
		t.Fatalf("wallet = %+v, want it bound to the session user", w)
	}
}

// Signing in with a wallet already on file binds nothing new, which is what
// keeps a re-login from adding a duplicate verification method to the on-chain
// document every time. The fact is carried by signin.bound; this pins the store
// side of it, which is what bound is derived from.
func TestReloginBindsNothingNew(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})

	if _, m := signIn(t, app, a); m["status"] != "ok" {
		t.Fatalf("first sign-in: %v", m["msg"])
	}
	first := wallets(t, db)
	if len(first) != 1 {
		t.Fatalf("first sign-in bound %d wallets, want 1", len(first))
	}
	if _, m := signIn(t, app, a); m["status"] != "ok" {
		t.Fatalf("second sign-in: %v", m["msg"])
	}
	if again := wallets(t, db); len(again) != 1 {
		t.Fatalf("second sign-in left %d wallets, want the same 1", len(again))
	}
}
