// SPDX-License-Identifier: MIT OR Apache-2.0
package wallet

import (
	"testing"
	"time"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/orm"
	wc "github.com/luxwallet/connect/go/walletconnect"
)

// Hanzo Cloud #464 equivalents: the native /v1/iam/web3/verify endpoint must
// reject every unauthenticated forgery before any account or code is minted.
func TestAttack_EmptyPayload(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})
	// {} equivalent: empty address/message/signature.
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, "", "", ""), nil)
	errorIs(t, code, m, "malformed")
	if n := len(users(t, db)); n != 0 {
		t.Fatalf("users=%d want 0", n)
	}
	if n := len(wallets(t, db)); n != 0 {
		t.Fatalf("wallets=%d want 0", n)
	}
}
func TestAttack_ForgedAddressNoSignature(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})
	victim := "0x1111111111111111111111111111111111111111"
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, victim, "not a signed message", ""), nil)
	errorIs(t, code, m, "malformed")
	if n := len(users(t, db)); n != 0 {
		t.Fatalf("users=%d want 0", n)
	}
}
func TestAttack_ValidSignatureWrongKey(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})
	// attacker key signs, but claims victim address.
	ch := mintFor(t, app, "evm")
	victim := "0x1111111111111111111111111111111111111111"
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, victim)
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, victim, msg, sig), nil)
	if len(users(t, db)) != 0 {
		t.Fatalf("users created")
	}
	// SDK rejects as address-mismatch (signer in msg != recovered) or bad-signature; either 4xx.
	if code < 400 || code > 499 {
		t.Fatalf("status=%d m=%v", code, m)
	}
	if m["status"] != "error" {
		t.Fatalf("m=%v", m)
	}
}
func TestAttack_UnknownNonce(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})
	// Valid signature over a nonce never issued by the server.
	statementv := statement
	expire := "2035-01-01T00:00:00Z"
	version := "1"
	ch := wc.LoginChallenge{Domain: host, URI: "https://" + host + "/login", Statement: &statementv, Nonce: "unknownnonce1234567890abcd", IssuedAt: "2025-01-01T00:00:00Z", ExpirationTime: &expire, Version: &version}
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	code, m := post(t, app, PathVerify, body(a, wc.ChainEVM, addr, msg, sig), nil)
	errorIs(t, code, m, "nonce invalid, already used, or expired")
	if n := len(users(t, db)); n != 0 {
		t.Fatalf("users=%d", n)
	}
}
func TestAttack_ReplayedAndExpiredNonce(t *testing.T) {
	// replay already covered by TestReplay/TestReplayConcurrent; expired by TestExpired.
	// Here assert replay in one flow with real key succeeds once then fails.
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})
	ch := mintFor(t, app, "evm")
	msg, sig := signWith(t, signer(t), ch, wc.ChainEVM, addr)
	b := body(a, wc.ChainEVM, addr, msg, sig)
	if code, m := post(t, app, PathVerify, b, nil); okData(t, code, m) == "" {
		t.Fatal("first ok")
	}
	code, m := post(t, app, PathVerify, b, nil)
	errorIs(t, code, m, "nonce invalid")
	// expired: shorten TTL row
	app2, db2 := newServer(t)
	a2 := seed(t, db2, opts{signup: true})
	ch2 := mintFor(t, app2, "evm")
	row, _ := orm.Get[schema.Challenge](db2, id(ch2.Nonce))
	row.ExpireTime = time.Now().UTC().Add(-time.Minute).Format(time.RFC3339)
	_ = row.UpdateCtx(tctx())
	msg2, sig2 := signWith(t, signer(t), ch2, wc.ChainEVM, addr)
	code, m = post(t, app2, PathVerify, body(a2, wc.ChainEVM, addr, msg2, sig2), nil)
	errorIs(t, code, m, "nonce invalid")
	_ = app
}
func TestAttack_HappyPathRealKey(t *testing.T) {
	app, db := newServer(t)
	a := seed(t, db, opts{signup: true})
	code, m := signIn(t, app, a)
	if okData(t, code, m) == "" {
		t.Fatal("happy path failed")
	}
	if n := len(users(t, db)); n != 1 {
		t.Fatalf("users=%d", n)
	}
	if w := wallets(t, db); len(w) != 1 || w[0].Address != addr {
		t.Fatalf("wallets=%+v", w)
	}
}
