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

package object

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/names"

	luxcrypto "github.com/luxfi/crypto"
	wc "github.com/luxwallet/wallet-connect/go/walletconnect"

	_ "modernc.org/sqlite" // db = sqlite (pure-Go driver, matches object/ormer.go)
)

// newWeb3TestOrmer wires the package-level `ormer` global to a fresh in-memory
// sqlite engine with the wallet-login tables synced. Mirrors the harness in
// migrate_phone_e164_test.go. Restores the previous ormer on cleanup.
func newWeb3TestOrmer(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + dir + "/web3.db?_journal_mode=WAL&_busy_timeout=5000"
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine: %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	for _, tbl := range []interface{}{new(User), new(Web3Nonce), new(WalletLink)} {
		if err := engine.Sync2(tbl); err != nil {
			t.Fatalf("Sync2(%T): %v", tbl, err)
		}
	}
	prev := ormer
	ormer = &Ormer{driverName: "sqlite", Engine: engine}
	t.Cleanup(func() {
		ormer = prev
		_ = engine.Close()
	})
}

// mintEvmProof signs a CAIP-122 message with a fresh secp256k1 key and returns
// the lowercase address, the canonical message, and the 0x signature. Uses the
// SAME luxfi/crypto path the SDK verifier uses, so the proof is genuinely valid.
func mintEvmProof(t *testing.T, challenge *wc.LoginChallenge) (address, message, signature string) {
	t.Helper()

	priv, err := luxcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	address = wc.AddressFromPublicKey(luxcrypto.FromECDSAPub(&priv.PublicKey))

	message, err = wc.BuildSiwxMessage(wc.BuildParams{
		Challenge: *challenge,
		Address:   address,
		Chain:     wc.ChainEVM,
	})
	if err != nil {
		t.Fatalf("BuildSiwxMessage: %v", err)
	}

	sig, err := luxcrypto.Sign(wc.EIP191Digest(message), priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig[64] += 27 // wallets emit V as 27/28; the verifier normalises it back
	signature = "0x" + hex.EncodeToString(sig)
	return address, message, signature
}

// --- Nonce burn -------------------------------------------------------------

func TestBurnWeb3Nonce_DoubleBurnRejected(t *testing.T) {
	newWeb3TestOrmer(t)

	n := &Web3Nonce{
		Owner:      "built-in",
		Name:       "nonce-abc",
		Chain:      "evm",
		Domain:     "hanzo.id",
		ExpireTime: time.Now().Add(10 * time.Minute).Format(time.RFC3339),
		Used:       false,
	}
	if _, err := AddWeb3Nonce(n); err != nil {
		t.Fatalf("AddWeb3Nonce: %v", err)
	}

	// First burn wins.
	got, err := BurnWeb3Nonce("nonce-abc")
	if err != nil {
		t.Fatalf("BurnWeb3Nonce(1): %v", err)
	}
	if got == nil {
		t.Fatal("first burn returned nil; expected the row")
	}
	if got.Domain != "hanzo.id" {
		t.Errorf("burned row domain = %q, want hanzo.id", got.Domain)
	}

	// Second burn of the same nonce must be rejected (replay guard).
	got2, err := BurnWeb3Nonce("nonce-abc")
	if err != nil {
		t.Fatalf("BurnWeb3Nonce(2): %v", err)
	}
	if got2 != nil {
		t.Fatal("second burn returned a row; replay must be rejected")
	}
}

func TestBurnWeb3Nonce_UnknownNonce(t *testing.T) {
	newWeb3TestOrmer(t)
	got, err := BurnWeb3Nonce("does-not-exist")
	if err != nil {
		t.Fatalf("BurnWeb3Nonce: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for unknown nonce")
	}
}

func TestBurnWeb3Nonce_Expired(t *testing.T) {
	newWeb3TestOrmer(t)
	n := &Web3Nonce{
		Owner:      "built-in",
		Name:       "nonce-old",
		Domain:     "hanzo.id",
		ExpireTime: time.Now().Add(-1 * time.Minute).Format(time.RFC3339), // already expired
		Used:       false,
	}
	if _, err := AddWeb3Nonce(n); err != nil {
		t.Fatalf("AddWeb3Nonce: %v", err)
	}
	got, err := BurnWeb3Nonce("nonce-old")
	if err != nil {
		t.Fatalf("BurnWeb3Nonce: %v", err)
	}
	if got != nil {
		t.Fatal("expected nil for expired nonce")
	}
}

// --- WalletLink resolution --------------------------------------------------

func TestWalletLink_Resolution(t *testing.T) {
	newWeb3TestOrmer(t)

	link := &WalletLink{
		Owner:   "hanzo",
		User:    "alice",
		Chain:   "evm",
		Address: "0xabc0000000000000000000000000000000000def",
		Scheme:  "secp256k1-eip191",
	}
	if ok, err := AddWalletLink(link); err != nil || !ok {
		t.Fatalf("AddWalletLink: ok=%v err=%v", ok, err)
	}

	// Found, org-scoped.
	got, err := GetWalletLink("hanzo", "evm", "0xabc0000000000000000000000000000000000def")
	if err != nil {
		t.Fatalf("GetWalletLink: %v", err)
	}
	if got == nil || got.User != "alice" {
		t.Fatalf("expected alice's link, got %+v", got)
	}

	// Wrong org -> not found.
	other, err := GetWalletLink("lux", "evm", "0xabc0000000000000000000000000000000000def")
	if err != nil {
		t.Fatalf("GetWalletLink(other org): %v", err)
	}
	if other != nil {
		t.Fatal("link must be org-scoped; found it under the wrong org")
	}

	// Global lookup ignores org.
	g, err := GetWalletLinkGlobal("evm", "0xabc0000000000000000000000000000000000def")
	if err != nil {
		t.Fatalf("GetWalletLinkGlobal: %v", err)
	}
	if g == nil || g.User != "alice" {
		t.Fatalf("global lookup failed: %+v", g)
	}

	// Listing by user.
	links, err := GetWalletLinksByUser("hanzo", "alice")
	if err != nil {
		t.Fatalf("GetWalletLinksByUser: %v", err)
	}
	if len(links) != 1 {
		t.Fatalf("expected 1 link for alice, got %d", len(links))
	}
}

func TestWalletLink_GloballyUnique(t *testing.T) {
	newWeb3TestOrmer(t)

	addr := "0x1111111111111111111111111111111111111111"
	if ok, err := AddWalletLink(&WalletLink{Owner: "hanzo", User: "alice", Chain: "evm", Address: addr}); err != nil || !ok {
		t.Fatalf("AddWalletLink(alice): ok=%v err=%v", ok, err)
	}

	// A second identity claiming the same (chain,address) must be detectable as
	// already-linked. The auth core uses GetWalletLinkGlobal to enforce this
	// before inserting; here we assert the global lookup sees the existing bind.
	g, err := GetWalletLinkGlobal("evm", addr)
	if err != nil {
		t.Fatalf("GetWalletLinkGlobal: %v", err)
	}
	if g == nil || g.User != "alice" {
		t.Fatalf("expected the wallet bound to alice, got %+v", g)
	}
}

// --- Full verify happy-path + replay (existing-link login) ------------------

// seedLinkedUser inserts a user and a wallet link for `address` under org `hanzo`
// so VerifyWalletLogin resolves an existing identity (no provisioning needed --
// AddUser has a wide blast radius unsuitable for unit context).
func seedLinkedUser(t *testing.T, address string) (*Application, *Organization) {
	t.Helper()

	user := &User{
		Owner:       "hanzo",
		Name:        "wallet_alice",
		Id:          "00000000-0000-0000-0000-000000000001",
		Type:        "normal-user",
		CreatedTime: "2026-01-01T00:00:00Z",
	}
	if _, err := ormer.Engine.Insert(user); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if ok, err := AddWalletLink(&WalletLink{
		Owner: "hanzo", User: "wallet_alice", Chain: "evm", Address: address, Scheme: "secp256k1-eip191",
	}); err != nil || !ok {
		t.Fatalf("AddWalletLink: ok=%v err=%v", ok, err)
	}

	app := &Application{Owner: "admin", Name: "app-hanzo", Organization: "hanzo", EnableSignUp: false}
	org := &Organization{Owner: "admin", Name: "hanzo"}
	return app, org
}

func TestVerifyWalletLogin_EVM_HappyPath_And_Replay(t *testing.T) {
	newWeb3TestOrmer(t)

	domain := "hanzo.id"

	// 1. Mint a challenge (persists the nonce) for EVM.
	_, challenge, err := MintWeb3Challenge(domain, wc.ChainEVM, "")
	if err != nil {
		t.Fatalf("MintWeb3Challenge: %v", err)
	}

	// 2. Sign it with a real key -> valid EVM proof.
	address, message, signature := mintEvmProof(t, challenge)

	// 3. Seed an existing user linked to that exact (verified) address.
	app, org := seedLinkedUser(t, address)

	in := WalletLoginInput{
		Domain:       domain,
		Chain:        wc.ChainEVM,
		Scheme:       string(wc.SchemeSecp256k1EIP191),
		Address:      address,
		Message:      message,
		Signature:    signature,
		Method:       "login",
		Application:  app,
		Organization: org,
	}

	// Happy path: verifies, burns nonce, resolves the linked user.
	user, err := VerifyWalletLogin(in)
	if err != nil {
		t.Fatalf("VerifyWalletLogin (happy): %v", err)
	}
	if user == nil || user.Name != "wallet_alice" {
		t.Fatalf("resolved wrong user: %+v", user)
	}

	// Replay: the SAME proof (same nonce) must now fail -- the nonce was burned.
	_, err = VerifyWalletLogin(in)
	if err == nil {
		t.Fatal("replay of a burned-nonce proof must be rejected")
	}
}

func TestVerifyWalletLogin_RejectsTamperedSignature(t *testing.T) {
	newWeb3TestOrmer(t)
	domain := "hanzo.id"

	_, challenge, err := MintWeb3Challenge(domain, wc.ChainEVM, "")
	if err != nil {
		t.Fatalf("MintWeb3Challenge: %v", err)
	}
	address, message, signature := mintEvmProof(t, challenge)
	app, org := seedLinkedUser(t, address)

	// Flip a hex nibble in the signature body -> wrong recovered address.
	bad := []byte(signature)
	if bad[10] == 'a' {
		bad[10] = 'b'
	} else {
		bad[10] = 'a'
	}

	_, err = VerifyWalletLogin(WalletLoginInput{
		Domain:       domain,
		Chain:        wc.ChainEVM,
		Scheme:       string(wc.SchemeSecp256k1EIP191),
		Address:      address,
		Message:      message,
		Signature:    string(bad),
		Method:       "login",
		Application:  app,
		Organization: org,
	})
	if err == nil {
		t.Fatal("tampered signature must be rejected")
	}
}

func TestVerifyWalletLogin_LoginOnly_NoLink_Errors(t *testing.T) {
	newWeb3TestOrmer(t)
	domain := "hanzo.id"

	_, challenge, err := MintWeb3Challenge(domain, wc.ChainEVM, "")
	if err != nil {
		t.Fatalf("MintWeb3Challenge: %v", err)
	}
	address, message, signature := mintEvmProof(t, challenge)

	// No seeded link, method=login, no session -> must error (no account).
	app := &Application{Owner: "admin", Name: "app-hanzo", Organization: "hanzo", EnableSignUp: false}
	org := &Organization{Owner: "admin", Name: "hanzo"}

	_, err = VerifyWalletLogin(WalletLoginInput{
		Domain:       domain,
		Chain:        wc.ChainEVM,
		Scheme:       string(wc.SchemeSecp256k1EIP191),
		Address:      address,
		Message:      message,
		Signature:    signature,
		Method:       "login",
		Application:  app,
		Organization: org,
	})
	if err == nil {
		t.Fatal("login with no linked wallet must error")
	}
}

func TestVerifyWalletLogin_DomainMismatch(t *testing.T) {
	newWeb3TestOrmer(t)

	// Nonce minted for hanzo.id, but the caller claims lux.id as the host.
	_, challenge, err := MintWeb3Challenge("hanzo.id", wc.ChainEVM, "")
	if err != nil {
		t.Fatalf("MintWeb3Challenge: %v", err)
	}
	address, message, signature := mintEvmProof(t, challenge)
	app, org := seedLinkedUser(t, address)

	_, err = VerifyWalletLogin(WalletLoginInput{
		Domain:       "lux.id", // != the host the nonce was minted against
		Chain:        wc.ChainEVM,
		Scheme:       string(wc.SchemeSecp256k1EIP191),
		Address:      address,
		Message:      message,
		Signature:    signature,
		Method:       "login",
		Application:  app,
		Organization: org,
	})
	if err == nil {
		t.Fatal("a host that doesn't match the minted nonce domain must be rejected")
	}
}
