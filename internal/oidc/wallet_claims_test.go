// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// The `wallets` and `did` claims are asserted on a token minted through the
// REAL confidential flow, not on a hand-built Identity: the point of resolving
// them in identityOf is that every mint path carries them, and only a real mint
// proves that.

// bindWallet puts a (chain, address) on an account, as the wallet sign-in flow
// does when it links one.
func bindWallet(t *testing.T, db orm.DB, owner, user, chain, address string) {
	t.Helper()
	w := orm.New[schema.Wallet](db)
	w.Owner, w.User, w.Chain, w.Address = owner, user, chain, address
	w.Scheme = "secp256k1-eip191"
	w.CreatedTime = "2026-09-04T00:00:00Z"
	w.SetId(owner + "/" + user + "/" + chain + "/" + address)
	if err := w.CreateCtx(context.Background()); err != nil {
		t.Fatalf("bind wallet: %v", err)
	}
}

// claimsFrom reads a minted access token's claim set.
func claimsFrom(t *testing.T, token string) Claims {
	t.Helper()
	var got Claims
	if _, _, err := jwt.NewParser().ParseUnverified(token, &got); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	return got
}

// A person with two wallets gets both, chain-qualified, plus the identifier
// derived from the subject the same token carries.
func TestToken_CarriesWalletsAndDID(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	bindWallet(t, db, "hanzo", "alice", "evm", "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23")
	bindWallet(t, db, "hanzo", "alice", "solana", "7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDpvcMwJeK")

	got := claimsFrom(t, accessTokenFor(t, app, "openid profile"))

	// Ordered, because the set lands in a signed value: two tokens for one
	// unchanged account must not differ byte for byte.
	want := []schema.WalletRef{
		{Chain: "evm", Address: "0x2c7536e3605d9c16a7a3d7b1898e529396a65c23"},
		{Chain: "solana", Address: "7EqQdEULxWcraVx3mXKFjc84LhCkMGZCkRuDpvcMwJeK"},
	}
	if len(got.Wallets) != len(want) {
		t.Fatalf("wallets = %+v, want %+v", got.Wallets, want)
	}
	for i := range want {
		if got.Wallets[i] != want[i] {
			t.Fatalf("wallets[%d] = %+v, want %+v", i, got.Wallets[i], want[i])
		}
	}
	// THE INVARIANT: the DID and the subject name one person. Deriving the DID
	// anywhere but from this token's own `sub` is how they would come apart.
	if want := schema.DID(got.Subject); got.DID != want {
		t.Fatalf("did = %q, want %q (derived from sub %q)", got.DID, want, got.Subject)
	}
	if got.DID == "" {
		t.Fatal("did claim is empty for a resolvable subject")
	}
}

// An account with no wallet omits the claim rather than carrying an empty list,
// so a consumer reading it never has to tell [] from absent.
func TestToken_OmitsWalletsWhenNoneAreBound(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	got := claimsFrom(t, accessTokenFor(t, app, "openid profile"))
	if got.Wallets != nil {
		t.Fatalf("wallets = %+v on an account with none, want the claim omitted", got.Wallets)
	}
	// The DID does not depend on a wallet: it is derived from the subject, so
	// every person has one whether or not they have proved a key.
	if got.DID == "" {
		t.Fatal("did claim is absent for an account with no wallet; it derives from the subject, not from a wallet")
	}
}

// UserInfo and the token describe one principal. A client holding either must
// not get two answers, which is the rule `name` and `groups` are already under.
func TestUserinfo_AgreesWithTheTokenOnWalletsAndDID(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	bindWallet(t, db, "hanzo", "alice", "evm", "0xabc")

	access := accessTokenFor(t, app, "openid profile")
	claims := claimsFrom(t, access)
	status, info := userinfo(t, app, access)
	if status != 200 {
		t.Fatalf("userinfo status %d", status)
	}
	if info["did"] != claims.DID {
		t.Fatalf("userinfo did = %v, token did = %q", info["did"], claims.DID)
	}
	list, ok := info["wallets"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("userinfo wallets = %v, want one entry", info["wallets"])
	}
	w, _ := list[0].(map[string]any)
	if w["chain"] != "evm" || w["address"] != "0xabc" {
		t.Fatalf("userinfo wallet = %v, want the chain-qualified address", w)
	}
}

// UserInfo reads the wallet set FRESH. A wallet unlinked a minute ago must stop
// counting now rather than when the token lapses — the rule memberships are
// already under, and the reason userinfo does not echo the token.
func TestUserinfo_ReflectsAnUnlinkBeforeTheTokenLapses(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	bindWallet(t, db, "hanzo", "alice", "evm", "0xabc")

	access := accessTokenFor(t, app, "openid profile")
	if _, info := userinfo(t, app, access); info["wallets"] == nil {
		t.Fatal("userinfo did not carry the bound wallet to begin with")
	}

	w, err := orm.Get[schema.Wallet](db, "hanzo/alice/evm/0xabc")
	if err != nil {
		t.Fatalf("load wallet: %v", err)
	}
	if err := w.DeleteCtx(context.Background()); err != nil {
		t.Fatalf("delete wallet: %v", err)
	}

	if _, info := userinfo(t, app, access); info["wallets"] != nil {
		t.Fatalf("userinfo still reports %v on the same token after the wallet went", info["wallets"])
	}
}

// Discovery says exactly what a token carries. Advertising a claim nothing
// emits is what left consumers reading `name` as a display name for a year.
func TestDiscovery_AdvertisesWalletsAndDID(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})

	resp, body := do(t, app, jsonReq("GET", "/.well-known/openid-configuration", nil))
	if resp.StatusCode != 200 {
		t.Fatalf("discovery status %d", resp.StatusCode)
	}
	listed := map[string]bool{}
	for _, c := range decode(t, body)["claims_supported"].([]any) {
		listed[c.(string)] = true
	}
	for _, name := range []string{"wallets", "did"} {
		if !listed[name] {
			t.Fatalf("claims_supported omits %q, which every user token carries", name)
		}
	}
}
