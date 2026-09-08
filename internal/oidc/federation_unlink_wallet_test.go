// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Unlinking a wallet runs the SAME policy every other sign-in method runs —
// only the storage differs. These pin both halves: that the policy still
// applies, and that the (chain, address) actually named is the one that goes.

// doUnlinkWallet posts an unlink naming a specific wallet.
func doUnlinkWallet(t *testing.T, app *zip.App, bearer, owner, name, chain, address string) (int, map[string]any) {
	t.Helper()
	req := jsonReq("POST", PathUnlink, map[string]any{
		"providerType": "wallet",
		"user":         map[string]string{"owner": owner, "name": name},
		"chain":        chain,
		"address":      address,
	})
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, body := do(t, app, req)
	return resp.StatusCode, decode(t, body)
}

// walletsOf reads the account's remaining bindings.
func walletsOf(t *testing.T, db orm.DB, owner, user string) []*schema.Wallet {
	t.Helper()
	got, err := store.WalletsOf(context.Background(), db, owner, user)
	if err != nil {
		t.Fatalf("read wallets: %v", err)
	}
	return got
}

// The account holder removes one of its own wallets; the others stay. Before
// this, a wallet was the one sign-in method with no way off an account —
// connectorFor had no entry for it and the answer was always "can't be
// unlinked".
func TestUnlinkWallet_RemovesTheOneNamed(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	bindWallet(t, db, "hanzo", "alice", "evm", "0xabc")
	bindWallet(t, db, "hanzo", "alice", "solana", "SoLaNa1")

	access := accessTokenFor(t, app, "openid")
	if _, m := doUnlinkWallet(t, app, access, "hanzo", "alice", "evm", "0xabc"); m["status"] != "ok" {
		t.Fatalf("unlink wallet: %v", m["msg"])
	}
	left := walletsOf(t, db, "hanzo", "alice")
	if len(left) != 1 || left[0].Chain != "solana" {
		t.Fatalf("remaining wallets = %+v, want the solana one alone", left)
	}
}

// A wallet the account does not hold is refused as not linked — not with
// whatever the last-credential rule concluded about a method that was never
// there.
func TestUnlinkWallet_UnknownPairIsNotLinked(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	bindWallet(t, db, "hanzo", "alice", "evm", "0xabc")

	access := accessTokenFor(t, app, "openid")
	_, m := doUnlinkWallet(t, app, access, "hanzo", "alice", "evm", "0xdead")
	if m["status"] == "ok" {
		t.Fatal("unlink of a wallet the account does not hold was permitted")
	}
	if m["msg"] != "please link first" {
		t.Fatalf("msg = %v, want the not-linked answer", m["msg"])
	}
	if len(walletsOf(t, db, "hanzo", "alice")) != 1 {
		t.Fatal("the account's real wallet went")
	}
}

// The address is matched AS STORED. The verifier canonicalized it at link time
// — EVM lowercased, other chains trimmed only, because base58/bech32/SS58 are
// case-sensitive — so folding here would let a caller name one spelling and
// remove a binding it did not name.
func TestUnlinkWallet_AddressIsMatchedAsStored(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	bindWallet(t, db, "hanzo", "alice", "solana", "SoLaNa1")

	access := accessTokenFor(t, app, "openid")
	if _, m := doUnlinkWallet(t, app, access, "hanzo", "alice", "solana", "solana1"); m["status"] == "ok" {
		t.Fatal("a case variant of a case-SENSITIVE address removed the binding")
	}
	if len(walletsOf(t, db, "hanzo", "alice")) != 1 {
		t.Fatal("the binding went despite the spelling not matching")
	}
}

// The request must say WHICH wallet. An account holds many across many chains,
// so an unlink that named only the provider would remove whichever row sorted
// first.
func TestUnlinkWallet_NamesTheWalletOrIsRefused(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	bindWallet(t, db, "hanzo", "alice", "evm", "0xabc")

	access := accessTokenFor(t, app, "openid")
	if _, m := doUnlink(t, app, access, "wallet", "hanzo", "alice"); m["status"] == "ok" {
		t.Fatal("an unlink naming no wallet was permitted")
	}
	if len(walletsOf(t, db, "hanzo", "alice")) != 1 {
		t.Fatal("a wallet went on a request that named none")
	}
}

// THE ONE THAT WAS BROKEN. The last-credential rule counted "does this account
// have a wallet", so an account whose only credential was one wallet read that
// wallet as proof that removing it was safe — the check was its own subject,
// and a person could self-detach into an account with no way back in.
func TestUnlinkWallet_RefusedWhenItIsTheOnlyCredential(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	bindWallet(t, db, "hanzo", "alice", "evm", "0xabc")
	// The token is minted while the password still exists; the account is
	// stripped to the wallet alone afterwards, which is the state a
	// wallet-provisioned identity is created in.
	access := accessTokenFor(t, app, "openid")
	clearPassword(t, db, "alice")

	_, m := doUnlinkWallet(t, app, access, "hanzo", "alice", "evm", "0xabc")
	if m["status"] == "ok" {
		t.Fatal("the only way into the account was removed by a self-service click")
	}
	if len(walletsOf(t, db, "hanzo", "alice")) != 1 {
		t.Fatal("the last credential went")
	}
}

// A second wallet IS another way in, so removing the first is safe. Without
// this arm the fix above would refuse an unlink that is perfectly fine.
func TestUnlinkWallet_PermittedWhenAnotherWalletRemains(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	bindWallet(t, db, "hanzo", "alice", "evm", "0xabc")
	bindWallet(t, db, "hanzo", "alice", "evm", "0xdef")
	access := accessTokenFor(t, app, "openid")
	clearPassword(t, db, "alice")

	if _, m := doUnlinkWallet(t, app, access, "hanzo", "alice", "evm", "0xabc"); m["status"] != "ok" {
		t.Fatalf("unlink refused with a second wallet on file: %v", m["msg"])
	}
	if left := walletsOf(t, db, "hanzo", "alice"); len(left) != 1 || left[0].Address != "0xdef" {
		t.Fatalf("remaining wallets = %+v, want 0xdef alone", left)
	}
}

// Authority is the one every unlink has: the account holder, or a SuperAdmin.
// A colleague is not either.
func TestUnlinkWallet_CrossUserRefused(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	seedUser(t, db, "bob", "bob@hanzo.ai", "pw")
	bindWallet(t, db, "hanzo", "bob", "evm", "0xbob")

	access := accessTokenFor(t, app, "openid") // signs in as alice
	if _, m := doUnlinkWallet(t, app, access, "hanzo", "bob", "evm", "0xbob"); m["status"] == "ok" {
		t.Fatal("one member unlinked another member's wallet")
	}
	if len(walletsOf(t, db, "hanzo", "bob")) != 1 {
		t.Fatal("bob's wallet went")
	}
}

// A wallet is NOT gated by the application's CanUnlink flag, because there is
// nothing for the flag to live on: native wallet sign-in has no provider row.
// Reading it would refuse every self-unlink on every application, permanently.
// The account here has a GitHub link declared unlinkable=false, which is what
// the flag would be read from if a wallet consulted one.
func TestUnlinkWallet_IsNotGatedByTheProviderFlag(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkGitHub(t, db, "alice", "gh-alice", false)
	bindWallet(t, db, "hanzo", "alice", "evm", "0xabc")

	access := accessTokenFor(t, app, "openid")
	if _, m := doUnlinkWallet(t, app, access, "hanzo", "alice", "evm", "0xabc"); m["status"] != "ok" {
		t.Fatalf("wallet unlink refused: %v", m["msg"])
	}
	if len(walletsOf(t, db, "hanzo", "alice")) != 0 {
		t.Fatal("the wallet stayed")
	}
}
