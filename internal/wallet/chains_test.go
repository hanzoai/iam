// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package wallet

import (
	"testing"

	wc "github.com/luxwallet/connect/go/walletconnect"

	"github.com/hanzoai/iam/pkg/schema"
)

// schema.WalletChains carries NAMES so that package stays dependency-free, which
// buys the leaf both the endpoints and the login descriptor can import — but a
// name is only as good as its agreement with the luxwallet constant it stands
// for. This is where that agreement is enforced, in the one package that imports
// both. A rename upstream fails here instead of silently narrowing what can sign
// in: a chain whose name stopped matching would be advertised and then refused,
// which is the exact screen-vs-endpoint disagreement the shared list exists to
// prevent.
func TestWalletChainsMatchSDK(t *testing.T) {
	want := []wc.Chain{
		wc.ChainEVM, wc.ChainSolana, wc.ChainBitcoin,
		wc.ChainTON, wc.ChainXRP, wc.ChainPolkadot, wc.ChainCardano,
	}
	got := schema.WalletChains()

	if len(got) != len(want) {
		t.Fatalf("schema.WalletChains() has %d chains, the SDK set has %d: %v vs %v",
			len(got), len(want), got, want)
	}
	for i, w := range want {
		if got[i] != string(w) {
			t.Errorf("chain %d = %q, want %q (the luxwallet constant)", i, got[i], string(w))
		}
	}
}

// Every advertised chain must be one the endpoints accept, and nothing else may
// be. This is the property that matters: the list is only worth sharing if both
// halves genuinely read it.
func TestAdvertisedChainsAreExactlyTheSupportedOnes(t *testing.T) {
	for _, name := range schema.WalletChains() {
		if !supported(wc.Chain(name)) {
			t.Errorf("advertised chain %q is refused by supported() — a screen would offer "+
				"a wallet the nonce endpoint then rejects", name)
		}
	}
	for _, bogus := range []string{"dogecoin", "", "EVM ", "eip155:1"} {
		if supported(wc.Chain(bogus)) {
			t.Errorf("supported(%q) = true; only the shared list may pass", bogus)
		}
	}
}
