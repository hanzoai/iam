// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Wallet is the (Chain, Address) -> user binding (v1 the legacy surface `wallet_link`, v2
// kind "wallets") — the identity half of CAIP-122 wallet sign-in (HIP-0111).
// One user owns many wallets (EVM + Solana + Bitcoin + …, several addresses per
// chain). The (Chain, Address) pair is globally unique: a wallet binds to at
// most one identity, which is what stops a wallet from hijacking an account.
//
// Address is stored exactly as the verifier canonicalized it — EVM lowercased,
// every other chain trimmed only, because base58/bech32/SS58 are case-SENSITIVE.
// The SDK's verifier accepts case/whitespace variants of one key, so storing the
// canonical form is what keeps one key resolving to one identity instead of N.
//
// A side table, not user columns: the legacy model stored one address per
// provider (user.web3onboard) and cannot represent N wallets across M chains.
// A link is its own value; the user is referenced, not mutated.
type Wallet struct {
	orm.Model[Wallet]

	Owner   string `json:"owner" orm:"index"` // organization
	User    string `json:"user" orm:"index"`  // user.Name
	Chain   string `json:"chain" orm:"index"`
	Address string `json:"address" orm:"index"`

	Scheme      string `json:"scheme"`
	PublicKey   string `json:"publicKey"`
	CreatedTime string `json:"createdTime"`
}
