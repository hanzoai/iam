// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// WalletChains is the ONE list of chain families wallet sign-in accepts. It sits
// in this leaf package because two callers that must never disagree both need it:
// the nonce/verify endpoints GATE on it, and the login descriptor ADVERTISES from
// it. A screen offering a chain the verifier refuses is the same defect as a
// social button that dead-ends, and one list is what makes that unrepresentable.
//
// Names, not SDK types, so this package stays dependency-free; internal/wallet
// pins them against the luxwallet constants in its own test, so a rename upstream
// fails the build rather than silently narrowing what can sign in.
//
// The login descriptor previously reported web3 from an application's linked
// PROVIDER of category "web3" — the seeded Web3Onboard row, whose clientId is the
// unexpanded literal `${IAM_WEB3_CLIENT_ID}` and which names a third-party library
// this build does not import. Native seven-chain sign-in was therefore advertised
// as absent on every screen while its endpoints answered normally.
func WalletChains() []string {
	return []string{"evm", "solana", "bitcoin", "ton", "xrp", "polkadot", "cardano"}
}

// Wallet is the (Chain, Address) -> user binding (v1 `wallet_link`, v2
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
