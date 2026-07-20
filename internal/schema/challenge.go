// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Challenge is a single-use, expiring wallet login challenge (v1 Casdoor
// `web3_nonce`, v2 kind "challenges") — the anti-replay half of CAIP-122 wallet
// sign-in (HIP-0111). GET /v1/iam/web3/nonce mints one; POST /v1/iam/web3/verify
// burns it before any crypto runs, so a captured proof can never be redeemed
// twice even when its signature is valid.
//
// Owner is always "built-in": a challenge is minted before any application or
// tenant is known, so the challenge store is global, not org-scoped. Name IS the
// nonce string, so (Owner, Name) is the natural key the burn locks.
//
// Domain is the request-derived brand host the wallet signed against, re-checked
// against this row at verify. The whole phishing defense rides on that binding,
// which is why the host is stored at mint rather than re-derived from the client
// at verify.
type Challenge struct {
	orm.Model[Challenge]

	Owner string `json:"owner" orm:"index"` // "built-in" — the challenge store is global
	Name  string `json:"name" orm:"index"`  // the nonce string itself (the lookup key)

	// Chain and Address are the advisory scoping hints the mint was asked for.
	// Chain is re-checked at verify so a nonce minted for one chain cannot be
	// redeemed with a valid proof on another; Address is a hint only — identity
	// comes from the VERIFIED address, never from this row.
	Chain   string `json:"chain"`
	Address string `json:"address"`

	Domain      string `json:"domain"`
	CreatedTime string `json:"createdTime"`
	ExpireTime  string `json:"expireTime"` // RFC3339
	Used        bool   `json:"used"`
}
