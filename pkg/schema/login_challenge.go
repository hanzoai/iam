// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// LoginChallenge is a half-finished authentication ceremony: the server-side
// memory of a sign-in that has proven one thing and must prove another before a
// token exists. The MFA gate mints one when a password verifies but the second
// factor is outstanding, and it is consumed exactly once by the finishing
// request.
//
// v1 keeps this in a beego cookie session — MfaSessionUserId (object/mfa.go:51).
// v2 has no key/value session store, so the state is an owner-scoped row and the
// client holds only its opaque id.
//
// It is a SIBLING of Token, never a Token with borrowed fields: /v1/iam/oauth/token
// resolves a grant by Code and mints from it, so a challenge filed there would sit
// on the redemption path wearing a fictional Application and Scope — an access
// token waiting to be minted from a half-authenticated ceremony. It is also
// DISTINCT from the web3 Challenge (schema.Challenge, the CAIP-122 nonce): that is
// a pre-auth anti-replay token with no principal, this is bound to a KNOWN subject.
//
// Identity is the (Owner, Name) pair; the orm string key is "owner/name". Name is
// the opaque id the client returns; Id carries orm:"index" because the client
// presents the id alone. Subject is the "owner/name" of the principal the ceremony
// is for — the ONE place a finish learns whom it is acting as (never a request
// parameter). Payload is the kind's own state: the just-used verification type for
// an MFA challenge, the pinned authorize request for a federated one. Used makes it
// one-shot; ExpireIn (unix) bounds it.
//
// Offered is what may ANSWER it — the second factors the sign-in was held offering.
// It is a property of the challenge rather than of either kind's payload, because
// both kinds have one and the answer is checked against the offer for both. Deciding
// it once, here, is also what makes the check honest: a finish that recomputed the
// offer would follow the account as it changed between the hold and the answer, and
// the finish that had NO offer to check accepted any factor at all — an
// authenticator-only account was passable with an emailed code.
type LoginChallenge struct {
	orm.Model[LoginChallenge]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime"`

	Kind     string   `json:"kind"`
	Subject  string   `json:"subject"`
	Payload  string   `json:"payload"`
	Offered  []string `json:"offered"`
	Used     bool     `json:"used"`
	ExpireIn int64    `json:"expireIn"`
}
