// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Challenge is a half-finished authentication ceremony: the server-side memory
// of a sign-in that has proven one thing and must prove another before a token
// exists. It is minted by the MFA gate at login (the password verified, the
// second factor outstanding) and by the WebAuthn begin endpoints (the options
// issued, the assertion outstanding), and it is consumed exactly once by the
// matching finish.
//
// v1 keeps this in a beego cookie session — MfaSessionUserId (object/mfa.go:51),
// "registration"/"authentication" (controllers/webauthn.go:68,162). v2 has no
// key/value session store, so the state is an owner-scoped row and the client
// holds only its opaque id.
//
// It is a SIBLING of Token, never a Token with borrowed fields. A Token is a
// grant: /v1/iam/oauth/token resolves one by Code and mints an access token from
// it. Filing a challenge there would put a row on that lookup whose Application
// and Scope are fictions, and a fiction on the redemption path is an access
// token waiting to be minted from a half-authenticated ceremony. The two are
// different values with different lifecycles, so they are different entities.
//
// Identity is the (Owner, Name) pair and the orm string key is "owner/name";
// Name is the opaque id the client returns. Subject is the "owner/name" of the
// principal the ceremony is for — the ONE place a finish learns whom it is
// acting as (invariant 3: never a request parameter). Payload is the kind's own
// state: the go-webauthn SessionData JSON for a ceremony, the just-used
// verification type for an MFA challenge (v1's "verificationCodeType" session
// key, controllers/auth.go:539). Used makes it one-shot; ExpireIn (unix) bounds
// it. Id carries orm:"index" because the client presents the id alone.
type Challenge struct {
	orm.Model[Challenge]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime"`

	Kind     string `json:"kind"`
	Subject  string `json:"subject"`
	Payload  string `json:"payload"`
	Used     bool   `json:"used"`
	ExpireIn int64  `json:"expireIn"`
}
