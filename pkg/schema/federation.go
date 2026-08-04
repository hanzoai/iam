// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// FederationState is ONE in-flight identity-federation transaction: the
// server-side memory that spans the browser's round-trip to an external identity
// provider (Google/GitHub, …) during an Authorization-Code federation, where
// iam acts as the OIDC/OAuth2 Relying Party. It is what lets the IdP callback
// RESUME the original iam authorize request, and it is the CSRF / replay guard
// for that callback.
//
// Identity is the (Owner, Name) pair; Name IS the opaque 256-bit `state` value
// iam sends to the IdP, so the callback resolves the transaction by the state
// the IdP reflects back. The row is single-use (Used) and expiring (ExpireIn),
// and is bound to the initiating browser by BindHash — the SHA-256 of a
// per-transaction anti-forgery cookie — so a state that is stolen or injected
// into another browser cannot complete (login-CSRF / session-fixation defense).
//
// No IdP access/ID tokens are persisted here: only the material needed to VERIFY
// the IdP response (the IdP-leg PKCE verifier and, for OIDC, the nonce checked
// against the id_token) and to RESUME the app-leg (the original authorize
// parameters, so the callback mints an iam authorization code identical to the
// one a password login mints). The row is burned on consume.
type FederationState struct {
	orm.Model[FederationState]

	// (Owner, Name) is the natural key. Owner is the federated Provider's owner
	// (e.g. "admin"); Name is the opaque `state` token — the value the IdP
	// reflects back and the callback looks the transaction up by.
	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime" orm:"index"`

	// Provider is the Provider row NAME this transaction federates to
	// (e.g. "provider-google") — the connector whose callback this state authorizes.
	Provider string `json:"provider"`

	// App-leg: the ORIGINAL iam authorize request, stashed so the callback can
	// resume it. The minted iam code is bound to CodeChallenge/RedirectUri/Nonce
	// exactly as a password-login code is, so the relying party's existing PKCE
	// code→token exchange completes unchanged. AppState is echoed on the final
	// redirect back to the relying party.
	ClientId            string `json:"clientId"`
	RedirectUri         string `json:"redirectUri"`
	AppState            string `json:"appState"`
	Scope               string `json:"scope"`
	AppNonce            string `json:"appNonce"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	Resource            string `json:"resource"`

	// IdP-leg verification material (single-use; never leaves the process, never
	// logged). IdpVerifier is the PKCE code_verifier for the IdP token exchange;
	// IdpNonce is the nonce sent to an OIDC IdP and checked against the returned
	// id_token; BindHash is the SHA-256 of the browser anti-forgery cookie value.
	IdpVerifier string `json:"idpVerifier"`
	IdpNonce    string `json:"idpNonce"`
	BindHash    string `json:"bindHash"`

	// ExpireIn is the unix expiry; Used marks the transaction consumed so a
	// replayed callback completes nothing.
	ExpireIn int64 `json:"expireIn"`
	Used     bool  `json:"used"`
}
