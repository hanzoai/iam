// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/golang-jwt/jwt/v5"

// Claims is the iam token claim set: the standard registered claims plus the
// Hanzo first-class claims the SDK and downstream validators read. owner and
// organization are the tenant (both the org slug); scope carries the granted
// scopes; nonce is echoed into the id_token; tokenType distinguishes an
// access-token from an id-token. A field is emitted only when populated, so one
// struct serves both token shapes without leaking empty claims.
type Claims struct {
	jwt.RegisteredClaims
	Scope        string `json:"scope,omitempty"`
	Owner        string `json:"owner,omitempty"`
	Organization string `json:"organization,omitempty"`
	Email        string `json:"email,omitempty"`
	// Name is the IAM USERNAME (the `<name>` half of `<owner>/<name>`, e.g. "z"),
	// never a display name. With Owner it forms the ONE address every Hanzo surface
	// names a principal by — `hanzo auth login` files its credential under
	// `owner/name` read straight off these claims, so whatever lands here IS the
	// principal downstream believes it holds.
	//
	// OIDC gives `name` display semantics and this token used to honour that,
	// carrying DisplayName ("Zach Kelling") while the account was "z". Adding
	// preferred_username gave the username somewhere to live but left `name`
	// display-sourced, so the wrong-principal reading stayed on the wire for every
	// consumer that reads `name` — the CLI among them. The display name now has its
	// own claim (Display) and `name` states the username, always. That is a
	// deliberate divergence from OIDC's display reading of `name`, taken because
	// one address for a principal beats two spellings that disagree.
	Name string `json:"name,omitempty"`
	// PreferredUsername is the OIDC-standard spelling of the same username, kept
	// because discovery advertises it in claims_supported and cloud's money path
	// already reads it: a wallet is addressed `<org>/<username>`, and when the only
	// username-shaped claim was a display-sourced `name` it addressed
	// `hanzo/Zach Kelling` — a wallet no funding path can name — while the balance
	// sat in `hanzo/z`. It is sourced from the SAME field as Name (Identity.Name),
	// so the two cannot drift apart the way `name` drifted from the account.
	PreferredUsername string `json:"preferred_username,omitempty"`
	// Display is the human-facing name — what a console greets you by. It is
	// profile data, never an address: nothing may resolve a principal from it.
	// `displayName` is the spelling schema.User, SCIM and whoami already use, so
	// this value keeps its one name across every surface that carries it.
	Display string `json:"displayName,omitempty"`
	// BillingAccount names WHICH LEDGER this token spends from — the org pool, or
	// empty to let the consumer's shape rule pick. account.Payer honours it above
	// every other signal precisely because it is SIGNED: a caller cannot name its
	// own payer, so this is IAM stating who is entitled to spend what.
	//
	// Empty is meaningful, not missing: it means "no explicit entitlement", and
	// the consumer falls back to the behaviour it already had.
	BillingAccount string `json:"billing_account,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	Azp            string `json:"azp,omitempty"`
	TokenType      string `json:"tokenType,omitempty"`
	// Orgs is the membership set — the tenancy the identity may act in, home org
	// first — a resource server reads to authorize an org-switch (X-Org-Id ∈ orgs)
	// with no round-trip. omitempty ⇒ a nil set omits the claim entirely (a machine
	// token, which has no membership, never carries it), so one struct still serves
	// both an app token and a user token without emitting an empty claim.
	Orgs []OrgRef `json:"orgs,omitempty"`
}
