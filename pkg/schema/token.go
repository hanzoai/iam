// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Token is an issued OAuth2/OIDC token record (v1 the legacy surface `token`, v2 kind
// "tokens"). One row is the authorization-server's persistent memory of a
// single grant: the short-lived authorization code and its PKCE challenge, the
// minted access and refresh tokens (stored verbatim for reissue plus as salted
// hashes for constant-shape lookup), the scope, token type, lifetimes, and the
// RFC 8707 resource indicator that binds the grant to an audience. It ties an
// application, its organization, and the authenticated user together for the
// life of the session. Field complete against the v1 row so no credential,
// challenge, or lifetime is lost on migration — a dropped field here is lost
// auth state. Identity is the (Owner, Name) pair; the orm string key is
// "owner/name".
//
// Code, AccessTokenHash, and RefreshTokenHash carry orm:"index": v1 resolves a
// live grant by presented code or by the hash of a bearer/refresh token, so
// those columns are the hot lookup paths and stay indexed. Owner, Name, and
// CreatedTime are indexed for owner-scoped listing in newest-first order.
// AccessToken and RefreshToken are the full secret material (v1 mediumtext) and
// are left unindexed — lookups go through the hash siblings, never the plaintext.
type Token struct {
	orm.Model[Token]

	Owner       string `json:"owner" orm:"index"`
	Name        string `json:"name" orm:"index"`
	CreatedTime string `json:"createdTime" orm:"index"`

	Application  string `json:"application"`
	Organization string `json:"organization"`
	User         string `json:"user"`

	Code                string `json:"code" orm:"index" url:"-"`
	UserCode            string `json:"userCode,omitempty" orm:"index"`
	AccessToken         string `json:"accessToken" url:"-"`
	RefreshToken        string `json:"refreshToken" url:"-"`
	AccessTokenHash     string `json:"accessTokenHash" orm:"index"`
	RefreshTokenHash    string `json:"refreshTokenHash" orm:"index"`
	ExpiresIn           int    `json:"expiresIn"`
	Scope               string `json:"scope"`
	TokenType           string `json:"tokenType"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	CodeIsUsed          bool   `json:"codeIsUsed"`
	CodeExpireIn        int64  `json:"codeExpireIn"`
	Resource            string `json:"resource"` // RFC 8707 resource indicator

	// RedirectUri binds the authorization code to the exact redirect URI of the
	// authorize request (RFC 6749 §4.1.3): the token endpoint refuses a code
	// redeemed with a different redirect_uri, closing code-injection across a
	// client's registered URIs.
	RedirectUri string `json:"redirectUri,omitempty"`

	// Nonce is the OIDC authorize nonce, stored on the code and echoed into the
	// id_token minted at the exchange (OIDC Core §3.1.3.6) so a relying party
	// binds the id_token to its own request and detects replay.
	Nonce string `json:"nonce,omitempty"`

	// Refresh-token rotation state (v2). Each refresh belongs to a family (the
	// grant); rotation mints a new row in the same family and marks the prior
	// one consumed. Presenting a consumed refresh is reuse — the whole family is
	// revoked (RFC 9700 §4.14.2). RefreshExpireIn is the refresh token's own
	// absolute expiry (unix), independent of the access token's shorter life.
	RefreshFamily   string `json:"refreshFamily,omitempty" orm:"index"`
	RefreshConsumed bool   `json:"refreshConsumed,omitempty"`
	RefreshExpireIn int64  `json:"refreshExpireIn,omitempty"`

	// PublicGrant records that this grant was established WITHOUT client
	// authentication — a PKCE code exchange from a client that presented no
	// secret. Whether a client is confidential is a property of the GRANT, not
	// only of the registration: `hanzo-cli` and every @hanzo/iam SPA keep a
	// registered secret for a BACKEND path while the surface that actually signs
	// in is a public PKCE client that cannot hold one. authorizationCodeGrant
	// already makes exactly that bounded relaxation; this is the same fact,
	// recorded so refreshTokenGrant can honour it instead of demanding a secret
	// the client never had (which 401s invalid_client and kills the session at
	// the access token's expiry). Carried across rotation, so the second refresh
	// behaves like the first.
	PublicGrant bool `json:"publicGrant,omitempty"`
}
