// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Token is an issued OAuth2/OIDC token record (v1 Casdoor `token`, v2 kind
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

	Code                string `json:"code" orm:"index"`
	AccessToken         string `json:"accessToken"`
	RefreshToken        string `json:"refreshToken"`
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
}
