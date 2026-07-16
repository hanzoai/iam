// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package oidc serves the IAM v2 OpenID Connect / OAuth2 surface on zip. The
// handlers are RAW zip handlers (func(c *zip.Ctx) error), not typed generics,
// because the auth surface needs query params, form bodies, redirects, and
// headers a JSON-in/JSON-out handler can't reach.
//
// The surface is the canonical hanzo.id contract, unchanged across the v1→v2
// backend swap: discovery + JWKS under .well-known, the oauth/{authorize,token,
// userinfo,logout} endpoints, and the front-door {get-app-login, auth/methods,
// login} the hosted UI calls. Tokens are signed JWTs (RS256 interop, ES/ML-DSA
// behind the same JWKS); every value is verified, never trusted.
package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"
)

// Canonical OIDC paths — the single source of truth the @hanzo/iam SDK and every
// existing relying party hard-code. iam2 serves them directly; the transition
// off v1 is a backend swap behind the same paths, never a parallel version.
const (
	PathAuthorize   = "/v1/iam/oauth/authorize"
	PathToken       = "/v1/iam/oauth/token"
	PathUserInfo    = "/v1/iam/oauth/userinfo"
	PathLogout      = "/v1/iam/oauth/logout"
	PathJWKS        = "/v1/iam/.well-known/jwks"
	PathJWKSRoot    = "/.well-known/jwks"
	PathDiscovery   = "/.well-known/openid-configuration"
	PathDiscoveryV1 = "/v1/iam/.well-known/openid-configuration"
)

// Mount registers the entire OIDC/OAuth2 surface on app, backed by db. This is
// the one entry point the route table calls — discovery, JWKS, the protocol
// endpoints, and the front door are all wired here so the surface lives in one
// place.
func Mount(app *zip.App, db orm.DB) {
	// Discovery and the JWKS are each served at BOTH the root well-known path
	// (RFC 8414 §3, where a bare-origin client and the gateway's default look)
	// and the /v1/iam-prefixed path, matching the live hanzo.id surface. Both
	// paths are the same handler over the same keys — one key set, two spellings
	// of where to find it.
	jwks := jwksHandler(db)
	app.Get(PathDiscovery, Discovery)
	app.Get(PathDiscoveryV1, Discovery)
	app.Get(PathJWKS, jwks)
	app.Get(PathJWKSRoot, jwks)

	// OAuth2 / OIDC protocol endpoints.
	app.Get(PathAuthorize, authorizeHandler(db))
	app.Post(PathAuthorize, authorizeHandler(db))
	app.Get(PathUserInfo, userinfoHandler(db))
	app.Post(PathUserInfo, userinfoHandler(db))
	app.Get(PathLogout, logoutHandler(db))
	app.Post(PathLogout, logoutHandler(db))

	// The token endpoint, the credential login that mints codes, and the
	// read-only front door the hosted <Login> self-configures from.
	MountToken(app, db)
	MountLogin(app, db)
	MountFrontDoor(app, db)

	// The confidential-client "act on behalf of a user" primitive (the console +
	// keyless-AI proxies mint their forwarded bearer here). Authenticates the
	// client itself, so it is not Bearer-gated.
	MountIssueToken(app, db)
}

// Discovery serves the OIDC discovery document, host-relative (issuer derived
// from the request host, the same value the tokens carry as `iss`) so a strict
// client never splits origin. It advertises only what iam2 implements: the
// authorization-code flow, S256 PKCE, the three supported grants, and the
// signing algorithms whose public keys the JWKS actually publishes.
func Discovery(c *zip.Ctx) error {
	iss := tokenIssuer(c)
	return c.JSON(200, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + PathAuthorize,
		"token_endpoint":                        iss + PathToken,
		"userinfo_endpoint":                     iss + PathUserInfo,
		"end_session_endpoint":                  iss + PathLogout,
		"jwks_uri":                              iss + PathJWKS,
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query", "fragment", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "RS512", "ES256", "ES384", "ES512", "MLDSA65"},
		"scopes_supported":                      []string{"openid", "email", "profile", "address", "phone", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"iss", "sub", "aud", "iat", "exp", "nbf", "jti", "nonce", "azp",
			"owner", "organization", "scope", "tokenType",
			"name", "preferred_username", "email", "email_verified",
			"picture", "address", "phone", "groups", "is_verified",
		},
	})
}
