// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package oidc serves the IAM v2 OpenID Connect surface on zip. Handlers are
// RAW zip handlers (func(c *zip.Ctx) error), not typed generics, because the
// auth surface needs query params, form bodies, cookies, redirects, and
// headers — things a JSON-in/JSON-out typed handler can't reach.
//
// Phase 2 increment 1 (this file): the read-only discovery + JWKS surface.
// The authorize / token / userinfo / logout endpoints follow at the same
// canonical paths.
package oidc

import (
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
)

// Canonical HIP-0111 OIDC paths — the single source of truth the @hanzo/iam
// SDK hard-codes. iam2 is a standalone server, so it serves these directly
// (no /v2 transition prefix on the SDK-facing OIDC contract; the v2 prefix is
// only on the internal admin CRUD).
const (
	PathAuthorize = "/v1/iam/oauth/authorize"
	PathToken     = "/v1/iam/oauth/token"
	PathUserInfo  = "/v1/iam/oauth/userinfo"
	PathLogout    = "/v1/iam/oauth/logout"
	PathJWKS      = "/v1/iam/.well-known/jwks"
	PathDiscovery = "/.well-known/openid-configuration"
)

// Mount registers the OIDC surface on app. Increment 1 wires discovery + JWKS;
// subsequent increments add authorize/token/userinfo/logout at the paths above.
func Mount(app *zip.App) {
	app.Get(PathDiscovery, Discovery)
	app.Get(PathJWKS, JWKS)
}

// Discovery serves the OIDC discovery document, host-relative (issuer derived
// from the request host) so strict clients never split-origin. It advertises
// ONLY the canonical /v1/iam/oauth/* endpoints + jwks; implicit is permanently
// absent, PKCE S256 is the only challenge method.
func Discovery(c *zip.Ctx) error {
	iss := "https://" + httpx.EffectiveHost(c)
	return c.JSON(200, map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + PathAuthorize,
		"token_endpoint":                        iss + PathToken,
		"userinfo_endpoint":                     iss + PathUserInfo,
		"end_session_endpoint":                  iss + PathLogout,
		"jwks_uri":                              iss + PathJWKS,
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "none"},
		"subject_types_supported":               []string{"public"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"id_token_signing_alg_values_supported": []string{"RS256", "ES256", "MLDSA65"},
		"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "owner"},
	})
}

// JWKS serves the JSON Web Key Set. Increment 1 returns a well-formed empty
// set (200, ETag) so tooling and discovery validators succeed; the certs are
// wired from the Cert entity when token signing lands (increment 2 — ML-DSA-65
// hybrid JWT), keeping this endpoint's shape stable across the increment.
func JWKS(c *zip.Ctx) error {
	c.SetHeader("Cache-Control", "public, max-age=60")
	return c.JSON(200, map[string]any{"keys": []any{}})
}
