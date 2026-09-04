// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package oidc serves the IAM OpenID Connect / OAuth2 surface on zip. The
// handlers are RAW zip handlers (func(c *zip.Ctx) error), not typed generics,
// because the auth surface needs query params, form bodies, redirects, and
// headers a JSON-in/JSON-out handler can't reach.
//
// The surface is the canonical hanzo.id contract, unchanged across the v1→v2
// backend swap: discovery + JWKS under .well-known, the oauth/{authorize,token,
// userinfo,logout} endpoints, and the native {get-app-login, auth/methods,
// login} the hosted UI calls. Tokens are signed JWTs (RS256 interop, ES/ML-DSA
// behind the same JWKS); every value is verified, never trusted.
package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"
)

// Canonical OIDC paths — the single source of truth the @hanzo/iam SDK and every
// existing relying party hard-code. iam serves them directly; the transition
// off v1 is a backend swap behind the same paths, never a parallel version.
const (
	PathAuthorize    = "/v1/iam/oauth/authorize"
	PathToken        = "/v1/iam/oauth/token"
	PathUserInfo     = "/v1/iam/oauth/userinfo"
	PathLogout       = "/v1/iam/oauth/logout"
	PathJWKS         = "/v1/iam/.well-known/jwks"
	PathJWKSRoot     = "/.well-known/jwks"
	PathDiscovery    = "/.well-known/openid-configuration"
	PathDiscoveryV1  = "/v1/iam/.well-known/openid-configuration"
	PathASMetadata   = "/.well-known/oauth-authorization-server"        // RFC 8414 (root)
	PathASMetadataV1 = "/v1/iam/.well-known/oauth-authorization-server" // RFC 8414 (v1)
	PathDevice       = "/v1/iam/oauth/device"                           // RFC 8628 device authorization
	// PathDeviceInfo names the application a pending user_code belongs to — what
	// the approval page must show a human before they authorize it.
	PathDeviceInfo = "/v1/iam/oauth/device/info"
	// PathDeviceVerify is the user-facing device-approval PAGE (a route in the
	// hosted SPA), not an API path: RFC 8628's verification_uri is somewhere a
	// human opens and signs in, which the JSON token API can never be.
	PathDeviceVerify = "/login/oauth/device"
)

// CodeLoginRequired is the STABLE machine-readable reason for "this needs a
// signed-in session and there isn't one". The human `msg` beside it is prose and
// several causes share it; a caller that must ROUTE on the cause — the device
// approval page deciding to show a sign-in form rather than an error — cannot
// parse prose.
//
// It exists because the alternative was a lie: an unauthenticated device approval
// used to fall through to the credential check and answer "organization, username
// and password are required", naming three fields that page has never rendered and
// never sends. An error must describe the thing the caller can actually do.
const CodeLoginRequired = "login_required"

// PathRefreshToken is the spelling signed-in clients POST their refresh to. It is
// the SAME handler as PathToken at a second address — grant_type=refresh_token
// travels in the body, so this is a second spelling of the endpoint, never a
// separate grant. Discovery advertises only PathToken.
//
// It is registered because callers hold it: refreshes arrive here continuously,
// and serving them anywhere else logs every signed-in session out. It is the only
// legacy token spelling kept — the Casdoor-era `access_token` path and the
// `/v1/iam/userinfo` spelling draw no traffic, so neither is registered.
const PathRefreshToken = "/v1/iam/oauth/refresh_token"

// Route registers the entire OIDC/OAuth2 surface on r, backed by db. This is the
//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// one entry point the route table calls — discovery, JWKS, the protocol
// endpoints, and the native surface are all bound here so it all lives in one
// place. r is the PUBLIC group (registered before the router's authentication
// Guard): the whole OIDC/OAuth + native surface is pre-authentication by
// construction, so membership in this group IS what makes it reachable without a
// bearer — there is no separate allow-list to keep in sync.
func Route(r *zip.App, db orm.DB) {
	// Discovery and the JWKS are each served at BOTH the root well-known path
	// (RFC 8414 §3, where a bare-origin client and the gateway's default look)
	// and the /v1/iam-prefixed path, matching the live hanzo.id surface. Both
	// paths are the same handler over the same keys — one key set, two spellings
	// of where to find it.
	r.Get(PathDiscovery, Discovery)
	r.Get(PathDiscoveryV1, Discovery)
	// RFC 8414 OAuth Authorization Server Metadata — the same self-consistent
	// document at the OAuth well-known path (a superset serves it), so an OAuth-only
	// client that looks for `oauth-authorization-server` finds the AS too.
	r.Get(PathASMetadata, Discovery)
	r.Get(PathASMetadataV1, Discovery)
	// One handler, two addresses: the same key set under the subsystem's prefix
	// and at the host root, because a relying party configured with either must
	// find it.
	zip.Alias(r.Get, PathJWKS, PathJWKSRoot, jwksHandler(db))

	// OAuth2 / OIDC protocol endpoints.
	r.Get(PathAuthorize, authorizeHandler(db))
	r.Post(PathAuthorize, authorizeHandler(db))
	r.Get(PathUserInfo, userinfoHandler(db))
	r.Post(PathUserInfo, userinfoHandler(db))
	r.Get(PathLogout, logoutHandler(db))
	r.Post(PathLogout, logoutHandler(db))

	// The token endpoint, the credential login that mints codes, and the
	// read-only endpoints the hosted <Login> self-configures from.
	routeToken(r, db)
	routeLogin(r, db)
	routeFrontDoor(r, db)

	// The two WebAuthn ceremonies: enroll a passkey, and sign in with one. Both
	// are public — a passkey sign-in has no bearer to present, and the enrollment
	// pair authenticates itself from the portal's session cookie.
	routeWebauthn(r, db)

	// Identity federation: the external-IdP callback (Google/GitHub, …). The
	// authorize endpoint kicks a federation off when the request names a
	// `provider`; this registers the fixed return endpoint the IdP redirects to.
	routeFederation(r, db)
	routeFederationMfa(r, db)
	// The two halves of the linking law: connect a provider to the account you
	// already hold, and disconnect one.
	routeLink(r, db)
	routeUnlink(r, db)

	// RFC 7662 introspection + RFC 7009 revocation — the standard token-management
	// endpoints a resource server / confidential client uses (client-authenticated).
	routeIntrospectRevoke(r, db)

	// RFC 8628 device authorization grant — the browserless CLI sign-in. The
	// request endpoint is registered here; the poll rides the token endpoint and
	// the approval rides the login endpoint, both already public above.
	routeDevice(r, db)

	// The confidential-client "act on behalf of a user" primitive (the console +
	// keyless-AI proxies mint their forwarded bearer here). Authenticates the
	// client itself, so it is not Bearer-gated.
	routeIssueToken(r, db)
}

// Discovery returns the OpenID Connect discovery document — the one URL you
// point a standards-compliant client at so it can find every other endpoint on
// its own, instead of you configuring them by hand.
//
// It advertises only what is actually implemented, so a client that reads it
// cannot ask for a flow that will fail: the authorization-code flow, PKCE with
// S256, the supported grants, and the signing algorithms whose public keys the
// JWKS really publishes.
//
// The issuer is derived from the host you asked on and is the same value the
// tokens carry, so a client that pins the issuer never sees it change.
func Discovery(c *zip.Ctx) error {
	iss := tokenIssuer(c)
	return c.JSON(200, map[string]any{
		"issuer":                        iss,
		"authorization_endpoint":        iss + PathAuthorize,
		"token_endpoint":                iss + PathToken,
		"userinfo_endpoint":             iss + PathUserInfo,
		"introspection_endpoint":        iss + PathIntrospect,
		"revocation_endpoint":           iss + PathRevoke,
		"end_session_endpoint":          iss + PathLogout,
		"device_authorization_endpoint": iss + PathDevice,
		"jwks_uri":                      iss + PathJWKS,
		"response_types_supported":      []string{"code"},
		"response_modes_supported":      []string{"query", "fragment", "form_post"},
		"grant_types_supported":         []string{"authorization_code", "refresh_token", "client_credentials", "password", grantTypeTokenExchange, deviceGrant},
		// The sign-in modes a client may ask for. Advertised because a relying
		// party CANNOT discover them by trying: a server that ignores prompt=none
		// answers with a login page, which to the client is indistinguishable from
		// a server that honoured it and found no session. Saying so here is what
		// lets a client rely on the silent flow instead of guessing.
		//
		// `consent` is absent because there is no consent screen to show, and
		// `create` because there is no signup-first mode on this endpoint. This
		// document advertises only what is implemented.
		"prompt_values_supported":               promptValues,
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "RS512", "ES256", "ES384", "ES512", "MLDSA65"},
		"scopes_supported":                      []string{"openid", "email", "profile", "address", "phone", "offline_access"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"claims_supported": []string{
			"iss", "sub", "aud", "iat", "exp", "nbf", "jti", "nonce", "azp", "act",
			"owner", "organization", "scope", "tokenType",
			// `name` and `preferred_username` are both the USERNAME here; the human's
			// name is `displayName`. Advertising a claim nothing emits is what left
			// consumers reading `name` as a display name for a year, so the list says
			// exactly what a token carries.
			"name", "preferred_username", "displayName", "email", "email_verified",
			"picture", "address", "phone", "groups", "is_verified",
		},
	})
}
