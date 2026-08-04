// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/subtle"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// RFC 7662 Token Introspection + RFC 7009 Token Revocation — the two standard
// token-management endpoints a resource server / confidential client uses. Both
// are POST, client-authenticated (client_secret_basic or _post, constant-time),
// on the OAuth token surface. Introspection reports whether a token is currently
// active — JWT-valid AND its grant row still exists, so a REVOKED token reads
// inactive — and returns its claims when active. Revocation deletes the grant
// row (the whole refresh-rotation family for a refresh token) and always answers
// 200 (RFC 7009 §2.2: an invalid/unknown token is not an error, so the endpoint
// is no token-existence oracle).
const (
	PathIntrospect = "/v1/iam/oauth/introspect"
	PathRevoke     = "/v1/iam/oauth/revoke"
)

// routeIntrospectRevoke registers the introspection + revocation endpoints on the
// PUBLIC group r (client-authenticated, not Bearer-gated).
func routeIntrospectRevoke(r zip.Router, db orm.DB) {
	r.Post(PathIntrospect, introspectHandler(db))
	r.Post(PathRevoke, revokeHandler(db))
}

// authTokenClient authenticates the CALLING CLIENT, and only the client:
// client_id names it, and a client that HOLDS a secret must present it
// (constant-time). A client that holds none is PUBLIC, and client_id is the whole
// of what it can present — the same bounded relaxation authorizationCodeGrant and
// refreshTokenGrant already make for the loopback PKCE clients. It never widens a
// confidential client: a stored secret is always demanded and always verified,
// and a nil/unknown app fails closed.
//
// It reads NOTHING about the token, so the status code it produces cannot tell an
// unauthenticated caller whether the token it sent exists (RFC 7009 §2.2). WHAT a
// caller may then do is a separate question, answered by each handler below.
func authTokenClient(ctx context.Context, db orm.DB, c *zip.Ctx) (*schema.Application, bool) {
	clientID, clientSecret := clientAuth(c)
	if clientID == "" {
		return nil, false
	}
	app, err := store.GetApplicationByClientId(ctx, db, clientID)
	if err != nil || app == nil {
		return nil, false
	}
	if app.ClientSecret != "" &&
		subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
		return nil, false
	}
	return app, true
}

// introspectHandler answers whether an access token is still good, and what it
// is good for — the check a resource server of yours makes before honouring a
// token it did not mint.
//
// A token counts as active only if it verifies AND has not been revoked, so a
// revoked token reads as dead here immediately rather than until it expires. A
// token that is unknown, expired or revoked answers simply that it is not
// active, and nothing more — the endpoint is not a way to learn about tokens you
// were not given.
func introspectHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		ctx := c.Context()
		// Introspection reports on tokens the caller did not necessarily issue, so
		// it stays CONFIDENTIAL-only: RFC 7662 §2.1 addresses it to a protected
		// resource, and a public client_id is unauthenticated by construction.
		app, ok := authTokenClient(ctx, db, c)
		if !ok || app.ClientSecret == "" {
			return tokenErrorClient(c, "client authentication failed")
		}

		tokenStr := param(c, "token")
		if tokenStr == "" {
			return c.JSON(200, inactiveToken())
		}
		h := hashToken(tokenStr)
		// Liveness: the grant row must still exist (a revoked/rotated token has none).
		row, _ := store.GetTokenByAccessTokenHash(ctx, db, h)
		if row == nil {
			row, _ = store.GetTokenByRefreshHash(ctx, db, h)
		}
		if row == nil {
			return c.JSON(200, inactiveToken())
		}
		claims, err := verifyToken(ctx, db, tokenStr)
		if err != nil {
			return c.JSON(200, inactiveToken())
		}

		resp := map[string]any{
			"active":     true,
			"token_type": "Bearer",
			"scope":      claims.Scope,
			"client_id":  claims.Azp,
			"sub":        claims.Subject,
			"iss":        claims.Issuer,
			"owner":      claims.Owner,
		}
		if claims.Organization != "" {
			resp["organization"] = claims.Organization
		}
		if claims.Email != "" {
			resp["username"] = claims.Email
		}
		if len(claims.Audience) > 0 {
			resp["aud"] = claims.Audience
		}
		if claims.ExpiresAt != nil {
			resp["exp"] = claims.ExpiresAt.Unix()
		}
		if claims.IssuedAt != nil {
			resp["iat"] = claims.IssuedAt.Unix()
		}
		if claims.NotBefore != nil {
			resp["nbf"] = claims.NotBefore.Unix()
		}
		if claims.ID != "" {
			resp["jti"] = claims.ID
		}
		return c.JSON(200, resp)
	}
}

// revokeHandler retires a token before it expires — what you call when someone
// signs out or a credential may have leaked.
//
// Revoking an access token kills that token. Revoking a REFRESH token kills the
// whole chain it belongs to, so no further access tokens can be minted from it
// and every token already minted from it dies with it.
//
// A token that is not yours, or that never existed, answers success and does
// nothing — so the endpoint cannot be used to discover which tokens are real.
//
// PUBLIC clients revoke too, and must: sign-out is the only control a long-lived
// refresh token has. hanzo-cli is a public PKCE client holding a 30-day rotating
// refresh token, so a confidential-only revocation endpoint made `hanzo auth
// logout` a LOCAL DELETE — the credential it dropped stayed spendable at
// hanzo.id for the rest of the month, with nothing able to kill it. Measured
// 2026-08-01: revoke answered 401 invalid_client and the refresh token went on
// minting access tokens.
//
// Widening authentication does not widen authority. The caller must still POSSESS
// the token — and possession already permits USE, of which revocation is the
// strict opposite — and the row must belong to the client that presents it, so a
// public client_id buys the ability to destroy exactly what its holder could
// otherwise spend. RFC 6749 §3.2.1 is the same reading: a client with no
// credentials identifies itself with client_id.
func revokeHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		ctx := c.Context()
		app, ok := authTokenClient(ctx, db, c)
		if !ok {
			return tokenErrorClient(c, "client authentication failed")
		}
		clientName := app.Name

		tokenStr := param(c, "token")
		if tokenStr == "" {
			return revoked(c)
		}
		h := hashToken(tokenStr)

		if row, _ := store.GetTokenByAccessTokenHash(ctx, db, h); row != nil {
			if row.Application == clientName {
				_ = store.DeleteToken(ctx, db, row)
			}
			return revoked(c)
		}
		if row, _ := store.GetTokenByRefreshHash(ctx, db, h); row != nil {
			if row.Application == clientName {
				family, _ := store.ListTokensByRefreshFamily(ctx, db, row.RefreshFamily)
				for _, t := range family {
					_ = store.DeleteToken(ctx, db, t)
				}
			}
			return revoked(c)
		}
		return revoked(c)
	}
}

// inactiveToken is the RFC 7662 response for a token that is not active.
func inactiveToken() map[string]any { return map[string]any{"active": false} }

// revoked is the RFC 7009 §2.2 success response: HTTP 200, empty body.
func revoked(c *zip.Ctx) error { return c.Status(200).JSON(200, struct{}{}) }
