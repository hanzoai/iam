// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/subtle"
	"net/http"

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
func routeIntrospectRevoke(r *zip.Group, db orm.DB) {
	r.Raw(http.MethodPost, PathIntrospect, introspectHandler(db))
	r.Raw(http.MethodPost, PathRevoke, revokeHandler(db))
}

// authTokenClient authenticates the CALLING CLIENT, and only the client.
// client_id names it. The answer is the registration and whether the caller
// PROVED everything that registration can demand:
//
//   - a registration with no secret is PUBLIC: client_id is all it can present,
//     so it is proved by naming itself.
//   - a caller that presents a secret (in the body, or by HTTP Basic, even an
//     empty one) must present the right one (constant-time), or it fails.
//   - a caller that presents NO secret to a registration that holds one is that
//     registration's PUBLIC half: the browser or CLI surface that signed in by
//     PKCE and never held the secret. It is identified, not proved, and may only
//     act on grants established the same way (schema.Token.PublicGrant) — the
//     rule refreshTokenGrant applies to the same grants.
//
// It reads NOTHING about the token, so the status code it produces cannot tell an
// unauthenticated caller whether the token it sent exists (RFC 7009 §2.2). WHAT a
// caller may then do is a separate question, answered by each handler below.
func authTokenClient(ctx context.Context, db orm.DB, c *zip.Ctx) (app *schema.Application, proved, ok bool) {
	clientID, clientSecret := clientAuth(c)
	if clientID == "" {
		return nil, false, false
	}
	app, err := store.GetApplicationByClientId(ctx, db, clientID)
	if err != nil || app == nil {
		return nil, false, false
	}
	if app.ClientSecret == "" {
		return app, true, true
	}
	if clientSecret == "" && !basicAttempted(c) {
		return app, false, true
	}
	if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
		return nil, false, false
	}
	return app, true, true
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
		app, proved, ok := authTokenClient(ctx, db, c)
		if !ok || !proved || app.ClientSecret == "" {
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
// refresh token has (RFC 7009 §2.1 — a public client identifies itself with
// client_id). A browser app or CLI is a public PKCE client and holds no secret,
// and that includes the public half of a registration that keeps a secret for a
// backend path, so requiring one here would leave signing out as a local delete —
// forgetting a credential that stays spendable for the rest of its lifetime.
//
// Widening authentication does not widen authority. The caller must still POSSESS
// the token — and possession already permits USE, of which revocation is the
// strict opposite — and the row must belong to the client that presents it. A
// caller that did not prove the registration's secret revokes only a grant that
// was itself established without it, so a public client_id buys the ability to
// destroy exactly what its holder could otherwise spend.
func revokeHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		ctx := c.Context()
		app, proved, ok := authTokenClient(ctx, db, c)
		if !ok {
			return tokenErrorClient(c, "client authentication failed")
		}
		mayRevoke := func(row *schema.Token) bool {
			return row.Application == app.Name && (proved || row.PublicGrant)
		}

		tokenStr := param(c, "token")
		if tokenStr == "" {
			return revoked(c)
		}
		h := hashToken(tokenStr)

		if row, _ := store.GetTokenByAccessTokenHash(ctx, db, h); row != nil {
			if mayRevoke(row) {
				_ = store.DeleteToken(ctx, db, row)
			}
			return revoked(c)
		}
		if row, _ := store.GetTokenByRefreshHash(ctx, db, h); row != nil {
			if mayRevoke(row) {
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
