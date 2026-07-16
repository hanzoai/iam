// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/subtle"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/store"
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

// MountIntrospectRevoke registers the introspection + revocation endpoints.
func MountIntrospectRevoke(app *zip.App, db orm.DB) {
	app.Post(PathIntrospect, introspectHandler(db))
	app.Post(PathRevoke, revokeHandler(db))
}

// authConfidentialClient authenticates the calling client and requires it to be
// CONFIDENTIAL (holds a verified secret). Introspection and revocation are
// privileged token-management operations; a public client may not call them.
// Constant-time secret compare; a nil app or empty stored secret fails closed.
func authConfidentialClient(ctx context.Context, db orm.DB, c *zip.Ctx) (name string, ok bool) {
	clientID, clientSecret := clientAuth(c)
	if clientID == "" {
		return "", false
	}
	app, err := store.GetApplicationByClientId(ctx, db, clientID)
	if err != nil || app == nil || app.ClientSecret == "" {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
		return "", false
	}
	return app.Name, true
}

// introspectHandler implements RFC 7662. Active iff the grant row still exists
// (revocation-aware, the same liveness check userinfo makes) AND the JWT verifies
// under the trusted keys. The response carries the standard introspection claims;
// an inactive/absent/unauthenticated-target token returns only `{active:false}`.
func introspectHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		ctx := c.Context()
		if _, ok := authConfidentialClient(ctx, db, c); !ok {
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

// revokeHandler implements RFC 7009. A confidential client revokes a token that
// was issued to IT (§2.1) — an access token deletes that grant row; a refresh
// token revokes the whole rotation family so no further access tokens can be
// minted and every sibling dies. A token belonging to another client, or an
// unknown token, is a silent 200 (no revocation, no oracle — §2.2).
func revokeHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		ctx := c.Context()
		clientName, ok := authConfidentialClient(ctx, db, c)
		if !ok {
			return tokenErrorClient(c, "client authentication failed")
		}

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
