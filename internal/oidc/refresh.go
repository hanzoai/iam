// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/subtle"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// Refresh-token rotation with reuse detection. A refresh token is an opaque,
// single-use bearer (stored only as a SHA-256 hash): every exchange consumes the
// presented token and mints a successor in the same rotation family. Presenting
// an already-consumed refresh is a replay — the whole family is revoked so a
// stolen token cannot outlive its legitimate successor (RFC 9700 §4.14). This is
// the load-bearing hardening over v1, whose refresh path is rotate-and-delete
// with no family cascade.

// refreshTokenGrant handles grant_type=refresh_token.
func refreshTokenGrant(c *zip.Ctx, db orm.DB) error {
	ctx := c.Context()
	now := nowFunc()

	presented := param(c, "refresh_token")
	if presented == "" {
		return tokenError(c, 400, "invalid_request", "refresh_token is required")
	}
	clientID, clientSecret := clientAuth(c)

	tok, err := store.GetTokenByRefreshHash(ctx, db, hashToken(presented))
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if tok == nil {
		return tokenError(c, 400, "invalid_grant", "refresh token is invalid or revoked")
	}
	app, err := resolveTokenApp(ctx, db, tok)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if app == nil {
		return tokenError(c, 400, "invalid_grant", "refresh token is invalid or revoked")
	}

	// Client authentication: the presented client must be the grant's client, and
	// a confidential client must present its secret.
	if clientID != "" && subtle.ConstantTimeCompare([]byte(clientID), []byte(app.ClientId)) != 1 {
		return tokenError(c, 400, "invalid_grant", "client mismatch")
	}
	if app.ClientSecret != "" {
		if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
			return tokenErrorClient(c, "client authentication failed")
		}
	}

	// Reuse detection: a consumed token was already rotated. Revoke the whole
	// family and refuse — a replay means the token leaked.
	if tok.RefreshConsumed {
		revokeRefreshFamily(ctx, db, tok.RefreshFamily)
		return tokenError(c, 400, "invalid_grant", "refresh token replay detected")
	}
	if tok.RefreshExpireIn != 0 && now.Unix() > tok.RefreshExpireIn {
		return tokenError(c, 400, "invalid_grant", "refresh token expired")
	}

	// Optional scope narrowing — never widening (RFC 6749 §6).
	scope := tok.Scope
	if req := param(c, "scope"); req != "" {
		if !scopeSubset(req, tok.Scope) {
			return tokenError(c, 400, "invalid_scope", "requested scope exceeds the grant")
		}
		scope = req
	}

	// Rotate: consume the presented token, then mint a successor in the same
	// family. The successor is a new row so the consumed one remains as a
	// tripwire for replay until the family is revoked or expires.
	tok.RefreshConsumed = true
	if err := store.SaveToken(ctx, db, tok); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	nameSeed, err := newOpaqueToken()
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	nu := &schema.Token{
		Owner:        tok.Owner,
		Application:  tok.Application,
		Organization: tok.Organization,
		User:         tok.User,
		Scope:        scope,
		Nonce:        tok.Nonce,
		Resource:     tok.Resource,
		RedirectUri:  tok.RedirectUri,
	}
	nu.Name = "rt-" + nameSeed[:24]
	resp, err := issueTokens(ctx, db, c, app, nu, tok.RefreshFamily, now)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if err := store.PersistToken(ctx, db, nu); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	return c.JSON(200, resp)
}

// revokeRefreshFamily deletes every token row in a rotation family — the
// containment response when a rotated refresh token is replayed.
func revokeRefreshFamily(ctx context.Context, db orm.DB, family string) {
	rows, err := store.ListTokensByRefreshFamily(ctx, db, family)
	if err != nil {
		return
	}
	for _, r := range rows {
		_ = store.DeleteToken(ctx, db, r)
	}
}

// scopeSubset reports whether every scope in sub is present in super.
func scopeSubset(sub, super string) bool {
	for _, s := range strings.Fields(sub) {
		if !hasScope(super, s) {
			return false
		}
	}
	return true
}
