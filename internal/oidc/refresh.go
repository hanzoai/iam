// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
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
	// a confidential client must present its secret (RFC 6749 §6).
	//
	// Confidential is a property of the GRANT, not only of the registration —
	// tok.PublicGrant, set at establishment by the SAME bounded relaxation
	// authorizationCodeGrant documents. One registration can serve both shapes: a
	// backend path that holds the secret, and a CLI or SPA surface that signs in
	// as a public PKCE client and holds none. Demanding the secret here would
	// contradict the exchange that just succeeded without it — the client cannot
	// acquire one an hour later — and the session would die at the access token's
	// expiry, for exactly the clients refresh_token exists for.
	//
	// It never widens: a grant that WAS client-authenticated still must
	// authenticate, and a presented secret is always verified.
	if clientID != "" && subtle.ConstantTimeCompare([]byte(clientID), []byte(app.ClientId)) != 1 {
		return tokenError(c, 400, "invalid_grant", "client mismatch")
	}
	// Reserved-org confidential clients never bypass client authentication.
	if app.ClientSecret != "" && (clientSecret != "" || !tok.PublicGrant || policy.IsReservedOrg(app.Organization)) && !app.Proves(clientSecret) {
		return tokenErrorClient(c, "client authentication failed")
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

	// Rotate atomically in ONE transaction: lock and re-read the presented row
	// (GetForUpdate), consume it, mint the successor (including any fail-closed
	// SuperAdmin audit row), and persist the successor. A failed audit or mint
	// rolls back without consuming the refresh token, and racing rotations on
	// the same token mint at most once while losers detect replay and revoke the
	// family.
	nameSeed, err := newOpaqueToken()
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	storageID := tok.Key().Encode()
	var resp tokenResponse
	err = db.RunInTransactionWith(ctx, nil, func(tx orm.DB) error {
		cur, err := orm.GetForUpdate[schema.Token](tx, storageID)
		if orm.IsNotFound(err) {
			return errReplay
		}
		if err != nil {
			return err
		}
		if cur.RefreshConsumed {
			return errReplay
		}
		if cur.RefreshExpireIn != 0 && now.Unix() > cur.RefreshExpireIn {
			return errRefreshExpired
		}
		cur.RefreshConsumed = true
		if err := cur.UpdateCtx(ctx); err != nil {
			return err
		}
		nu := &schema.Token{
			Owner:        cur.Owner,
			Application:  cur.Application,
			Organization: cur.Organization,
			User:         cur.User,
			Scope:        scope,
			Nonce:        cur.Nonce,
			Resource:     cur.Resource,
			RedirectUri:  cur.RedirectUri,
			// Carry establishment properties forward across rotation.
			PublicGrant: cur.PublicGrant,
			Device:      cur.Device,
		}
		nu.Name = "rt-" + nameSeed[:24]
		r, err := issueTokens(ctx, tx, c, app, nu, cur.RefreshFamily, now)
		if err != nil {
			return err
		}
		if err := store.PersistToken(ctx, tx, nu); err != nil {
			return err
		}
		resp = r
		return nil
	})
	if errors.Is(err, errReplay) {
		revokeRefreshFamily(ctx, db, tok.RefreshFamily)
		return tokenError(c, 400, "invalid_grant", "refresh token replay detected")
	}
	if errors.Is(err, errRefreshExpired) {
		return tokenError(c, 400, "invalid_grant", "refresh token expired")
	}
	if err != nil {
		return mintError(c, err)
	}
	return c.JSON(200, resp)
}

// errReplay is a rotation that found its presented token already consumed or revoked.
var errReplay = errors.New("oidc: refresh token already rotated")

// errRefreshExpired is a refresh token that expired before the rotation locked it.
var errRefreshExpired = errors.New("oidc: refresh token expired")

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
