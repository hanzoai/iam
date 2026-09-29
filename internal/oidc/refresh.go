// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/subtle"
	"errors"
	"strings"

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
	// authenticate, a presented secret is always verified, and an application of
	// a reserved org is never relaxed (Application.Relaxes).
	if clientID != "" && subtle.ConstantTimeCompare([]byte(clientID), []byte(app.ClientId)) != 1 {
		return tokenError(c, 400, "invalid_grant", "client mismatch")
	}
	if app.ClientSecret != "" && (clientSecret != "" || !tok.PublicGrant || !app.Relaxes()) && !app.Proves(clientSecret) {
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

	// Rotate: consume the presented token, then mint a successor in the same
	// family. The successor is a new row so the consumed one remains as a
	// tripwire for replay until the family is revoked or expires.
	//
	// All three writes are ONE transaction with the mint between them, because
	// the mint writes too: a SuperAdmin token's record (trail.go). A mint that
	// fails, that record included, leaves the presented token unconsumed, so a
	// passing fault costs the holder a retry and not the session. The presented
	// row is read again inside it, so of two rotations racing on one token only
	// the first mints and the second is a replay.
	nameSeed, err := newOpaqueToken()
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	var resp tokenResponse
	err = db.RunInTransaction(ctx, func(tx orm.DB) error {
		cur, err := store.GetTokenByRefreshHash(ctx, tx, tok.RefreshTokenHash)
		if err != nil {
			return err
		}
		if cur == nil || cur.RefreshConsumed {
			return errReplay
		}
		cur.RefreshConsumed = true
		if err := store.SaveToken(ctx, tx, cur); err != nil {
			return err
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
			// The successor is the SAME grant, so it carries the same establishment
			// fact. Dropping it would make only the FIRST refresh work and the second
			// 401 — a session that dies an hour late instead of on time.
			PublicGrant: tok.PublicGrant,
			Device:      tok.Device,
		}
		nu.Name = "rt-" + nameSeed[:24]
		// issueTokens re-resolves nu.User against the user table, so THIS is where a
		// rotation revalidates the subject it inherited. It matters here more than at
		// any other grant: the User key above is copied from the predecessor, frozen at
		// the establishment that minted the family, and a user can be deleted, banned,
		// or re-keyed underneath it afterwards. Without the re-read, a family outlives
		// the identity it was granted to and every rotation renews that.
		//
		// A refusal writes nothing, and the family stays refused for as long as its
		// subject is: every rotation asks again.
		r, err := issueTokens(ctx, tx, c, app, nu, tok.RefreshFamily, now)
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
	if err != nil {
		return mintError(c, err)
	}
	return c.JSON(200, resp)
}

// errReplay is a rotation that found its presented token already consumed.
var errReplay = errors.New("oidc: refresh token already rotated")

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
