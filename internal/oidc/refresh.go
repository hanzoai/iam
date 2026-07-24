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

	// The presented client_id, when sent, must be the grant's client (both paths).
	if clientID != "" && subtle.ConstantTimeCompare([]byte(clientID), []byte(app.ClientId)) != 1 {
		return tokenError(c, 400, "invalid_grant", "client mismatch")
	}
	// Client authentication is discriminated by the GRANT's provenance, never by
	// whether the request carries a secret — the same reason the authorization_code
	// grant gates on the code, not the request. There is no code_verifier on refresh,
	// so the discriminator is the durable provenance carried on the token family:
	//
	//   - CONFIDENTIAL grant (app has a registered secret AND the grant was NOT
	//     PKCE-bound: tok.CodeChallenge == "", preserved across every rotation below).
	//     Such a client authenticated with its secret at grant time and MUST present a
	//     matching one on refresh, constant-time (RFC 9700 §4.13.2 — confidential
	//     clients are authenticated on refresh). app.ClientSecret is non-empty on this
	//     branch, so a missing/wrong secret fails the compare → 401.
	//   - PUBLIC grant (everything else): a browser PKCE client — including the
	//     dual-use record that has a stored secret but redeemed via PKCE — or a
	//     secretless client. It holds no usable secret and is authenticated by
	//     possession of the rotating, single-use, reuse-detected refresh token itself
	//     (the refresh analog of the PKCE verifier). A presented secret is a stale
	//     browser echo — IGNORED, never a 401. Verifying it was the same defect the
	//     authorization_code path had: it 401'd the in-browser refresh.
	if app.ClientSecret != "" && tok.CodeChallenge == "" {
		if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
			return tokenErrorClient(c, "client authentication failed")
		}
	}

	// Expiry and scope are validated on the presented row BEFORE the consume. Both read
	// immutable per-row state (RefreshExpireIn is stamped once at mint, Scope is the grant's
	// own), so no lock is needed here; validating scope first also means a too-wide request
	// refuses without burning an otherwise-valid token.
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

	// Rotate: atomically consume the presented token, then mint a successor in the same
	// family. Reuse detection and the consume are ONE row-locked operation
	// (store.ConsumeRefreshToken) — a read-check-then-write would let two concurrent exchanges
	// of ONE token both observe RefreshConsumed=false and both rotate, so a stolen refresh
	// could be raced through as "first use", silently defeating reuse detection (RFC 9700
	// §4.14 TOCTOU). Losing the race IS the reuse case: revoke the whole family so the
	// containment fires for the loser exactly as a sequential replay would, and the consumed
	// row remains a tripwire for later replay until the family is revoked or expires.
	won, err := store.ConsumeRefreshToken(ctx, db, tok)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if !won {
		revokeRefreshFamily(ctx, db, tok.RefreshFamily)
		return tokenError(c, 400, "invalid_grant", "refresh token replay detected")
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
		// Preserve the grant's PKCE provenance across rotation: it is the durable
		// public-vs-confidential discriminator the client-auth check above reads. A
		// dual-use record (stored secret, redeemed via PKCE = public) would otherwise be
		// misclassified confidential on the 2nd rotation and 401 the browser — the bug
		// re-emerging one hop later. CodeChallenge is only ever SERVER-SET, at the
		// authorization-code mint (internal/oidc.MintCode from the /oauth/authorize flow),
		// and carried verbatim here on each rotation: there is NO REST/CRUD write path to
		// the tokens entity (the mass-assign create/update was removed — see
		// internal/tokens), so a caller cannot set or flip it. It therefore faithfully
		// reflects the grant's real provenance and cannot be attacker-chosen.
		CodeChallenge:       tok.CodeChallenge,
		CodeChallengeMethod: tok.CodeChallengeMethod,
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
