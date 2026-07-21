// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/store"
)

// The code→session exchange: POST /v1/iam/signin. After the authorize/login flow
// redirects back with `?code&state`, the console posts them here (code+state ride
// the query — what the @hanzo/iam client sends — or a JSON body) and iam2 redeems
// the code for a durable SESSION, returning the account envelope like get-account.
//
// This is the session-establishment counterpart to the OAuth token endpoint: the
// token endpoint trades a code (with client auth + PKCE) for an access token; signin
// trades it for the portal's signed hanzo_session cookie. Possession of the 256-bit
// single-use code is the proof — no client secret crosses this call — so the code is
// BURNED on use: a replay establishes no second session.

// PathSignin is the canonical code→session endpoint.
const PathSignin = "/v1/iam/signin"

// signinForm is the JSON body a non-query caller may post; the canonical @hanzo/iam
// client sends code+state on the query string.
type signinForm struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

// signinHandler redeems an authorization code for a session and returns the account.
func signinHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()

		// Query first (the redirect-flow client posts code+state as query params),
		// then a JSON body for programmatic callers.
		code := c.Query("code")
		if code == "" {
			var f signinForm
			_ = c.Bind(&f)
			code = f.Code
		}
		if code == "" {
			return httpx.Err(c, "code is required")
		}

		tok, err := store.GetTokenByCode(ctx, db, code)
		if err != nil {
			return httpx.Err(c, "server_error")
		}
		now := nowFunc()
		// One opaque answer for unknown / already-redeemed / expired — no oracle, and
		// the same replay+expiry guards RedeemCode enforces (minus client/PKCE, which
		// this session exchange does not present).
		if tok == nil || tok.CodeIsUsed || (tok.CodeExpireIn != 0 && now.Unix() > tok.CodeExpireIn) {
			return httpx.Err(c, "the authorization code is invalid or expired")
		}
		owner, name := splitSub(tok.User)
		if owner == "" || name == "" {
			return httpx.Err(c, "the authorization code has no subject")
		}

		// Burn the code (single-use) BEFORE establishing the session, so a replay
		// loses the race and mints nothing.
		tok.CodeIsUsed = true
		if err := store.SaveToken(ctx, db, tok); err != nil {
			return httpx.Err(c, "server_error")
		}

		// Establish the durable session the portal + gateway admin-guard read via
		// get-account. Its sid is registered for revocation (sessions.Set).
		if err := sessions.Set(ctx, c.Fiber(), db, owner, name, tok.Application); err != nil {
			return httpx.Err(c, err.Error())
		}

		env, status := accountEnvelopeFor(ctx, db, owner, name)
		return c.JSON(status, env)
	}
}
