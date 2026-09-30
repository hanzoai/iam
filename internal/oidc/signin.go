// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/store"
)

// The code→session exchange: POST /v1/iam/signin. After the authorize/login flow
// redirects back with `?code&state`, the console posts them here (code+state ride
// the query — what the @hanzo/iam client sends — or a JSON body) and iam redeems
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
	// CodeVerifier is the PKCE verifier for the challenge the code was minted
	// with; a code redeems here only with it.
	CodeVerifier string `json:"code_verifier"`
}

// signinHandler completes a sign-in: it exchanges the one-time code your
// application was handed at the end of the login flow for a live session, and
// returns the signed-in account.
//
// The code works once. This is the call that turns a finished login into
// something your application can act on.
func signinHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()

		// Query first (the redirect-flow client posts code+state as query params),
		// then a JSON body for programmatic callers.
		var f signinForm
		_ = c.Bind(&f)
		code, verifier := c.Query("code"), c.Query("code_verifier")
		if code == "" {
			code = f.Code
		}
		if verifier == "" {
			verifier = f.CodeVerifier
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
		// A portal session is minted only from a code the platform's own
		// application asked for, proven by the PKCE verifier of that request, and
		// carrying the moment the person signed in — which the session keeps, so a
		// session is never younger than the sign-in behind it.
		app, err := store.GetApplicationByName(ctx, db, tok.Owner, tok.Application)
		if err != nil {
			return httpx.Err(c, "server_error")
		}
		switch {
		case app == nil || !app.Platform:
			return httpx.Err(c, "the authorization code was not issued to the platform's own application")
		case tok.CodeChallenge == "" || VerifyPKCE(verifier, tok.CodeChallenge, tok.CodeChallengeMethod) != nil:
			return httpx.Err(c, "the authorization code must be redeemed with the PKCE verifier it was requested with")
		case tok.AuthTime <= 0:
			return httpx.Err(c, "the authorization code records no sign-in")
		}

		// Burn the code (single-use) BEFORE establishing the session, so a replay
		// loses the race and mints nothing.
		tok.CodeIsUsed = true
		if err := store.SaveToken(ctx, db, tok); err != nil {
			return httpx.Err(c, "server_error")
		}

		// Establish the durable session the portal + gateway admin-guard read via
		// get-account. Its sid is registered for revocation (sessions.Set).
		if err := sessions.Set(ctx, c.Fiber(), db, owner, name, tok.Application, tok.AuthTime); err != nil {
			return httpx.Err(c, err.Error())
		}

		env, status := accountEnvelopeFor(ctx, db, owner, name)
		return c.JSON(status, env)
	}
}
