// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"encoding/json"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/store"
)

// The second-factor RESUME for a federated login. When the federation callback
// resolves a user who owes a factor, it mints nothing — it parks the resume in a
// single-use, expiring, subject-pinned LoginChallenge (KindFederation) and sends
// the browser to the hosted 2FA page. This endpoint is where that page posts the
// factor: it verifies it through the SAME factor seam the password MFA gate uses
// and, only then, mints the code for the PINNED authorize request.
//
// It closes the hole a live MFA gate would otherwise leave open: without it, a
// 2FA-enrolled user signing in through Google/GitHub would skip the second factor
// a password login demands.

// PathFederationMfa is the resume endpoint. Public (before the Guard): it
// self-authenticates through the challenge the callback set — a single-use,
// expiring, subject-pinned token — exactly as the callback self-authenticates via
// its state. The challenge id rides the httpOnly, SameSite=Lax cookie, so a
// cross-site POST carries no challenge and fails closed.
const PathFederationMfa = "/v1/iam/oauth/federation/mfa"

// routeFederationMfa registers the resume endpoint on the PUBLIC group r.
func routeFederationMfa(r zip.Router, db orm.DB) {
	r.Post(PathFederationMfa, federationMfaHandler(db))
}

// fedMfaForm is the resume body. It carries the FACTOR and nothing else — no user
// id and no redirect_uri, BY DESIGN: the target user and the whole authorize
// request are pinned in the challenge (Subject + Payload), so there is
// structurally no request field that could swap them mid-flow.
type fedMfaForm struct {
	Challenge    string `json:"challenge"`
	MfaType      string `json:"mfaType"`
	Passcode     string `json:"passcode"`
	RecoveryCode string `json:"recoveryCode"`
}

// federationMfaHandler completes a sign-in that came in through another identity
// provider and still owes a second factor. The person supplies the factor here
// and the login finishes.
//
// The account is fixed when the challenge is issued, not by the request, so no
// one can redirect a half-finished login onto somebody else's account. A wrong
// factor uses the challenge up: retrying means starting the sign-in again, the
// same as a mistyped password.
func federationMfaHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f fedMfaForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		ctx := c.Context()

		ch, err := TakeChallenge(ctx, db, ReadChallenge(c, f.Challenge), KindFederation, nowFunc())
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		ClearChallenge(c)

		owner, name, _ := strings.Cut(ch.Subject, "/")
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if user == nil || user.IsForbidden || user.IsDeleted {
			return httpx.Err(c, ErrChallenge.Error())
		}

		// Verify the factor through the ONE seam, shared with the password gate. It used
		// to be a second switch here that called itself the shared one while accepting
		// only TOTP, so an account holding just an emailed or texted factor could answer
		// a password login and not this one.
		if err := proveFactor(ctx, db, user, ch, f.MfaType, f.Passcode, f.RecoveryCode); err != nil {
			return httpx.Err(c, err.Error())
		}

		// Resume the ORIGINAL authorize request from the PINNED payload — never from
		// the request. Re-resolve the app and re-validate its redirect_uri against the
		// live allow-list (defense in depth against a tampered row).
		var p fedResumeParams
		if err := json.Unmarshal([]byte(ch.Payload), &p); err != nil {
			return httpx.Err(c, "internal error")
		}
		app, err := store.GetApplicationByClientId(ctx, db, p.ClientId)
		if err != nil || app == nil {
			return httpx.Err(c, "the client application is unavailable")
		}
		if !app.IsRedirectUriValid(p.RedirectUri) {
			return httpx.Err(c, "invalid redirect_uri")
		}
		loc, err := federationMint(c, db, app, user, p, nowFunc())
		if err != nil {
			if err == errPKCERequired {
				return httpx.Err(c, "PKCE is required for public clients")
			}
			return httpx.Err(c, "internal error")
		}
		// The SPA navigates the browser to this RP redirect (redirect_uri?code&state).
		return httpx.Ok(c, loc)
	}
}
