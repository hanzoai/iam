// Copyright 2026 Hanzo AI, Inc. All rights reserved.
package oidc

import (
	"context"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/store"
)

// PathAccount (canonical.go) is the native front-door account endpoint — what
// the hanzo.id portal's account page and the gateway admin-guard call.
//
// SECURITY CONTRACT. The gateway admin-guard derives the global-admin
// (SuperAdmin) predicate from the `owner` this returns — a caller is a global
// admin iff `data.owner == AdminOrg` (gateway/cmd/admin-guard). So the response
// shape MUST match v1 exactly — {status, sub, name, data:<user>, data2:<org>} —
// and every secret (password hash, access secret, TOTP, recovery codes) MUST be
// redacted. Anonymous callers get {status:"error"} (200, casibase convention),
// never a leak: the admin-guard reads status=="error" → not-admin, fail-closed.
// accountResponse mirrors v1's Response for the account read (the casibase envelope).
type accountResponse struct {
	Status string `json:"status"`
	Msg    string `json:"msg,omitempty"`
	Sub    string `json:"sub,omitempty"`
	Name   string `json:"name,omitempty"`
	Data   any    `json:"data,omitempty"`
	Data2  any    `json:"data2,omitempty"`
}

// getAccount returns the signed-in person's own account and the organization
// they belong to — what a console reads to draw the account menu.
//
// Passwords, API secrets and MFA material are stripped. It answers for a session
// cookie or a bearer token alike.
func getAccount(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()

		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return c.JSON(200, accountResponse{Status: "error", Msg: "please sign in first"})
		}
		env, status := accountEnvelopeFor(ctx, db, owner, name)
		return c.JSON(status, env)
	}
}

// accountEnvelopeFor builds the get-account envelope for an already-resolved
// caller: the REDACTED user + organization in the casibase shape, or an error
// envelope when the user or org lookup fails. It is the ONE place the account
// envelope is assembled, shared by get-account and signin (the code→session
// exchange), so the two can never drift. status is the HTTP code to return with
// it (200 for both ok and the casibase "error" convention, 500 on a store fault).
func accountEnvelopeFor(ctx context.Context, db orm.DB, owner, name string) (accountResponse, int) {
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return accountResponse{Status: "error", Msg: "server_error"}, 500
	}
	if user == nil {
		return accountResponse{Status: "error", Msg: "the user does not exist"}, 200
	}
	org, err := store.GetOrganizationByName(ctx, db, user.Owner)
	if err != nil {
		return accountResponse{Status: "error", Msg: "server_error"}, 500
	}
	return accountResponse{
		Status: "ok",
		Sub:    subjectOf(user), // the stable `sub` (UUID, or owner/name pre-cutover)
		Name:   user.Name,
		Data:   user.Mask(), // owner + isAdmin survive; every secret stripped
		Data2:  org.Mask(),  // org master/default passwords masked
	}, 200
}

// callerOf resolves the signed-in principal by SESSION COOKIE first (the portal
// and gateway-admin-guard path) then bearer access token (the API path) — two
// credentials, one identity. ok=false means no valid session or token.
func callerOf(ctx context.Context, c *zip.Ctx, db orm.DB) (owner, name string, ok bool) {
	if o, n, ok := sessions.Resolve(ctx, c.Fiber(), db); ok {
		return o, n, true
	}
	bearer := httpx.Bearer(c)
	if bearer == "" {
		return "", "", false
	}
	claims, err := verifyToken(ctx, db, bearer)
	if err != nil {
		return "", "", false
	}
	// The `sub` is a stable UUID for a v2 token; resolve it to the real (owner,name)
	// so the account/whoami envelope reports the identity, not the opaque subject. A
	// subject with no user row (a machine token) is not an account caller.
	u, err := store.GetUserBySubject(ctx, db, claims.Subject)
	if err != nil || u == nil {
		return "", "", false
	}
	return u.Owner, u.Name, true
}
