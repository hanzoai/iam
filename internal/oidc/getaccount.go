// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package oidc

import (
	"context"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/store"
)

// PathAccount (canonical.go) is the native account endpoint — what
// the hanzo.id portal's account page and the gateway admin-guard call.
//
// SECURITY CONTRACT. The gateway admin-guard derives the SuperAdmin predicate
// from the `owner` this returns — a caller is a SuperAdmin iff
// `data.owner == AdminOrg` (gateway/cmd/admin-guard). So the response
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

		owner, name, ok := readerOf(ctx, c, db)
		if !ok {
			return c.JSON(200, accountResponse{Status: "error", Msg: "please sign in first"})
		}
		env, status := accountEnvelopeFor(ctx, db, owner, name)
		return c.JSON(status, env)
	}
}

// PathAccounts is the list of people signed in on the calling browser.
const PathAccounts = "/v1/iam/accounts"

// browserAccount is what the account chooser shows for one person: enough to
// recognise them and to name them in a login_hint, nothing more.
type browserAccount struct {
	Sub         string `json:"sub"`
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName,omitempty"`
	Email       string `json:"email,omitempty"`
	Avatar      string `json:"avatar,omitempty"`
}

// getAccounts returns the people signed in on this browser, the most recent
// sign-in first — what the sign-in page lists when an application asks the person
// to choose an account.
//
// It reads the session cookie and nothing else, so it only ever answers the
// browser holding the sessions. An account forbidden or deleted since it signed
// in is left out. A browser with nobody signed in gets an empty list.
func getAccounts(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		list := []browserAccount{}
		for _, sc := range sessions.Accounts(ctx, c.Fiber(), db) {
			u, err := store.GetUserByName(ctx, db, sc.Owner, sc.Name)
			if err != nil || u == nil || u.IsForbidden || u.IsDeleted {
				continue
			}
			list = append(list, browserAccount{
				Sub:         subjectOf(u),
				Owner:       u.Owner,
				Name:        u.Name,
				DisplayName: u.DisplayName,
				Email:       u.Email,
				Avatar:      u.Picture(),
			})
		}
		c.SetHeader("Cache-Control", "no-store")
		return httpx.Ok(c, list)
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
//
// It answers the account's HOLDER, which is who every self-service write acts
// as: an impersonated bearer resolves nobody here, because the person holding it
// is an operator and not the person it names. Reads use readerOf.
func callerOf(ctx context.Context, c *zip.Ctx, db orm.DB) (owner, name string, ok bool) {
	return callerFrom(ctx, db, c.Fiber().Cookies(sessions.CookieName), httpx.Bearer(c))
}

// callerFrom is callerOf for a typed handler, which zip hands no *Ctx — it gets
// the same two credentials as bound header values instead. Same order and the
// same checks: session cookie first (the portal), then bearer (the API). callerOf
// delegates here so one of the two cannot quietly become the lenient one.
func callerFrom(ctx context.Context, db orm.DB, sessionCookie, bearer string) (owner, name string, ok bool) {
	owner, name, imp, ok := accountOf(ctx, db, sessionCookie, bearer)
	return owner, name, ok && !imp
}

// readerOf is callerOf for a READ: an impersonated bearer resolves to the person
// it names, so an operator sees that person's account as they would. Never for a
// write — a password, a passkey, a linked sign-in, a profile — which is how an
// impersonation would outlive its fifteen minutes.
func readerOf(ctx context.Context, c *zip.Ctx, db orm.DB) (owner, name string, ok bool) {
	owner, name, _, ok = accountOf(ctx, db, c.Fiber().Cookies(sessions.CookieName), httpx.Bearer(c))
	return owner, name, ok
}

// accountOf is the one resolution behind callerOf and readerOf: the account a
// session cookie or a bearer speaks for, and whether that bearer is impersonated.
func accountOf(ctx context.Context, db orm.DB, sessionCookie, bearer string) (owner, name string, imp, ok bool) {
	if sc, ok := sessions.CurrentValue(ctx, sessionCookie, db); ok {
		return sc.Owner, sc.Name, false, true
	}
	if bearer == "" {
		return "", "", false, false
	}
	claims, err := verifyBearer(ctx, db, bearer)
	if err != nil {
		return "", "", false, false
	}
	// The `sub` is a stable UUID for a v2 token; resolve it to the real (owner,name)
	// so the account/whoami envelope reports the identity, not the opaque subject. A
	// subject with no user row (a machine token) is not an account caller.
	u, err := store.GetUserBySubject(ctx, db, claims.Subject)
	if err != nil || u == nil {
		return "", "", false, false
	}
	// An impersonation reads only while its operator may still impersonate.
	if claims.Imp {
		if _, err := Operator(ctx, db, claims); err != nil {
			return "", "", false, false
		}
	}
	return u.Owner, u.Name, claims.Imp, true
}
