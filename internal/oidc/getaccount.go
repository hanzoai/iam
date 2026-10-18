// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package oidc

import (
	"context"
	"errors"
	"net/http"

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

// errSignedOut is a write no credential on the request speaks for.
var errSignedOut = errors.New("please sign in first")

// asker is what a write presents to say who is asking: the identity host's
// session cookie VALUE with the request facts sessions.Forgeable judges it by,
// and a bearer.
type asker struct {
	Method string
	Cookie string
	Site   string // Sec-Fetch-Site
	Origin string // Origin
	Host   string // Host
	Type   string // Content-Type
	Bearer string
}

// callerOf resolves the principal a WRITE acts as, by SESSION COOKIE first (the
// portal) then bearer access token (the API) — two credentials, one identity.
// errSignedOut means neither names a live account; sessions.ErrForgeable means
// the cookie came on a request another page could have sent, with no bearer.
//
// It answers the account's HOLDER, which is who every self-service write acts
// as: a bearer someone else acts through resolves nobody here — an impersonation,
// whose holder is an operator, and a delegation (as(), `act`), whose holder is the
// org key that minted it — because neither is the person it names. A delegated
// token founded orgs and took their keys for the person it named. Reads use
// readerOf.
func callerOf(ctx context.Context, c *zip.Ctx, db orm.DB) (owner, name string, err error) {
	return callerFrom(ctx, db, asker{
		Method: c.Method(),
		Cookie: c.Fiber().Cookies(sessions.CookieName),
		Site:   c.Header("Sec-Fetch-Site"),
		Origin: c.Header("Origin"),
		Host:   c.Header("Host"),
		Type:   c.Header("Content-Type"),
		Bearer: httpx.Bearer(c),
	})
}

// callerFrom is callerOf for a typed handler, which zip hands no *Ctx — it gets
// the same facts as bound header values instead. callerOf delegates here so one
// of the two cannot quietly become the lenient one.
//
// The cookie is spent only through sessions.WriterValue, the one rule for a write
// the cookie authorizes. A bearer is not ambient — no page can make a browser
// attach one — so a request carrying one is answered on it when its cookie may
// not be spent.
func callerFrom(ctx context.Context, db orm.DB, a asker) (owner, name string, err error) {
	sc, err := sessions.WriterValue(ctx, a.Cookie, sessions.Request{Method: a.Method, Site: a.Site, Origin: a.Origin, Host: a.Host, Type: a.Type}, db)
	if sc != nil {
		owner, name, ok := sessionAccount(ctx, db, sc)
		if !ok {
			return "", "", errSignedOut
		}
		return owner, name, nil
	}
	if a.Bearer == "" {
		if err != nil {
			return "", "", err
		}
		return "", "", errSignedOut
	}
	owner, name, acted, ok := bearerAccount(ctx, db, a.Bearer)
	if !ok || acted {
		return "", "", errSignedOut
	}
	return owner, name, nil
}

// refuseCaller answers a raw write callerOf resolved nobody for: 403 for a cookie
// on a request another page could have sent, else the handler's own sign-in
// refusal msg.
func refuseCaller(c *zip.Ctx, err error, msg string) error {
	if errors.Is(err, sessions.ErrForgeable) {
		return httpx.Fail(c, http.StatusForbidden, err.Error(), "")
	}
	return httpx.Err(c, msg)
}

// callerAnswer is refuseCaller for a typed handler, which returns its answer.
func callerAnswer(err error) *httpx.Answer {
	if errors.Is(err, sessions.ErrForgeable) {
		return httpx.Bad(http.StatusForbidden, err.Error(), "")
	}
	return httpx.Bad(400, errSignedOut.Error(), CodeLoginRequired)
}

// readerOf is callerOf for a READ: a bearer someone else acts through resolves to
// the person it names, so an operator sees that person's account as they would.
// Never for a write — a password, a passkey, a linked sign-in, a profile, an org —
// which is how an impersonation would outlive its fifteen minutes.
func readerOf(ctx context.Context, c *zip.Ctx, db orm.DB) (owner, name string, ok bool) {
	owner, name, _, ok = accountOf(ctx, db, c.Fiber().Cookies(sessions.CookieName), httpx.Bearer(c))
	return owner, name, ok
}

// accountOf is the resolution behind readerOf: the account a session cookie or a
// bearer speaks for, and whether someone else acts through that bearer (an
// impersonation, or a delegation naming its actor in `act`).
//
// A suspended or deleted account resolves nobody on either credential: a session
// outlives the suspension that ends its account, so the account is read on every
// call, not trusted from the session.
func accountOf(ctx context.Context, db orm.DB, sessionCookie, bearer string) (owner, name string, acted, ok bool) {
	if sc, ok := sessions.CurrentValue(ctx, sessionCookie, db); ok {
		owner, name, ok := sessionAccount(ctx, db, sc)
		return owner, name, false, ok
	}
	if bearer == "" {
		return "", "", false, false
	}
	return bearerAccount(ctx, db, bearer)
}

// sessionAccount is the live account a verified session names.
func sessionAccount(ctx context.Context, db orm.DB, sc *sessions.Cookie) (owner, name string, ok bool) {
	u, err := store.GetUserByName(ctx, db, sc.Owner, sc.Name)
	if err != nil || u == nil || u.IsForbidden || u.IsDeleted {
		return "", "", false
	}
	return u.Owner, u.Name, true
}

// bearerAccount is the live account a bearer speaks for, and whether someone else
// acts through it.
func bearerAccount(ctx context.Context, db orm.DB, bearer string) (owner, name string, acted, ok bool) {
	claims, err := verifyBearer(ctx, db, bearer)
	if err != nil {
		return "", "", false, false
	}
	// The `sub` is a stable UUID for a v2 token; resolve it to the real (owner,name)
	// so the account/whoami envelope reports the identity, not the opaque subject. A
	// subject with no user row (a machine token) is not an account caller.
	u, err := store.GetUserBySubject(ctx, db, claims.Subject)
	if err != nil || u == nil || u.IsForbidden || u.IsDeleted {
		return "", "", false, false
	}
	// An impersonation reads only while its operator may still impersonate.
	if claims.Imp {
		if _, err := Operator(ctx, db, claims); err != nil {
			return "", "", false, false
		}
	}
	return u.Owner, u.Name, claims.Imp || claims.Act != nil, true
}
