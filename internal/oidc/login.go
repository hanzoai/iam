// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/sessions"
	"github.com/hanzoai/iam2/internal/store"
	"github.com/hanzoai/iam2/internal/users"
)

// The credential login front door: POST /v1/iam/login. The @hanzo/iam SDK +
// hanzo.id portal post here with the app/org + username/password (+ the PKCE
// authorize params when type=code). On success with type=code we mint a
// PKCE-bound authorization code and return it in the Response envelope; the SDK
// then exchanges it at /v1/iam/oauth/token. Login by EMAIL or USERNAME.
//
// This is the interactive-flow counterpart to the token endpoint: login mints
// the code, /token redeems it. Password verification is bcrypt (constant-time),
// never plaintext, and the hash never crosses a response.

// PathLogin is the canonical credential-login endpoint.
const PathLogin = "/v1/iam/login"

// loginForm is the request body the SDK/portal posts.
type loginForm struct {
	Application  string `json:"application"`
	Organization string `json:"organization"`
	Username     string `json:"username"` // email OR username
	Password     string `json:"password"`
	Type         string `json:"type"` // "code" (PKCE authorize) | "device" (RFC 8628 approval) | "login" (bare session)

	// UserCode is the RFC 8628 code the device displays, transcribed by the human
	// approving it (type=device).
	UserCode string `json:"userCode"`

	// PKCE authorize passthrough (present when type=code).
	ClientId            string `json:"clientId"`
	RedirectUri         string `json:"redirectUri"`
	State               string `json:"state"`
	Scope               string `json:"scope"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	Resource            string `json:"resource"`

	// The second factor (present on the finishing request). Challenge names the
	// outstanding ceremony; a browser returns it in the cookie the gate set and
	// leaves this empty.
	MfaType           string `json:"mfaType"`
	Passcode          string `json:"passcode"`
	RecoveryCode      string `json:"recoveryCode"`
	EnableMfaRemember bool   `json:"enableMfaRemember"`
	Challenge         string `json:"challenge"`
}

// routeLogin registers POST /v1/iam/login.
func routeLogin(r zip.Router, db orm.DB) {
	r.Post(PathLogin, loginHandler(db))
}

func loginHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f loginForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		ctx := c.Context()

		// A post carrying no fresh credential but naming an outstanding challenge is
		// the SECOND half of a sign-in this endpoint already gated: the second-factor
		// answer. The principal comes from the challenge, never from the body.
		if f.Username == "" && f.Password == "" {
			if id := ReadChallenge(c, f.Challenge); id != "" {
				return finishMfa(c, db, id, f)
			}
		}

		if f.Organization == "" || f.Username == "" || f.Password == "" {
			return httpx.Err(c, "organization, username and password are required")
		}

		user, err := resolveLoginUser(ctx, db, f.Organization, f.Username)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		// The hash algorithm is a property of the ROW, not a constant: use the
		// user's PasswordType, falling back to the organization's (v1's
		// object/check.go contract). Every live v1 row is argon2id — a bcrypt-only
		// verify would fail every real login at cutover.
		orgPasswordType := loginOrgPasswordType(ctx, db, f.Organization)
		// One opaque failure for "no such user" and "wrong password" — no oracle
		// that reveals whether the account exists.
		if user == nil || !users.VerifyPassword(user, f.Password, orgPasswordType) {
			return httpx.Err(c, "the username or password is incorrect")
		}

		// The password proved ONE factor. The gate holds the sign-in when a second
		// factor is outstanding — before ANY token or device approval — and answers
		// the request itself; a false means nothing more is owed. The verificationType
		// is "" because a password proves none of the offerable factors.
		org, err := store.GetOrganizationByName(ctx, db, user.Owner)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		gated, err := gate(c, db, user, org, "")
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if gated {
			return nil
		}

		return loginGrant(c, db, user, f)
	}
}

// loginGrant completes a sign-in that has passed the gate: a device approval, a
// bare portal session, or a PKCE-bound authorization code. It is the ONE minting
// tail every interactive path reaches — the credential post and the second-factor
// finish alike — so the checks between "this is the user" and "here is the grant"
// are stated once and cannot be true of one path and false of another.
func loginGrant(c *zip.Ctx, db orm.DB, user *schema.User, f loginForm) error {
	ctx := c.Context()

	// type=device: approve a pending RFC 8628 device authorization against the
	// identity now fully proven (device.go).
	if f.Type == "device" {
		return approveDevice(c, db, user, f.UserCode)
	}

	userID := user.Owner + "/" + user.Name

	// type=login: a bare portal sign-in. Establish the durable session the portal +
	// the gateway admin-guard read via get-account, then report the user id. The
	// cookie is best-effort — a session failure never blocks a valid login.
	if f.Type != "code" {
		_ = sessions.Set(ctx, c.Fiber(), db, user.Owner, user.Name, f.Application)
		return httpx.Ok(c, userID)
	}

	// type=code: mint a PKCE-bound authorization code for the OAuth flow. The org is
	// the USER's own, from the loaded row, so a second-factor post (which carries no
	// organization field) is checked exactly like the first.
	app, err := resolveLoginApp(ctx, db, f)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if app == nil {
		return httpx.Err(c, "the application does not exist")
	}
	if user.Owner != app.Organization && !app.IsShared && app.OrgChoiceMode == "" {
		return httpx.Err(c, "the user is not permitted to sign in to this application")
	}
	// Bind the code to an EXACTLY-registered redirect URI (RFC 6749 §3.1.2.3); the
	// token endpoint re-checks it. A supplied-but-unregistered URI is refused.
	if f.RedirectUri != "" && !app.IsRedirectUriValid(f.RedirectUri) {
		return httpx.Err(c, "invalid redirect_uri")
	}
	method := normalizeChallengeMethod(f.CodeChallenge, f.CodeChallengeMethod)
	if f.CodeChallenge != "" && method != "S256" {
		return httpx.Err(c, "only S256 PKCE is supported")
	}
	// A public client (no secret) must use PKCE — no downgrade.
	if app.ClientSecret == "" && f.CodeChallenge == "" {
		return httpx.Err(c, "PKCE is required for public clients")
	}
	code, err := MintCode(app, userID, f.Scope, f.CodeChallenge, method, f.Resource, nowFunc())
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	// Bind the redirect_uri and nonce onto the code so the token exchange can
	// re-verify the redirect and echo the nonce into the id_token.
	code.RedirectUri = f.RedirectUri
	code.Nonce = f.Nonce
	if err := store.PersistToken(ctx, db, code); err != nil {
		return httpx.Err(c, err.Error())
	}
	// The SDK reads data as the authorization code to exchange at /token.
	return httpx.Ok(c, code.Code)
}

// resolveLoginUser looks a user up by email (contains "@") or username, scoped
// to the org.
func resolveLoginUser(ctx context.Context, db orm.DB, org, identifier string) (*schema.User, error) {
	if strings.Contains(identifier, "@") {
		u, err := store.GetUserByEmail(ctx, db, org, identifier)
		if err != nil || u != nil {
			return u, err
		}
		// Fall through: some accounts set name = email (email is not indexed as
		// a separate login) — try name too.
	}
	return store.GetUserByName(ctx, db, org, identifier)
}

// resolveLoginApp resolves the OAuth app for a type=code login: by clientId when
// present, else by (org, application name).
func resolveLoginApp(ctx context.Context, db orm.DB, f loginForm) (*schema.Application, error) {
	if f.ClientId != "" {
		return store.GetApplicationByClientId(ctx, db, f.ClientId)
	}
	if f.Application != "" {
		return store.GetApplicationByName(ctx, db, "admin", f.Application)
	}
	return nil, nil
}

// loginOrgPasswordType returns the organization's PasswordType — the fallback
// when a user row carries none. A missing org yields "" (the user's own type
// then decides; if neither is set, cred.Verify fails closed rather than guessing
// an algorithm).
func loginOrgPasswordType(ctx context.Context, db orm.DB, org string) string {
	o, err := store.GetOrganizationByName(ctx, db, org)
	if err != nil || o == nil {
		return ""
	}
	return o.PasswordType
}
