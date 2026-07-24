// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
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
		// Verify through the ONE lockout-enforcing choke point (F-D1) — users.Authenticate,
		// shared with the ROPC grant, the registry token endpoint, and the LDAP-bind seam.
		// One opaque failure for "no such user" and "wrong password" — no oracle that
		// reveals whether the account exists — and a distinct lockout refusal after a run
		// of wrong passwords.
		ok, locked := users.Authenticate(ctx, db, user, f.Password, orgPasswordType, nowFunc())
		if locked {
			return httpx.Err(c, "too many failed attempts; the account is temporarily locked")
		}
		if !ok {
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
	// identity now fully proven (device.go). Device approval has its OWN tenant model —
	// a SuperAdmin may deliberately approve a device across tenants (device.go), a
	// blessed capability — so the reserved-org grant gate below (which binds a
	// SuperAdmin to its own-org app) does NOT apply to it; it precedes that gate.
	if f.Type == "device" {
		return approveDevice(c, db, user, f.UserCode)
	}

	// Reserved-org grant gate — the SAME store.IsReservedOrg refuse signup.go and the
	// ROPC grant enforce, which login.go alone was missing (F-D2 tail / F-D1). A
	// RESERVED-org principal (a SuperAdmin under "admin", a built-in/service identity)
	// may be granted a bare SESSION or an authorization CODE ONLY through an application
	// that itself SERVES that reserved org — the dedicated console. A shared,
	// org-choice, or cross-tenant app must NEVER authenticate one: otherwise any shared
	// app (whose per-type tenant gate below accepts every org) would mint a real
	// SuperAdmin grant on the correct admin password. Enforced here, ahead of BOTH the
	// bare-session and the type=code branches, so every credential grant shape (incl.
	// the second-factor finish, which reaches this same tail) is bound identically. A
	// normal-tenant login never triggers this (IsReservedOrg is false), so the shared/
	// org-choice apps keep serving them unchanged.
	if store.IsReservedOrg(user.Owner) {
		app, err := resolveLoginApp(ctx, db, f)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if app == nil || user.Owner != app.Organization {
			return httpx.Err(c, "the user is not permitted to sign in to this application")
		}
	}

	userID := user.Owner + "/" + user.Name

	// type=login: a bare portal sign-in. Establish the durable session the portal +
	// the gateway admin-guard read via get-account, then report the user id. The
	// cookie is best-effort — a session failure never blocks a valid login.
	if f.Type != "code" {
		_ = sessions.Set(ctx, c.Fiber(), db, user.Owner, user.Name, f.Application)
		return httpx.Ok(c, userID)
	}

	// type=code: mint the PKCE-bound authorization code through the ONE interactive mint
	// routine — MintFor, the SAME one the /oauth/authorize SSO fast path and the wallet
	// login use. Routing every credentialed front door through MintFor states the tenant
	// gate, the exact-redirect binding (RFC 6749 §3.1.2.3), the S256-only PKCE policy, the
	// public-client-must-PKCE rule, and the persisted fields (owner-pinned user,
	// CodeChallenge/method, redirect_uri, nonce) EXACTLY ONCE — so a redeemed code behaves
	// identically no matter which endpoint minted it, closing the divergence that left an
	// authorize-path code non-PKCE. The user's org is userID's own owner half, set
	// server-side, so a second-factor post (no organization field) is bound like the first.
	app, err := resolveLoginApp(ctx, db, f)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if app == nil {
		return httpx.Err(c, "the application does not exist")
	}
	code, err := MintFor(ctx, db, app, userID, Mint{
		Type:                "code",
		RedirectUri:         f.RedirectUri,
		State:               f.State,
		Scope:               f.Scope,
		Nonce:               f.Nonce,
		CodeChallenge:       f.CodeChallenge,
		CodeChallengeMethod: f.CodeChallengeMethod,
		Resource:            f.Resource,
	})
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	// The SDK reads data as the authorization code to exchange at /token.
	return httpx.Ok(c, code)
}

// resolveLoginUser looks a user up by the login identifier, scoped to the org,
// resolving NAME FIRST and email second — casdoor's own precedence
// (object.GetUserByFields tries the user NAME before the email/phone). This is
// load-bearing at cutover when two rows collide on an email: e.g. org hanzo holds
// both `hanzo/z` (name z, email z@hanzo.ai) and `hanzo/z@hanzo.ai` (name
// z@hanzo.ai, same email). The ROPC/login username "z@hanzo.ai" must resolve to
// the NAME match (hanzo/z@hanzo.ai) exactly as casdoor did — an email-first lookup
// would silently authenticate the OTHER identity. The `@` gate stays only to skip
// a pointless email lookup for a plain username.
func resolveLoginUser(ctx context.Context, db orm.DB, org, identifier string) (*schema.User, error) {
	if u, err := store.GetUserByName(ctx, db, org, identifier); err != nil || u != nil {
		return u, err
	}
	if strings.Contains(identifier, "@") {
		return store.GetUserByEmail(ctx, db, org, identifier)
	}
	return nil, nil
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
