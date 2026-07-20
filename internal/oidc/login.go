// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/mfa"
	"github.com/hanzoai/iam2/internal/schema"
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
// the code, /token redeems it. The password is verified against the row's own
// digest and never crosses a response.
//
// The route serves TWO requests, because v1 does (controllers/auth.go:905 and
// :1290): the credential post, and — when a challenge is outstanding — the
// second-factor post that finishes it. They are one endpoint because the client
// posts to one endpoint; they are separate branches because they prove different
// things. A code is minted only past the gate, on either path.

// PathLogin is the canonical credential-login endpoint.
const PathLogin = "/v1/iam/login"

// loginForm is the request body the SDK/portal posts. The first block is the
// credential post; MfaType/Passcode/RecoveryCode/EnableMfaRemember/Challenge are
// the second-factor post that answers a challenge this endpoint issued.
type loginForm struct {
	Application  string `json:"application"`
	Organization string `json:"organization"`
	Username     string `json:"username"` // email OR username
	Password     string `json:"password"`
	Type         string `json:"type"` // "code" (PKCE authorize) | "login" (bare session)

	// PKCE authorize passthrough (present when type=code).
	ClientId            string `json:"clientId"`
	RedirectUri         string `json:"redirectUri"`
	State               string `json:"state"`
	Scope               string `json:"scope"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	Resource            string `json:"resource"`

	// The second factor. Challenge names the outstanding ceremony; a browser
	// returns it in the cookie the gate set and leaves this empty.
	MfaType           string `json:"mfaType"`
	Passcode          string `json:"passcode"`
	RecoveryCode      string `json:"recoveryCode"`
	EnableMfaRemember bool   `json:"enableMfaRemember"`
	Challenge         string `json:"challenge"`
}

// The gate's two answers, verbatim from v1 (object/mfa.go:50-54). They are the
// literal STRING the client compares against in the envelope's `data` — the
// portal (web/src/auth/LoginPage.tsx:248) and the console's iam-login.ts both
// branch on it — so they are wire format, not internal names. Any other shape
// and the client reads the answer as an authorization code and the factor is
// skipped.
const (
	// RequiredMfa — the organization requires a factor this user has not
	// enrolled; the client must divert to enrollment.
	RequiredMfa = "RequiredMfa"
	// NextMfa — the user has factors; data2 carries the allowed ones and the
	// client must post one back. NO code is minted with this answer.
	NextMfa = "NextMfa"
)

// MountLogin registers POST /v1/iam/login.
func MountLogin(app *zip.App, db orm.DB) {
	app.Post(PathLogin, loginHandler(db))
}

func loginHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f loginForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		ctx := c.Context()

		// A post carrying no credential but naming an outstanding challenge is
		// the second half of a sign-in this endpoint already gated. The user
		// comes from the challenge, never from the body (invariant 3).
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
		// One opaque failure for "no such user" and "wrong password" — no oracle
		// that reveals whether the account exists.
		if user == nil || !users.VerifyPassword(user, f.Password) {
			return httpx.Err(c, "the username or password is incorrect")
		}

		// The password proved ONE factor. Everything past this point is the
		// second: the gate answers the request itself when a factor is
		// outstanding, and only a fall-through reaches a token.
		org, err := store.GetOrganizationByName(ctx, db, user.Owner)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		// verificationType is the factor JUST used. A password proves none of
		// the offerable factors, so it excludes nothing ("" — v1
		// controllers/auth.go:905 passes the same).
		gated, err := gate(c, db, user, org, "")
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if gated {
			return nil
		}

		return grant(c, db, user, f)
	}
}

// gate is the second-factor decision — the ONE place a sign-in is held. It
// answers the request itself and reports true when it did; a false means this
// principal has proven everything it owes and the caller may mint.
//
// Every path that signs a user in calls this BEFORE minting: the credential post
// above, and — when they land — the social/OAuth branch where the account
// already exists (v1 controllers/auth.go:1054) and the Web3 branch (v1
// controllers/web3_auth.go:229). v1 shipped the social one late, in 843e74f4,
// because an account-takeover fix exposed that "sign in with Google" walked past
// the factor entirely. One function, every call site — a gate that exists in one
// branch is not a gate.
//
// verificationType names the factor the caller already proved, so the challenge
// never offers it back (a code texted to a phone must not be answerable by
// texting that phone again). "" excludes nothing.
func gate(c *zip.Ctx, db orm.DB, user *schema.User, org *schema.Organization, verificationType string) (bool, error) {
	ctx := c.Context()

	// The organization REQUIRES a factor this user has not enrolled: the answer
	// is enrollment, not a challenge (v1 controllers/auth.go:515-520).
	if mfa.Prompt(org, user) {
		return true, httpx.Ok(c, RequiredMfa)
	}
	if !mfa.Enabled(user) {
		return false, nil
	}

	// "Remember this device" — a deadline in the FUTURE skips the factor
	// (v1 controllers/auth.go:523-527). Written by finishMfa with the same
	// nowRFC3339 the parse below expects; a format the parser cannot read is
	// treated as no deadline, so a bad value re-challenges rather than
	// silently granting a permanent skip.
	if remembered(user, nowFunc()) {
		return false, nil
	}

	allow := allowList(user, org, verificationType)
	if len(allow) == 0 {
		// Every factor is either the one just used or not actually enrolled:
		// there is nothing left to ask for (v1 falls through the same way).
		return false, nil
	}

	id, err := MintChallenge(ctx, db, KindMfa, user.Owner+"/"+user.Name, verificationType, nowFunc())
	if err != nil {
		return true, err
	}
	SetChallenge(c, id)
	// data is the STRING "NextMfa"; data2 carries the factors. No code is
	// minted here — that is the whole point of the gate.
	return true, httpx.Ok(c, NextMfa, allow)
}

// allowList is the factors a challenge may be answered with: enrolled, and not
// the one the caller just used (v1 controllers/auth.go:528-544). Each carries
// the org's remember window so the client can offer "don't ask again".
func allowList(user *schema.User, org *schema.Organization, verificationType string) []*schema.MfaProps {
	hours := 0
	if org != nil {
		hours = org.MfaRememberInHours
	}
	allow := []*schema.MfaProps{}
	for _, p := range mfa.AllProps(user) {
		if !p.Enabled || p.MfaType == verificationType {
			continue
		}
		p.MfaRememberInHours = hours
		allow = append(allow, p)
	}
	return allow
}

// remembered reports whether the user's "don't ask again" window is still open.
// An unparsable or empty deadline is not a skip: this fails CLOSED, to the
// challenge.
func remembered(user *schema.User, now time.Time) bool {
	if user.MfaRememberDeadline == "" {
		return false
	}
	deadline, err := time.Parse(time.RFC3339, user.MfaRememberDeadline)
	return err == nil && deadline.After(now)
}

// finishMfa answers an outstanding challenge. The user is loaded from the
// CHALLENGE's subject — never from the request — so a body naming another
// account cannot redirect the ceremony (invariant 3). Taking the challenge
// spends it, so a passcode replayed against the same id loses.
func finishMfa(c *zip.Ctx, db orm.DB, id string, f loginForm) error {
	ctx := c.Context()
	ch, err := TakeChallenge(ctx, db, id, KindMfa, nowFunc())
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	ClearChallenge(c)

	owner, name, _ := strings.Cut(ch.Subject, "/")
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if user == nil {
		return httpx.Err(c, ErrChallenge.Error())
	}

	switch {
	case f.Passcode != "":
		// The challenge's payload is the factor already used to get here.
		// Answering with that same factor proves nothing new (v1
		// controllers/auth.go:1325-1328).
		if f.MfaType == "" || f.MfaType == ch.Payload {
			return httpx.Err(c, "invalid multi-factor authentication type")
		}
		if f.MfaType != mfa.App {
			// Only TOTP has a verifier here. Refuse anything else rather than
			// wave it through: a factor with no verification is not a factor.
			return httpx.Err(c, "invalid multi-factor authentication type")
		}
		if !mfa.Verify(user.TotpSecret, f.Passcode) {
			return httpx.Err(c, "the multi-factor authentication code is incorrect")
		}
	case f.RecoveryCode != "":
		// A recovery code is one-time: the hit is removed and the row written
		// whether or not the rest of the sign-in succeeds, so a code cannot be
		// spent twice (v1 object/mfa.go:73-96).
		if !mfa.UseRecovery(user, f.RecoveryCode) {
			return httpx.Err(c, "the recovery code is incorrect")
		}
		if err := mfa.Save(ctx, db, user); err != nil {
			return httpx.Err(c, err.Error())
		}
	default:
		return httpx.Err(c, "missing passcode or recovery code")
	}

	if f.EnableMfaRemember {
		if err := remember(ctx, db, user); err != nil {
			return httpx.Err(c, err.Error())
		}
	}
	return grant(c, db, user, f)
}

// remember opens the "don't ask again" window: now + the ORG's
// MfaRememberInHours (v1 controllers/auth.go:1350-1360). A zero window — every
// live organization today — yields a deadline already in the past, so the gate
// keeps challenging. That is the shipped behavior and it is preserved: turning a
// zero into "forever" would silently disable the factor for every tenant.
func remember(ctx context.Context, db orm.DB, user *schema.User) error {
	org, err := store.GetOrganizationByName(ctx, db, user.Owner)
	if err != nil {
		return err
	}
	hours := 0
	if org != nil {
		hours = org.MfaRememberInHours
	}
	// Written with the SAME format `remembered` parses — a mismatch here is a
	// permanent skip or a permanent challenge, silently.
	user.MfaRememberDeadline = nowFunc().UTC().Add(time.Duration(hours) * time.Hour).Format(time.RFC3339)
	return mfa.Save(ctx, db, user)
}

// grant completes a sign-in that has passed the gate: the bare-session answer,
// or a PKCE-bound authorization code for the OAuth flow.
func grant(c *zip.Ctx, db orm.DB, user *schema.User, f loginForm) error {
	ctx := c.Context()
	userID := user.Owner + "/" + user.Name

	// type=login: a bare portal sign-in. Session issuance lands with the
	// session layer; for now report success + the user id (the shape the
	// portal expects for a non-OAuth sign-in).
	if f.Type != "code" {
		return httpx.Ok(c, userID)
	}

	// type=code: mint a PKCE-bound authorization code for the OAuth flow.
	app, err := resolveLoginApp(ctx, db, f)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if app == nil {
		return httpx.Err(c, "the application does not exist")
	}
	// Tenant isolation: the authenticated user's organization must be
	// permitted for this application — its own org, a shared app, or an app
	// that lets users choose their org. Without this a user in one tenant
	// could obtain a token whose `organization` claim names another tenant.
	// The org is the USER's own, from the loaded row, so a second-factor post
	// (which carries no organization field) is checked exactly like the first.
	if user.Owner != app.Organization && !app.IsShared && app.OrgChoiceMode == "" {
		return httpx.Err(c, "the user is not permitted to sign in to this application")
	}
	// Bind the code to an EXACTLY-registered redirect URI (RFC 6749 §3.1.2.3);
	// the token endpoint re-checks it. A supplied-but-unregistered URI is
	// refused — never minted against.
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

// GrantWebauthn completes a passkey sign-in through the SAME grant the password
// path uses. v1 puts the OAuth params of a webauthn finish in the QUERY
// (controllers/webauthn.go:175-176 + web/src/auth/LoginPage.tsx:444), so they are
// read there and folded into the one form the grant understands — one minting
// path, not a second copy of the PKCE and redirect rules.
//
// Note the query key is `challengeMethod`, not `codeChallengeMethod`: that is
// what the portal sends on this route.
func GrantWebauthn(c *zip.Ctx, db orm.DB, u *schema.User) error {
	return grant(c, db, u, loginForm{
		Type:                c.Query("responseType"),
		ClientId:            c.Query("clientId"),
		RedirectUri:         c.Query("redirectUri"),
		State:               c.Query("state"),
		Scope:               c.Query("scope"),
		Nonce:               c.Query("nonce"),
		CodeChallenge:       c.Query("codeChallenge"),
		CodeChallengeMethod: c.Query("challengeMethod"),
		Resource:            c.Query("resource"),
	})
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
