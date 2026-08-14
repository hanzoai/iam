// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
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
	// Code is a one-time code delivered to the identifier in Username, offered
	// INSTEAD of Password. Present means "sign me in with this code"; the two are
	// alternatives and a request carrying a code never reaches the password check.
	Code string `json:"code"`
	Type string `json:"type"` // "code" (PKCE authorize) | "device" (RFC 8628 approval) | "login" (bare session)

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

// loginHandler signs a person in with the credential they typed, and — when the
// request is part of an OAuth flow — hands back the one-time code that finishes
// it. A second factor, if the account has one, is asked for and required here.
//
// The password is compared against a stored one-way hash and is never logged,
// echoed or stored as typed.
func loginHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f loginForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		adoptQuery(c, &f)
		ctx := c.Context()

		// A post carrying no fresh credential but naming an outstanding challenge is
		// the SECOND half of a sign-in this endpoint already gated: the second-factor
		// answer. The principal comes from the challenge, never from the body.
		if f.Username == "" && f.Password == "" {
			if id := ReadChallenge(c, f.Challenge); id != "" {
				return finishMfa(c, db, id, f)
			}
			// SINGLE SIGN-ON. A code request carrying no credential but a LIVE session
			// THIS IdP issued is a user who is already signed in asking for a grant to
			// the next app. Re-typing the password would prove nothing new: the session
			// cookie is tamper-evident (HMAC over the platform signing key), carries its
			// own expiry, and its sid is checked against the Session row on every
			// resolve, so it is revocable — and it only ever exists downstream of the
			// full gate, second factor included, because loginGrant is what sets it.
			//
			// Without this every app bounced a signed-in person to a credential form:
			// the portal's own launcher tiles landed on a login wall, which reads as
			// "the link is dead" because the browser ends up back on the IdP.
			//
			// It grants NOTHING extra. The mint runs through loginGrant — the ONE
			// minting tail — so the reserved-org gate, the app-org tenant gate, the
			// exact redirect_uri match and the public-client PKCE requirement are the
			// same checks, in the same order, as a password post; only the proof of
			// identity differs. The row is re-read so an account forbidden or deleted
			// since sign-in is refused rather than riding its old session.
			//
			// type=device rides this too, and must: the approval page posts NO
			// credential (the human is already signed in — that is the whole point of
			// approving on a phone), so excluding it here dropped every approval
			// through to the credential check below and answered "organization,
			// username and password are required". The RFC 8628 flow could not
			// complete at all; `hanzo login` hung at "Waiting for approval…" forever.
			//
			// This does not weaken the "deliberate act" the exclusion was protecting.
			// The deliberate act is the human opening the verification URI and
			// transcribing the user_code their own device shows — approveDevice binds
			// the approver's proven identity onto exactly that pending code, and a code
			// nobody typed approves nothing. What the exclusion actually required was a
			// full password re-entry from someone already authenticated, which no
			// device flow asks for and which this page never sends.
			//
			// READ THIS BRANCH AS: a page that can both send the cookie and read the
			// answer takes the account over. It mints a spendable authorization code
			// from ambient authority alone, so the ONLY thing standing between it and
			// any page a signed-in user visits is who may read a credentialed
			// cross-origin answer here.
			//
			// internal/cors is where that is decided, and it decides it by EXACT
			// origin: this path is open to a browser, and credentialed to the exact
			// first-party console origins in IAM_SESSION_ORIGINS — never to a suffix,
			// never to the redirect_uri-derived allowlist a tenant can write into.
			//
			// That guarantee is this process's alone. A reverse proxy that appends
			// Access-Control-Allow-Origin ahead of us overrides it, and one on the
			// hanzo.ai and hanzo.id zones did: it reflected *.hanzo.ai — SAME-SITE
			// with the IdP host, so SameSite=Lax does not withhold the cookie — with
			// Access-Control-Allow-Credentials: true. Any page on a hanzo.ai
			// subdomain could reach this branch. Narrowing an edge rule is therefore
			// part of this branch's threat model, not an unrelated concern.
			if f.Type == "code" || f.Type == "device" {
				if owner, name, ok := sessions.Resolve(ctx, c.Fiber(), db); ok {
					user, err := store.GetUserByName(ctx, db, owner, name)
					if err != nil {
						return httpx.Err(c, err.Error())
					}
					if user == nil || user.IsForbidden || user.IsDeleted {
						return httpx.ErrCode(c, "please sign in first", CodeLoginRequired)
					}
					return loginGrant(c, db, user, f)
				}
				// No session, and this flow has no credential to fall back on: the
				// approval page posts none, by design. Falling through told the human
				// "organization, username and password are required" — naming three
				// fields that page does not have and will never show them — so the
				// only reading was that their credential was wrong, when what was
				// missing was a sign-in on this browser. Say the thing they can act on.
				//
				// The prose differs per flow (only one of them is a device) but the
				// REASON is one value: CodeLoginRequired is what the page routes on to
				// show a sign-in form and return here with the user_code intact. A
				// caller that had to branch on the sentence would break the first time
				// the sentence was reworded.
				msg := "please sign in first"
				if f.Type == "device" {
					msg = "please sign in first, then approve the device"
				}
				return httpx.ErrCode(c, msg, CodeLoginRequired)
			}
		}

		// One credential is required, not specifically a password: a code stands in
		// its place. Spelling this as "password == ''" refused every code sign-in
		// here, before the arm that knows how to read one.
		if f.Organization == "" || f.Username == "" || (f.Password == "" && f.Code == "") {
			return httpx.Err(c, "organization, username and password are required")
		}

		// The application is resolved before the identifier because it is part of
		// WHERE the identifier resolves: an application that founds an org per person
		// is the only thing that still knows where its accounts went.
		app, err := ResolveApp(ctx, db, f.ClientId, f.Application)
		if err != nil {
			return httpx.Err(c, "sign-in is unavailable")
		}

		user, err := resolveLoginUser(ctx, db, app, f.Organization, f.Username)
		if err != nil {
			// NEVER the resolver's own words. This is an UNAUTHENTICATED door and
			// nothing has been proven about the caller yet, so anything specific
			// here is an account-existence oracle: "matches more than one account"
			// tells a stranger that the address they typed is real, and which
			// addresses are worth attacking. An ambiguous identifier is answered
			// with the SAME opaque refusal a wrong password gets — the refusal this
			// endpoint already spent care making indistinguishable from "no such
			// user". The operator still learns everything from the server log; the
			// caller learns only that the credential did not work.
			if errors.Is(err, store.ErrEmailAmbiguous) || errors.Is(err, store.ErrPhoneAmbiguous) {
				return httpx.Err(c, "the username or password is incorrect")
			}
			return httpx.Err(c, "sign-in is unavailable")
		}

		// A code in place of a password: the SAME door, one arm further in. Sign-in
		// by email or SMS proves possession of an address the account already
		// holds, which is one factor exactly as a password is, so it joins here
		// rather than at a second endpoint — the MFA gate, the device approval and
		// the PKCE tail below are then true of it by construction instead of by a
		// second implementation that has to be kept in step.
		if f.Code != "" {
			ok, err := codeLogin(ctx, db, f, user)
			if err != nil {
				return httpx.Err(c, err.Error())
			}
			if !ok {
				return httpx.Err(c, "the code is incorrect or has expired")
			}
			// The code proved the channel it arrived on, so the gate is told WHICH
			// factor is already satisfied and offers a different one — an email code
			// is never answered by demanding a second email code.
			return afterFirstFactor(c, db, user, f, verificationChannel(f.Username))
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

		// The password proves none of the offerable second factors, so the gate is
		// told "" and may ask for any of them.
		return afterFirstFactor(c, db, user, f, "")
	}
}

// afterFirstFactor runs everything owed between "this is the user" and the grant.
// The gate holds the sign-in when a second factor is outstanding — before ANY
// token or device approval — and answers the request itself; false means nothing
// more is owed.
//
// proven names the factor the FIRST credential already satisfied, so the gate can
// exclude it (mfa_gate.allowList drops the matching factor): a password proves
// none and passes "", while an emailed or texted code proves that channel and must
// not be answered by demanding the same channel again. Both credential arms end
// here so the rules between proof and grant are stated once and cannot drift into
// being true of one arm and false of the other.
func afterFirstFactor(c *zip.Ctx, db orm.DB, user *schema.User, f loginForm, proven string) error {
	ctx := c.Context()
	org, err := store.GetOrganizationByName(ctx, db, user.Owner)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	gated, err := Gate(c, db, user, org, proven)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if gated {
		return nil
	}
	return loginGrant(c, db, user, f)
}

// verificationChannel names the factor a code delivered to identifier proves —
// the same two words the MFA factors use, so the value can be handed straight to
// the gate.
func verificationChannel(identifier string) string {
	if store.LooksLikePhone(identifier) {
		return factor.SMS
	}
	return factor.Email
}

// codeLogin verifies a one-time code as the whole first factor.
//
// It is deliberately strict about WHEN it may run, because it is a way into an
// account that never involves a password:
//
//   - the application must have code sign-in switched on (EnableCodeSignin), the
//     same per-app policy the login descriptor advertises;
//   - delivery must be configured, or this process could not have sent the code
//     it is being asked to trust;
//   - the code is spent by [otp.Consume] whatever the outcome — one
//     use on a hit, one counted guess on a miss.
//
// A code stands for the account it was MINTED for, which is why the resolved user
// goes into the consume rather than only the identifier off the request. Every
// refusal is the same opaque false, so nothing here tells a caller which addresses
// have accounts.
func codeLogin(ctx context.Context, db orm.DB, f loginForm, user *schema.User) (bool, error) {
	if !otp.DeliveryConfigured() {
		return false, nil
	}
	app, err := store.GetApplicationByClientId(ctx, db, f.ClientId)
	if err != nil {
		return false, err
	}
	if app == nil || !app.EnableCodeSignin {
		return false, nil
	}
	return otp.Consume(ctx, db, user, f.Username, f.Code, nowFunc())
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
	// blessed capability — so the reserved-org confinement MintFor enforces (which
	// binds a SuperAdmin to its own-org app) does NOT apply to it; it precedes it.
	if f.Type == "device" {
		return approveDevice(c, db, user, f.UserCode)
	}

	app, err := ResolveApp(ctx, db, f.ClientId, f.Application)
	if err != nil {
		return httpx.Err(c, err.Error())
	}

	// Everything between "this is the user" and "here is the grant" — reserved-org
	// confinement, the tenant rule, the exact redirect_uri match, S256-only PKCE
	// and the public-client challenge requirement — is MintFor's, not this
	// handler's. It was restated here once and drifted: the reserved-org gate
	// existed in this copy and nowhere else, so the wallet front door and (now)
	// silent SSO would each have had to remember it. One mint path, one set of
	// rules, no front door that can forget one.
	out, err := MintFor(ctx, db, app, user.Owner+"/"+user.Name, f.mint())
	if err != nil {
		return httpx.Err(c, err.Error())
	}

	// Establish the durable session the portal + the gateway admin-guard read via
	// get-account. It happens for EVERY interactive grant shape, because the thing
	// being recorded is that a human proved who they are to the IDENTITY PROVIDER —
	// and that is true whether they walked away with a bare portal sign-in or an
	// authorization code. The grant shape the RELYING PARTY asked for is a separate
	// question and has no business deciding whether the IdP remembers the human.
	//
	// Braiding those two together is what cost the fleet its single sign-on. This
	// ran under `if f.Type != "code"`, so the ONE path humans actually walk — every
	// app sends them through the code flow — minted a code and left no session. The
	// silent-SSO branch above was fully built, tested and correct, and simply had
	// nothing to read: hanzo.id asked for the password again on every app.
	//
	// sessions.Open is that rule, and it is where the wallet front door and the
	// return from another identity provider read it from too. Best-effort — a
	// session failure never blocks a valid login.
	_ = sessions.Open(ctx, c.Fiber(), db, user.Owner, user.Name, f.Application)

	// One return, one meaning: MintFor already yields the user id for a bare portal
	// sign-in and the authorization code for the code flow, so the SDK reads `data`
	// the same way either way. The old `if f.Type != "code"` early return restated
	// that distinction a second time and is gone — it is the same braiding of grant
	// shape into an unrelated decision that cost the fleet its single sign-on above.
	return httpx.Ok(c, out)
}

// mint is the authorize passthrough this form carries, in the shape the one mint
// path takes.
func (f loginForm) mint() Mint {
	return Mint{
		Type:                f.Type,
		RedirectUri:         f.RedirectUri,
		State:               f.State,
		Scope:               f.Scope,
		Nonce:               f.Nonce,
		CodeChallenge:       f.CodeChallenge,
		CodeChallengeMethod: f.CodeChallengeMethod,
		Resource:            f.Resource,
	}
}

// resolveLoginUser looks a user up by the login identifier: in the org the form
// names, then among the accounts the application itself registered.
//
// The second reach is what makes a per-person tenant reachable. A login screen
// names the APPLICATION's org — it is the only org the screen can know, since the
// person has not been identified yet — so an account that WORKS in an org of its
// own is not in the org being searched. Its own application is the one thing that
// still knows it, and [store.GetSignupByEmail] is that reach: this application's
// own accounts, by the address they registered with, ambiguity refused, reserved
// orgs unreachable.
//
// It is not a cross-org lookup by address. Resolving an address across every org
// couples the accounts that merely share one — their lockout counters above all —
// and that stays refused: nothing here reads a row another application created,
// or one that no application created.
//
// The org arm runs FIRST and is untouched, so every account that lives in the
// application's org resolves exactly as it always did, staff included.
func resolveLoginUser(ctx context.Context, db orm.DB, app *schema.Application, org, identifier string) (*schema.User, error) {
	user, err := resolveInOrg(ctx, db, org, identifier)
	if err != nil || user != nil {
		return user, err
	}
	if app == nil {
		return nil, nil
	}
	return store.GetSignupByEmail(ctx, db, app.Name, identifier)
}

// resolveInOrg resolves the login identifier within one org, resolving NAME FIRST
// and email second — legacy's own precedence
// (object.GetUserByFields tries the user NAME before the email/phone). This is
// load-bearing at cutover when two rows collide on an email: e.g. org hanzo holds
// both `hanzo/z` (name z, email z@hanzo.ai) and `hanzo/z@hanzo.ai` (name
// z@hanzo.ai, same email). The ROPC/login username "z@hanzo.ai" must resolve to
// the NAME match (hanzo/z@hanzo.ai) exactly as legacy did — an email-first lookup
// would silently authenticate the OTHER identity. The `@` gate stays only to skip
// a pointless email lookup for a plain username.
func resolveInOrg(ctx context.Context, db orm.DB, org, identifier string) (*schema.User, error) {
	if u, err := store.GetUserByName(ctx, db, org, identifier); err != nil || u != nil {
		return u, err
	}
	if strings.Contains(identifier, "@") {
		return store.GetUserByEmail(ctx, db, org, identifier)
	}
	// Phone LAST, and only for something shaped like a phone number. It runs after
	// name so a user literally named "12345" still wins their own row, and the
	// shape gate keeps an ordinary username from turning into a phone lookup.
	//
	// GetUserByPhone refuses to pick between two rows carrying one number
	// (ErrPhoneAmbiguous). That error is returned, not swallowed into "no such
	// user": the caller must not authenticate anyone against a number that
	// identifies two accounts.
	if store.LooksLikePhone(identifier) {
		return store.GetUserByPhone(ctx, db, org, identifier)
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

// adoptQuery takes the authorize request from the QUERY STRING when the body
// did not carry it.
//
// The login form is posted to the URL the authorize step handed the page, and
// that URL already carries the OAuth request. The BODY is the credential:
//
//	POST /v1/iam/login?clientId=…&redirectUri=…&scope=openid+profile+email&nonce=…&code_challenge=…
//	{"type":"code","username":…,"password":…,"application":…,"organization":…}
//
// Both spellings are read because the query has two authors: this server's own
// authorize endpoint writes RFC snake_case (authorizeForwardQuery), the
// @hanzo/iam SDK writes camelCase. The body binds camelCase only. Body wins
// when both are present; the query is a fallback, never an override — a value
// adopted here still runs every check the body path runs, so an unregistered
// redirect_uri is refused exactly as before.
//
// Reading only the body threw away a request the client HAD sent in full, and
// the damage surfaced two hops away at the relying party: no scope means no
// `openid`, so /token answered 200 with NO id_token (a KeyError in every strict
// OIDC client) and userinfo withheld `email`; no nonce failed the id_token
// claim check; no redirect_uri skipped the RFC 6749 §4.1.3 binding at
// redemption. One lookup site, so no parameter can be forgotten alone again.
func adoptQuery(c *zip.Ctx, f *loginForm) {
	adopt := func(dst *string, keys ...string) {
		if *dst == "" {
			for _, k := range keys {
				if v := c.Query(k); v != "" {
					*dst = v
					return
				}
			}
		}
	}
	adopt(&f.ClientId, "client_id", "clientId")
	adopt(&f.RedirectUri, "redirect_uri", "redirectUri")
	adopt(&f.Scope, "scope")
	adopt(&f.State, "state")
	adopt(&f.Nonce, "nonce")
	adopt(&f.Resource, "resource")
	adopt(&f.CodeChallenge, "code_challenge", "codeChallenge")
	adopt(&f.CodeChallengeMethod, "code_challenge_method", "codeChallengeMethod")
}
