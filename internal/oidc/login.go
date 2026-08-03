// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
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
	Type         string `json:"type"` // "code" (PKCE authorize) | "device" (RFC 8628 approval) | "login" (bare session)

	// Identity is an `owner/name` SELECTOR naming which of the identities this
	// browser already holds the request should act as — the account chooser's
	// answer, and `hanzo auth use` in a browser.
	//
	// It is not a credential and it cannot become one. It is looked up in the
	// HMAC-signed session cookie, so it can only ever name a principal that has
	// ALREADY completed a full sign-in on this browser; a selector matching
	// nothing selects nothing, and the request is answered as though no session
	// existed. Sending it alongside a password is refused rather than reconciled
	// — two different answers to "who is signing in" is not a preference.
	Identity string `json:"identity"`

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

		// A credential and an identity selector are two different answers to "who
		// is signing in", and there is no sensible reconciliation of the two. It is
		// refused rather than ranked, so no future reader has to remember which one
		// this endpoint decided wins.
		if f.Identity != "" && (f.Username != "" || f.Password != "") {
			return httpx.Err(c, "send either a credential or an identity to select, never both")
		}

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
			// THE CHOOSER'S ANSWER, and the account page's switcher: the SELECTED
			// identity is who this request acts as, and the grant is minted for the
			// identity Use HANDS BACK — never re-read from the cookie afterwards.
			//
			// That distinction is not stylistic. A cookie mutation is written to the
			// RESPONSE; the REQUEST still carries the session the browser arrived
			// with. Re-resolving here therefore answers with the PREVIOUSLY active
			// identity, and the chooser hands the app an authorization code for the
			// person the human just switched AWAY from — clicking "z@" signs you into
			// the app as a@, silently, with the account page showing z@ afterwards
			// because the NEXT request finally sees the new cookie. It read correctly
			// and it was wrong; only driving the real endpoint showed it. The value
			// Use returns is the one fact that is true within this request, so it is
			// the only thing allowed to answer.
			//
			// It is a selection among identities the browser ALREADY HOLDS, never an
			// authentication — sessions.Use looks the selector up inside the signed
			// cookie and mints nothing, so this endpoint cannot be talked into acting
			// as a principal that never signed in here. It also leaves auth_time
			// alone: switching back to an identity that authenticated a month ago
			// must not present it to a relying party as a fresh sign-in.
			if f.Identity != "" {
				owner, name, wellFormed := sessions.ParseIdentity(f.Identity)
				if !wellFormed {
					return httpx.Err(c, "identity must be owner/name")
				}
				selected, ok := sessions.Use(ctx, c.Fiber(), db, owner, name)
				if !ok {
					return httpx.ErrCode(c, "that account is not signed in on this browser", CodeLoginRequired)
				}
				return grantAs(c, db, selected.Owner, selected.Name, f)
			}

			if f.Type == "code" || f.Type == "device" {
				if owner, name, ok := sessions.Resolve(ctx, c.Fiber(), db); ok {
					return grantAs(c, db, owner, name, f)
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

		return signedIn(c, db, user, f)
	}
}

// grantAs completes a credential-LESS grant for an identity the browser already
// proved — the silent hop and the chooser's selection alike.
//
// The row is RE-READ rather than taken from the session, so an account forbidden
// or deleted since sign-in is refused instead of riding its old session. Both
// callers reach the same one, so neither can forget the check.
func grantAs(c *zip.Ctx, db orm.DB, owner, name string, f loginForm) error {
	ctx := c.Context()
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if user == nil || user.IsForbidden || user.IsDeleted {
		return httpx.ErrCode(c, "please sign in first", CodeLoginRequired)
	}
	return loginGrant(c, db, user, f)
}

// signedIn is what a CREDENTIAL just being checked means: the browser now holds
// this identity, and then the grant is minted.
//
// It is separated from loginGrant because the two facts had been braided, and
// the braid was a bug in both directions.
//
// One direction: the session write ran under `if f.Type != "code"`, so the ONE
// path humans actually walk — every app sends them through the code flow — minted
// a code and left no session behind. The silent-SSO branch was fully built and
// had nothing to read, so hanzo.id asked for the password again at every app. WHO
// the identity provider remembers is not a function of WHICH grant shape the
// relying party asked for; the two questions had no business sharing a branch.
//
// The other direction, and the one this lane depends on: the SSO and chooser
// paths reach loginGrant WITHOUT a credential, and they must not run this. Adding
// the identity again there would mint a second sid and stamp a fresh auth_time on
// a sign-in that happened days ago — a switch laundering a stale credential past
// a relying party's max_age. Only the two paths that actually verified something
// (the password post and the second-factor finish) call signedIn.
//
// Adding NEVER drops what the browser already holds (sessions.Add), so signing in
// as a@ while z@ is present yields two live identities rather than a replacement.
// The cookie is best-effort — a session failure never blocks a valid login.
func signedIn(c *zip.Ctx, db orm.DB, user *schema.User, f loginForm) error {
	// A device approval establishes no browser session of its own: the approver is
	// already signed in on this browser, and the grant it completes belongs to the
	// device at the other end of the flow.
	if f.Type != "device" {
		_ = sessions.Add(c.Context(), c.Fiber(), db, user.Owner, user.Name, f.Application)
	}
	return loginGrant(c, db, user, f)
}

// loginGrant completes a sign-in that has passed the gate: a device approval, a
// bare portal session, or a PKCE-bound authorization code. It is the ONE minting
// tail every interactive path reaches — the credential post, the second-factor
// finish, the silent hop and the chooser's selection alike — so the checks
// between "this is the user" and "here is the grant" are stated once and cannot
// be true of one path and false of another.
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

	// The SDK reads data as the user id (bare sign-in) or the authorization code
	// to exchange at /token.
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

// resolveLoginUser looks a user up by the login identifier, scoped to the org,
// resolving NAME FIRST and email second — legacy's own precedence
// (object.GetUserByFields tries the user NAME before the email/phone). This is
// load-bearing at cutover when two rows collide on an email: e.g. org hanzo holds
// both `hanzo/z` (name z, email z@hanzo.ai) and `hanzo/z@hanzo.ai` (name
// z@hanzo.ai, same email). The ROPC/login username "z@hanzo.ai" must resolve to
// the NAME match (hanzo/z@hanzo.ai) exactly as legacy did — an email-first lookup
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
