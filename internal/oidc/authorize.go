// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"strings"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The authorization endpoint: GET/POST /v1/iam/oauth/authorize — the entry point
// of the authorization-code flow. iam validates the request BEFORE it trusts
// any redirect: an unknown client_id or an unregistered redirect_uri is answered
// in place and NEVER redirected to (RFC 6749 §4.1.2.1), closing the open-redirect
// and code-injection surface that a bare pass-through would leave open.
//
// A validated request then has THREE possible answers, and which one it gets is
// the whole of single sign-on:
//
//	the session answers it   — a code, straight back to the registered
//	                           redirect_uri, no screen (prompt.go)
//	nobody is signed in, and — error=login_required, back to the registered
//	the client said none       redirect_uri, still no screen
//	otherwise                — the hosted login UI, which collects credentials
//	                           and posts to /v1/iam/login
//
// Before this, only the third existed: every request rendered a login page,
// prompt=none included. A relying party therefore had no way to ask "is anyone
// signed in?" without putting a login screen in front of a user who already
// was — which is not a missing feature, it is the absence of SSO.

// hostedLoginPath is the default hosted-login route the authorize endpoint hands
// a validated request to when the application pins no SigninUrl of its own.
const hostedLoginPath = "/login/oauth/authorize"

// authorizeRequest is the parsed authorize query.
type authorizeRequest struct {
	responseType        string
	clientID            string
	redirectURI         string
	scope               string
	state               string
	nonce               string
	codeChallenge       string
	codeChallengeMethod string
	resource            string
	responseMode        string
	provider            string
	prompt              string
	loginHint           string
	signup              bool
}

// authorizeHandler starts a sign-in — the address you send a browser to, and the
// beginning of every OAuth and OpenID Connect flow.
//
// If the person is ALREADY signed in here, it does not ask them again: it
// returns them to the application with a one-time code and they never see this
// page. When SEVERAL people are signed in on the browser and the request names
// none of them, it asks which one, with the account chooser. Otherwise it shows
// the right way to sign in for the application they are signing in to, or hands
// off to another identity provider if that is what they pick.
//
// A client can say what it wants with `prompt`: `none` means answer without any
// screen at all — with the code if a session exists, with an error if not
// (`account_selection_required` when several accounts are signed in and none is
// named), but never with a page; `login` means ask for the password again even if
// a session exists; `select_account` means let the person choose among the
// accounts signed in on this browser, or sign in to another. `login_hint` names
// which of those accounts the request is for.
//
// It returns only to an address the application has registered. That check
// happens before anything else, so a request naming an unregistered address is
// refused where the person can see it rather than being bounced onwards.
func authorizeHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		// A sign-in must run AT its sign-in origin, because everything a flow
		// sets along the way — the __Host-hanzo_fed browser binding, the session — is a
		// host-only cookie, while the IdP callback is pinned to that origin.
		// Answering on an alias host (iam.hanzo.ai, www.zoolabs.id, any host the
		// map folds) strands those cookies and social sign-in fails closed at the
		// callback. So an alias is answered with the same request relocated to
		// the origin, before anything is minted or set; 307 keeps the method. A
		// host that is its own sign-in origin (hanzo.ai) is answered in place.
		// See signinRelocation for the fail-closed guards.
		if loc, ok := signinRelocation(c); ok {
			return c.Redirect(307, loc)
		}
		ctx := c.Context()
		q := authorizeParams(c)
		// A parameter past its bound is refused in place, before anything reads it,
		// since it is not a request a client makes and echoing it back is no answer.
		if k := oversize(c); k != "" {
			return authorizeUserError(c, "invalid_request: "+k+" is too long")
		}

		// 1. Resolve the client. Without a known client there is no trusted
		// redirect target, so the error is shown in place — never redirected.
		if q.clientID == "" {
			return authorizeUserError(c, "client_id is required")
		}
		app, err := store.GetApplicationByClientId(ctx, db, q.clientID)
		if err != nil {
			return authorizeUserError(c, "internal error")
		}
		if app == nil {
			return authorizeUserError(c, "unknown client_id")
		}
		// 2. redirect_uri must EXACTLY match a registered URI before it can ever
		// be used as a redirect target. A mismatch is answered in place.
		if q.redirectURI == "" || !app.IsRedirectUriValid(q.redirectURI) {
			return authorizeUserError(c, "invalid redirect_uri")
		}

		// The redirect target is now trusted: protocol errors redirect back to it
		// with error+state (RFC 6749 §4.1.2.1).
		if q.responseType != "code" {
			return authorizeErrorRedirect(c, q, "unsupported_response_type", "only response_type=code is supported")
		}
		method := normalizeChallengeMethod(q.codeChallenge, q.codeChallengeMethod)
		if q.codeChallenge != "" && method != "S256" {
			return authorizeErrorRedirect(c, q, "invalid_request", "only S256 PKCE is supported")
		}
		if app.ClientSecret == "" && q.codeChallenge == "" {
			return authorizeErrorRedirect(c, q, "invalid_request", "PKCE is required for public clients")
		}

		p := parsePrompt(q.prompt)
		// A client that registered itself was vetted by nobody, and an address it
		// chose is where the code goes. A session answering for it silently would let
		// a link anyone can send hand that code to whoever registered the address, so
		// it is never answered from a session: the person types their credential for
		// it, and prompt=none has nothing to ask (RFC 6749 §10.6).
		if app.Dynamic() {
			if p.none {
				return authorizeErrorRedirect(c, q, errInteractionRequired, "this client needs the person to sign in")
			}
			p.login = true
		}
		if p.combined {
			return authorizeErrorRedirect(c, q, "invalid_request", "prompt=none must not be combined with other values")
		}

		// A login_hint that names an impersonation is answered here, by the hint
		// and the operator's session together, and never by a screen or by
		// whoever else is signed in on this browser (impersonate.go).
		if id, ok := impersonation(q.loginHint); ok {
			return impersonate(c, db, app, q, id)
		}

		// A request that names a social `provider` is federated to that external
		// IdP (Google/GitHub, …) instead of the hosted credential login. The
		// client + redirect_uri + PKCE policy above are already enforced, so the
		// federation broker starts from a validated request and a trusted target.
		//
		// It is decided BEFORE the session is consulted, because naming a provider
		// is an explicit instruction about WHICH identity to authenticate — the
		// person pressed "continue with Google" — and an ambient session is not an
		// answer to that. Which also means it can never be silent: the external IdP
		// is the one who decides, and reaching it is an interaction.
		if q.provider != "" {
			if p.none {
				return authorizeErrorRedirect(c, q, errInteractionRequired, "an external identity provider cannot be used without interaction")
			}
			return beginFederation(c, db, app, q, method)
		}

		// SINGLE SIGN-ON. A live session answers the request outright — this is
		// the branch that means "log in once at the issuer and every other app
		// already knows you". It is skipped when the client asked for a screen
		// (prompt=login / select_account), and its refusals are the OIDC error
		// codes prompt=none is owed.
		//
		// It is also skipped on a sign-in origin that is not the issuer's own host
		// (hanzo.ai signing in for hanzo.id). That origin holds a session of its
		// own, and the hosted page there asks "continue as" instead of answering
		// from it; prompt=none, which allows no page, is refused — except for the
		// platform's own applications that share one sign-out (silentAtSigninOrigin),
		// whose sign-out ends this origin's session too, so a silent answer here
		// can never revive a session the person ended.
		if !p.interactive() && !atIssuer(c) && !(p.none && silentAtSigninOrigin(app)) {
			if p.none {
				return authorizeErrorRedirect(c, q, errLoginRequired, "no session at this sign-in origin may answer without the person")
			}
		} else if !p.interactive() {
			code, refusal := silentGrant(c, db, app, q)
			if refusal == "" {
				return authorizeCodeRedirect(c, q, code)
			}
			if p.none {
				return authorizeErrorRedirect(c, q, refusal, "no interaction was permitted and the request could not be answered from an existing session")
			}
			// Several people are signed in here and the request named none of them:
			// the page asks which one, exactly as if the client had said so.
			if refusal == errAccountSelectionRequired {
				p.selectAccount = true
			}
		}

		// prompt=none has now been answered one way or the other; reaching here
		// with it set means the client asked for no UI and for a UI at once, which
		// `combined` already refused. Everything else gets the hosted login with a
		// clean, re-encoded request. The login page posts credentials to
		// /v1/iam/login, which mints the code.
		q.prompt = p.forwarded()
		// What the request demanded is recorded here, where it was validated, so a
		// page that resumes from a session without forwarding it is still held to it
		// (demand.go). A demand that cannot be recorded is not handed on unenforced.
		if d := (demand{Login: p.login || p.unrecognized, Choose: p.selectAccount, MaxAge: param(c, "max_age"), Since: nowFunc().Unix()}); d.needed() {
			if err := rememberDemand(ctx, db, demandKey(q.clientID, q.redirectURI, q.state, q.codeChallenge), d); err != nil {
				return authorizeUserError(c, "internal error")
			}
		}
		iss, err := tokenIssuer(c)
		if err != nil {
			return authorizeUserError(c, "internal error")
		}
		return c.Redirect(302, hostedLoginTarget(app, iss)+"?"+authorizeForwardQuery(q, method))
	}
}

// authorizeParams reads the authorize parameters from the query (GET) or form
// body (POST).
func authorizeParams(c *zip.Ctx) authorizeRequest {
	return authorizeRequest{
		responseType:        param(c, "response_type"),
		clientID:            param(c, "client_id"),
		redirectURI:         param(c, "redirect_uri"),
		scope:               param(c, "scope"),
		state:               param(c, "state"),
		nonce:               param(c, "nonce"),
		codeChallenge:       param(c, "code_challenge"),
		codeChallengeMethod: param(c, "code_challenge_method"),
		resource:            param(c, "resource"),
		responseMode:        param(c, "response_mode"),
		provider:            param(c, "provider"),
		prompt:              param(c, "prompt"),
		loginHint:           param(c, "login_hint"),
		signup:              param(c, "signup") == "true",
	}
}

// paramLimits bounds each authorize parameter, in bytes. A federation's begin
// leg stores the request in its transaction and the hosted login carries it in
// a URL, so each has a bound well past any client's use: a state of 1 KiB, a
// scope of dozens of names. Past one the request is refused, never cut, since a
// cut state or nonce no longer matches what the client holds.
var paramLimits = map[string]int{
	"response_type": 64, "client_id": 256, "redirect_uri": 2048, "scope": 2048,
	"state": 1024, "nonce": 512, "code_challenge": 128, "code_challenge_method": 64,
	"resource": 2048, "response_mode": 64, "provider": 256, "prompt": 256,
	"login_hint": 512, "signup": 64, "id_token_hint": 2048, "idp_nonce": 512,
}

// oversize names an authorize parameter longer than its bound, or "".
func oversize(c *zip.Ctx) string {
	for k, limit := range paramLimits {
		if len(param(c, k)) > limit {
			return k
		}
	}
	return ""
}

// hostedLoginTarget is the login URL a validated request is delegated to — the
// application's own SigninUrl when it names an origin the operator configured as a
// sign-in origin of this issuer, else the default hosted-login route. The value is
// an organization's to write for its own applications, so it is followed only where
// IAM itself signs people in: stored raw it made the issuer an open redirector, a 302
// to wherever a tenant's application said.
func hostedLoginTarget(app *schema.Application, iss string) string {
	if app.SigninUrl != "" {
		if u, err := url.Parse(strings.TrimSpace(app.SigninUrl)); err == nil && u.Scheme == "https" && u.User == nil {
			if origin, err := signinOrigin("https://" + u.Host); err == nil && configuredSignin(origin, normalizeIssuer(iss)) {
				return app.SigninUrl
			}
		}
	}
	// Relative on purpose. signinRelocation has already moved a request that
	// arrived on an alias to its sign-in origin, before anything is minted or
	// set, so by here the host IS that origin and this resolves there: on hanzo.id
	// the id SPA, on hanzo.ai the site's own page, which the edge serves at this path.
	return hostedLoginPath
}

// authorizeForwardQuery re-encodes the validated request as a clean query string
// for the hosted login — reconstructed from known parameters so nothing
// unexpected is passed through.
func authorizeForwardQuery(q authorizeRequest, method string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", q.clientID)
	v.Set("redirect_uri", q.redirectURI)
	setIfPresent(v, "scope", q.scope)
	setIfPresent(v, "state", q.state)
	setIfPresent(v, "nonce", q.nonce)
	if q.codeChallenge != "" {
		v.Set("code_challenge", q.codeChallenge)
		v.Set("code_challenge_method", method)
	}
	setIfPresent(v, "resource", q.resource)
	setIfPresent(v, "response_mode", q.responseMode)
	// The surviving prompt is carried to the page, because the page is what has
	// to act on it: `select_account` is a request to show an account CHOOSER
	// rather than a bare credential form, and only the UI can do that. `none`
	// never reaches here — it is answered above, without a page, which is what it
	// asked for.
	setIfPresent(v, "prompt", q.prompt)
	// The person the client asked for, so the page can offer them by name: the
	// credential form starts with this identifier in it.
	setIfPresent(v, "login_hint", q.loginHint)
	// Which of the two screens to open. Like `prompt`, the page is what acts on
	// it: an application sending someone to create an account wants the
	// registration form, not the credential form with a link to it. Re-encoded
	// from the parsed flag rather than echoed, so only the literal "true" ever
	// reaches the page. An application that does not ask gets sign-in, and a
	// deployment with registration closed gets sign-in either way.
	if q.signup {
		v.Set("signup", "true")
	}
	return v.Encode()
}

// authorizeCodeRedirect returns a successful silent authorization to the client:
// the code and the state, on the registered redirect_uri.
//
// It is the SAME return path an interactive sign-in takes — the browser lands on
// the client's callback with a code it exchanges at /token — so nothing
// downstream can tell the two apart, and nothing downstream has to.
func authorizeCodeRedirect(c *zip.Ctx, q authorizeRequest, code string) error {
	v := url.Values{}
	v.Set("code", code)
	return authorizeRedirect(c, q, v)
}

// silentAtSigninOrigin reports whether app may be answered silently
// (prompt=none) on a sign-in origin that is not the issuer's own host —
// hanzo.ai signing in for hanzo.id (decision D6).
//
// A sign-in origin holds a session of its own, and the reason authorize there
// asks before answering is that a sign-out somewhere else might have left that
// session alive, so a silent answer would sign the person back in after they
// signed out. That stops being true for exactly the applications whose sign-out
// is shared (IAM_SIGNOUT_APPS): leaving any of them retires the grant to all of
// them (revokeShared), and a sign-out the browser navigates through ends the
// session on every sign-in origin of the issuer (nextSignout). For those, and
// only those, the session here is one the person has not ended.
//
// The owner pin is the same one mintAllowed uses: the app must be owned by a
// reserved signing owner (admin/built-in, as every application the platform
// provisions is), so a tenant's app registered with a clientId that spells a
// listed one is still refused. Unset list allows nothing — fail closed.
//
// A request with no prompt keeps the hosted "continue as" page: this answers
// only the client that asked for no page at all.
func silentAtSigninOrigin(app *schema.Application) bool {
	return policy.IsSigningOwner(app.Owner) && appInList(envSignoutApps, app.ClientId)
}

// authorizeErrorRedirect bounces a protocol error back to the (already
// validated) redirect_uri with error+state, in the requested response mode.
func authorizeErrorRedirect(c *zip.Ctx, q authorizeRequest, code, desc string) error {
	v := url.Values{}
	v.Set("error", code)
	setIfPresent(v, "error_description", desc)
	return authorizeRedirect(c, q, v)
}

// authorizeRedirect returns the browser to the redirect_uri carrying v, in the
// requested response mode, with `state` echoed.
//
// Success and failure share it deliberately. They are the same act — hand these
// parameters to the client's registered address — and splitting them is how a
// server ends up echoing state on one and forgetting it on the other, or
// honouring response_mode=fragment for an error and not for a code.
//
// It runs only AFTER redirect_uri has been matched against the application's
// registered list, which is what makes appending to it safe.
func authorizeRedirect(c *zip.Ctx, q authorizeRequest, v url.Values) error {
	setIfPresent(v, "state", q.state)

	sep := "?"
	switch {
	case q.responseMode == "fragment":
		sep = "#"
	case strings.Contains(q.redirectURI, "?"):
		sep = "&"
	}
	return c.Redirect(302, q.redirectURI+sep+v.Encode())
}

// authorizeUserError answers a request whose client_id/redirect_uri could not be
// validated: the resource owner is informed in place and the request is NOT
// redirected anywhere (RFC 6749 §4.1.2.1). The message is server-controlled.
func authorizeUserError(c *zip.Ctx, msg string) error {
	c.SetHeader("Content-Type", "text/plain; charset=utf-8")
	return c.String(400, "authorization error: "+msg)
}

// normalizeChallengeMethod maps an omitted PKCE method to S256 when a challenge
// is present (S256 is the only method iam supports); an explicit non-S256
// method is returned unchanged so the caller rejects the downgrade.
func normalizeChallengeMethod(challenge, method string) string {
	if challenge == "" {
		return method
	}
	if method == "" || strings.EqualFold(method, "null") {
		return "S256"
	}
	return method
}

// setIfPresent sets a query value only when non-empty.
func setIfPresent(v url.Values, key, value string) {
	if value != "" {
		v.Set(key, value)
	}
}
