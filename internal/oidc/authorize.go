// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The authorization endpoint: GET/POST /v1/iam/oauth/authorize — the front door
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
}

// authorizeHandler starts a sign-in — the address you send a browser to, and the
// beginning of every OAuth and OpenID Connect flow.
//
// If the person is ALREADY signed in here, it does not ask them again: it
// returns them to the application with a one-time code and they never see this
// page. Otherwise it shows the right way to sign in for the application they are
// signing in to, or hands off to another identity provider if that is what they
// pick.
//
// A client can say what it wants with `prompt`: `none` means answer without any
// screen at all — with the code if a session exists, with an error if not, but
// never with a page; `login` means ask for the password again even if a session
// exists; `select_account` means let the person choose which identity to use.
//
// It returns only to an address the application has registered. That check
// happens before anything else, so a request naming an unregistered address is
// refused where the person can see it rather than being bounced onwards.
func authorizeHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		q := authorizeParams(c)

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
		if p.combined {
			return authorizeErrorRedirect(c, q, "invalid_request", "prompt=none must not be combined with other values")
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
		// already knows you". It is skipped only when the client asked for a
		// screen (prompt=login / select_account), and its refusals are the OIDC
		// error codes prompt=none is owed.
		if !p.interactive() {
			code, refusal := silentGrant(c, db, app, q)
			if refusal == "" {
				return authorizeCodeRedirect(c, q, code)
			}
			if p.none {
				return authorizeErrorRedirect(c, q, refusal, "no interaction was permitted and the request could not be answered from an existing session")
			}
		}

		// prompt=none has now been answered one way or the other; reaching here
		// with it set means the client asked for no UI and for a UI at once, which
		// `combined` already refused. Everything else gets the hosted login with a
		// clean, re-encoded request. The login page posts credentials to
		// /v1/iam/login, which mints the code.
		q.prompt = p.forwarded()
		return c.Redirect(302, hostedLoginTarget(app)+"?"+authorizeForwardQuery(q, method))
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
	}
}

// hostedLoginTarget is the login URL a validated request is delegated to — the
// application's own SigninUrl when set, else the default hosted-login route.
func hostedLoginTarget(app *schema.Application) string {
	if app.SigninUrl != "" {
		return app.SigninUrl
	}
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
