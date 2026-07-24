// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"net/url"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/internal/store"
)

// The authorization endpoint: GET/POST /v1/iam/oauth/authorize — the front door
// of the authorization-code flow. iam2 validates the request BEFORE it trusts
// any redirect: an unknown client_id or an unregistered redirect_uri is answered
// in place and NEVER redirected to (RFC 6749 §4.1.2.1), closing the open-redirect
// and code-injection surface that a bare pass-through would leave open. A
// well-formed request is delegated to the hosted login UI (matching v1), which
// collects credentials and posts to /v1/iam/login; that endpoint mints the
// PKCE-bound code and the browser lands back on the registered redirect_uri.

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
}

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

		// A request that names a social `provider` is federated to that external
		// IdP (Google/GitHub, …) instead of the hosted credential login. The
		// client + redirect_uri + PKCE policy above are already enforced, so the
		// federation broker starts from a validated request and a trusted target.
		if q.provider != "" {
			return beginFederation(c, db, app, q, method)
		}

		// SSO fast path — the clean-room equivalent of the fork's fastAutoSignin: when
		// the application opted into silent SSO AND the resource owner is ALREADY
		// authenticated (a valid hanzo.id session), the authorization endpoint mints the
		// code ITSELF and 302s straight back to the registered redirect_uri, rather than
		// bouncing to the hosted login. It mints through the SAME MintFor the credential
		// login uses — the one-and-only-one interactive mint routine — so the code
		// persists the EXACT fields a login-minted code does (owner-pinned user,
		// CodeChallenge, CodeChallengeMethod, redirect_uri, nonce). The PKCE challenge
		// validated above is written onto the row by the SERVER here, never round-tripped
		// through the login page where it could be dropped: dropping it left an
		// authorize-minted code non-PKCE (tok.CodeChallenge == "") so a public browser
		// redeem fell into the confidential branch and 401'd invalid_client — the defect
		// that forced three cutover rollbacks. userID is the SESSION identity, never a
		// request value, so a code can be minted for no one but the signed-in user.
		// F1b (defense in depth): the silent path mints ONLY for a SAME-TENANT session —
		// the session subject's org must equal the app's served Organization. A cross-org
		// session (a shared or org-choice app, or an app an admin registered under ANOTHER
		// tenant) falls through to the interactive hosted login instead of minting a code
		// from the cookie. This bounds the SSO fast path to one tenant, so even if the field
		// gate on EnableAutoSignin/IsShared were ever missed, a tenant admin's app can never
		// silently mint a code for a victim signed into a different tenant — the cross-tenant
		// amplification of the login-CSRF is dead here regardless of the app's flags. It is
		// stricter than MintFor's tenant gate on purpose (which admits any org for a shared /
		// org-choice app); same-tenant SSO — the console/commerce case — is unchanged.
		if app.EnableAutoSignin {
			if owner, name, ok := sessions.Resolve(ctx, c.Fiber(), db); ok && owner == app.Organization {
				if code, err := MintFor(ctx, db, app, owner+"/"+name, Mint{
					Type:                "code",
					RedirectUri:         q.redirectURI,
					State:               q.state,
					Scope:               q.scope,
					Nonce:               q.nonce,
					CodeChallenge:       q.codeChallenge,
					CodeChallengeMethod: method,
					Resource:            q.resource,
				}); err == nil {
					v := url.Values{}
					v.Set("code", code)
					setIfPresent(v, "state", q.state)
					return c.Redirect(302, joinQuery(q.redirectURI, v))
				}
				// A MintFor error here is residual: the same-tenant guard above already
				// excluded the tenant/reserved-org refusals (org == app.Organization inside
				// this block), and client, redirect_uri and PKCE were validated above and
				// re-asserted identically inside MintFor, so what remains is a persistence /
				// internal failure. Fall through to the hosted login rather than surfacing it;
				// a code is never minted on error, and the cross-tenant case never reaches
				// MintFor at all — it fell through at the same-tenant guard.
			}
		}

		// Delegate to the hosted login with a clean, re-encoded request. The login
		// page posts credentials to /v1/iam/login, which mints the code.
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
	return v.Encode()
}

// authorizeErrorRedirect bounces a protocol error back to the (already
// validated) redirect_uri with error+state, in the requested response mode.
func authorizeErrorRedirect(c *zip.Ctx, q authorizeRequest, code, desc string) error {
	v := url.Values{}
	v.Set("error", code)
	setIfPresent(v, "error_description", desc)
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
// is present (S256 is the only method iam2 supports); an explicit non-S256
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
