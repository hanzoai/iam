// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"errors"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// SINGLE SIGN-ON, from the authorize endpoint.
//
// One person signs in once at the issuer, and every other application they open
// afterwards reaches them already signed in — no second password, no second
// screen, not even a flicker. This file is the decision that makes that true,
// and the decision that refuses it.
//
// # Why it lives HERE and not on the login endpoint
//
// There was already a single-sign-on branch: POST /v1/iam/login answers a
// credential-less code request from the session cookie. But that is a
// CROSS-ORIGIN CREDENTIALED FETCH — the app's own page reads the answer — so it
// works only for an origin an operator has listed in IAM_SESSION_ORIGINS, and
// every origin on that list can mint a code for any signed-in visitor (see
// internal/cors). It cannot be the general answer: adding an app would mean
// handing another origin that power.
//
// The authorize endpoint needs none of it. The browser NAVIGATES to the issuer
// and is redirected back, so the answer is never read cross-origin, no CORS
// grant is involved, and the app can live on any host it has registered a
// redirect_uri for. SSO stops being an operator-listed privilege and becomes a
// property of the protocol.
//
// # Top-level navigation only
//
// The classic silent-renew technique is a hidden iframe. This server does not
// support it and should not:
//
//   - The session cookie is SameSite=Lax, so a browser does not present it on a
//     framed cross-site request at all. An iframe would see "not signed in" and
//     the flow would fail confusingly rather than work.
//   - The edge answers X-Frame-Options: DENY, so the page cannot be framed.
//   - Making it work would mean SameSite=None, which presents the session on
//     every cross-site subresource request on the internet. That is the trade
//     this design exists to refuse.
//
// So there is ONE way to be silently signed in: a top-level redirect. That is
// stated to the browser too — silentGrant declines when Sec-Fetch-Dest says the
// request is anything other than a document navigation, so even if the frame
// headers were dropped at the edge tomorrow, a framed request still cannot
// harvest a code.

// The prompt values this server implements. Discovery advertises exactly this
// list and nothing else, so a client that reads it can never ask for a mode that
// silently does something different.
//
// `consent` is deliberately absent: there is no OAuth consent screen to show, so
// advertising it would promise an interaction that does not exist.
const (
	promptNone          = "none"
	promptLogin         = "login"
	promptSelectAccount = "select_account"
)

// promptValues is the advertised set — the ONE list, read by discovery and by
// the parser, so the two can never disagree.
var promptValues = []string{promptNone, promptLogin, promptSelectAccount}

// prompt is a parsed `prompt` parameter: a space-delimited, case-sensitive set
// (OIDC Core §3.1.2.1).
type prompt struct {
	none          bool
	login         bool
	selectAccount bool

	// combined records `none` alongside any other value, which the spec makes an
	// error rather than a preference: the two instructions contradict — one says
	// show nothing, the other says show something.
	combined bool

	// unrecognized records a value outside the advertised set. It forces
	// INTERACTION, never silence: a directive this server does not understand
	// might be the one asking for a stronger check, so the fail-safe reading is
	// to ask the human, not to hand out a grant.
	unrecognized bool
}

// parsePrompt reads the `prompt` parameter.
func parsePrompt(raw string) prompt {
	var p prompt
	values := strings.Fields(raw)
	for _, v := range values {
		switch v {
		case promptNone:
			p.none = true
		case promptLogin:
			p.login = true
		case promptSelectAccount:
			p.selectAccount = true
		default:
			p.unrecognized = true
		}
	}
	p.combined = p.none && len(values) > 1
	return p
}

// forwarded is what the hosted login page is told, RE-SERIALIZED from the
// recognized values rather than passed through.
//
// The authorize endpoint hands the page a request rebuilt from known parameters
// precisely so nothing unexpected travels with it, and `prompt` is no exception:
// its raw value is client-controlled text that would otherwise land in the URL
// of a page this server sends people to. Only words this file defines can come
// out of here, so the page renders a directive or it renders nothing.
func (p prompt) forwarded() string {
	var out []string
	if p.login {
		out = append(out, promptLogin)
	}
	if p.selectAccount {
		out = append(out, promptSelectAccount)
	}
	return strings.Join(out, " ")
}

// interactive reports whether the request has ASKED for a screen, in which case
// no session may answer it. prompt=login is a relying party demanding a fresh
// credential — the one case where an existing session is exactly what must not
// be spent — and select_account asks the human which identity to use, which is a
// question only they can answer.
func (p prompt) interactive() bool { return p.login || p.selectAccount || p.unrecognized }

// OIDC Core §3.1.2.6 error codes. These are returned TO THE REDIRECT URI, never
// rendered: a client that asked for no UI gets a machine-readable answer it can
// act on, which is the entire point of asking.
const (
	errLoginRequired       = "login_required"
	errInteractionRequired = "interaction_required"
	errAccessDenied        = "access_denied"
)

// silentGrant answers "may this request be completed from the session alone?"
// and, when it may, returns the authorization code.
//
// The empty string as the second return means yes. Anything else is the OIDC
// error code a prompt=none request is answered with — and, for a request that
// did NOT say prompt=none, the reason it falls through to the login page
// instead.
//
// Every refusal is a refusal to grant. There is no path through this function
// that grants more than the interactive login would: the mint runs through
// MintFor, the ONE mint path, so the reserved-org confinement, the tenant rule,
// the exact redirect_uri match and the PKCE requirement are the same checks in
// the same order as a typed password. Only the proof of identity differs, and
// that proof — the session cookie — is HMAC-signed over the platform signing
// key, carries its own expiry, and has its sid checked against the Session row
// on every resolve, so it is revocable and it only ever exists downstream of a
// full sign-in, second factor included.
func silentGrant(c *zip.Ctx, db orm.DB, app *schema.Application, q authorizeRequest) (string, string) {
	ctx := c.Context()

	// A framed or fetched request is not a sign-in, it is a harvest. Only a
	// document navigation may spend the session.
	if !topLevelNavigation(c) {
		return "", errInteractionRequired
	}

	sc, ok := sessions.Current(ctx, c.Fiber(), db)
	if !ok {
		return "", errLoginRequired
	}

	// max_age: the relying party is asking for a sign-in no older than N seconds.
	// Answering it from a session older than that would be a lie told silently,
	// and it is the specific lie a client asks this question to avoid before a
	// sensitive operation.
	if !freshEnough(sc.AuthTime, param(c, "max_age")) {
		return "", errLoginRequired
	}

	// The account is re-read, never taken from the cookie: an identity forbidden
	// or deleted since sign-in must be refused rather than ride its old session.
	user, err := store.GetUserByName(ctx, db, sc.Owner, sc.Name)
	if err != nil {
		return "", errLoginRequired
	}
	if user == nil || user.IsForbidden || user.IsDeleted {
		return "", errLoginRequired
	}

	// id_token_hint names the person the client believes is signed in. If somebody
	// ELSE is, the client must be told login_required rather than handed a grant
	// for a different human (OIDC Core §3.1.2.1).
	//
	// This is not a nicety. A relying party doing silent renewal has an
	// established session for a specific subject; a code for a DIFFERENT subject,
	// arriving through the same callback the RP already trusts, swaps the signed-in
	// identity underneath the user with nothing on screen to notice. On a browser
	// where two identities are used in turn — the exact thing this platform is
	// building toward — that is not a corner case, it is Tuesday.
	if hint := param(c, "id_token_hint"); hint != "" {
		claims, err := verifyHint(ctx, db, hint)
		if err != nil || claims.Subject != subjectOf(user) {
			return "", errLoginRequired
		}
	}

	code, err := MintFor(ctx, db, app, user.Owner+"/"+user.Name, Mint{
		Type:                "code",
		RedirectUri:         q.redirectURI,
		State:               q.state,
		Scope:               q.scope,
		Nonce:               q.nonce,
		CodeChallenge:       q.codeChallenge,
		CodeChallengeMethod: q.codeChallengeMethod,
		Resource:            q.resource,
	})
	if err != nil {
		// A policy refusal, not a missing session. Re-asking for the password
		// would fail the same way, so the client is told it was denied rather
		// than sent round a loop it cannot win.
		return "", errAccessDenied
	}
	return code, ""
}

// topLevelNavigation reports whether the browser is NAVIGATING here — the only
// context in which a session may be spent silently.
//
// Sec-Fetch-Dest is set by the browser itself and is not settable by script, so
// a page cannot lie about being a navigation. It is absent from non-browser
// clients and from browsers that predate the header; absence is allowed, because
// the alternative is refusing every request from a client that cannot be doing
// the framing this guards against anyway. What is refused is a request that
// SAYS it is a frame, an image, or a fetch.
func topLevelNavigation(c *zip.Ctx) bool {
	dest := c.Header("Sec-Fetch-Dest")
	return dest == "" || dest == "document"
}

// freshEnough reports whether a sign-in at authTime satisfies a `max_age`
// request. An absent, malformed or negative max_age imposes no requirement —
// there is nothing to satisfy. Zero is a real value and means "authenticate
// now", which no existing session can satisfy.
func freshEnough(authTime int64, maxAge string) bool {
	if maxAge == "" {
		return true
	}
	secs, err := parseNonNegative(maxAge)
	if err != nil {
		return true
	}
	// max_age=0 asks for an authentication that happens NOW, and an existing
	// session by definition happened before the request arrived. It is spelled
	// out rather than left to the arithmetic below, because unix SECONDS cannot
	// tell "authenticated a moment ago" from "authenticating now" — a session
	// half a second old would otherwise satisfy a client that asked for a fresh
	// credential, which is the one client that must never be fobbed off.
	if secs == 0 {
		return false
	}
	// A session with no recorded auth time predates the field; it cannot prove
	// freshness, so it does not get to claim it.
	if authTime <= 0 {
		return false
	}
	return nowFunc().Unix()-authTime <= secs
}

// errNotANumber — max_age was not a plain decimal count of seconds.
var errNotANumber = errors.New("not a decimal number of seconds")

// parseNonNegative reads a decimal count of seconds, refusing anything that is
// not exactly that. strconv would accept "+5" and "-0"; a hand-rolled digit scan
// accepts one spelling of one value.
func parseNonNegative(s string) (int64, error) {
	var n int64
	if s == "" {
		return 0, errNotANumber
	}
	for i := 0; i < len(s); i++ {
		d := s[i]
		if d < '0' || d > '9' {
			return 0, errNotANumber
		}
		n = n*10 + int64(d-'0')
		if n > 1<<40 { // absurd max_age: treat as no constraint rather than overflow
			return 0, errNotANumber
		}
	}
	return n, nil
}
