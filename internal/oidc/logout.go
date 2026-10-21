// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PathSignIn is the hosted sign-in page (hanzoai/id App.tsx routes /login; the
// page reads the application from ?client_id). A signed-out browser lands there
// on the issuer origin the request arrived at, so a white-labelled brand lands on
// ITS OWN page rather than another tenant's.
const PathSignIn = "/login"

// logoutHandler ends a sign-in and sends the browser somewhere sensible. Accepts
// GET or POST, so it works as a plain link.
//
// It ACTUALLY signs you out — worth stating, because a logout that computes a
// redirect and answers {"status":"ok"} while ending no session and revoking no
// token is worse than none: the person on the shared machine believes it worked.
// Three things happen here, in this order:
//
//  1. The browser session dies — sid revoked server-side AND the cookie expired
//     (sessions.Clear). Server-side revocation is the load-bearing half: a copy
//     of the cookie taken before logout must not still resolve.
//  2. The relying party's tokens are revoked when an id_token_hint names it, so
//     the refresh token cannot mint a fresh access token after the human left.
//     Revocation state is authoritative — a JWT's `exp` still reads valid for
//     days, so expiry is necessary but never sufficient.
//  3. Only then is a redirect considered, and only to a REGISTERED uri.
//
// The open-redirect guard: a redirect happens only when a VERIFIED
// id_token_hint (or client_id) identifies the application and that application
// has registered the target. Nobody can turn your logout link into a redirect to
// a site of their choosing.
//
// A GET is the end-session navigation (OIDC RP-Initiated Logout 1.0 §2), so it
// always ends on a page: the registered address when one was asked for, else
// this issuer's sign-in page for the application being signed out of. A relying
// party therefore needs no configuration to sign someone out. A POST is also how
// a program signs out, so it keeps the JSON answer unless it asks for HTML.
func logoutHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()

		// (0) A relying party's sign-out form posted from another site arrives
		// without the session cookie, because SameSite=Lax keeps it off a cross-site
		// POST. Answering it would end nothing and still return the browser to the
		// relying party, which reads that as signed out while the session lives. So
		// the browser comes back here as a GET with the same parameters, the one
		// cross-site request the cookie rides on.
		if again, ok := crossSiteForm(c); ok {
			return c.Redirect(http.StatusSeeOther, again)
		}

		// (1) End every session the browser holds. First: it must happen whether or
		// not a hint is supplied, whether or not a redirect is asked for, and
		// whether or not any of what follows succeeds. The one thing that stops it
		// is a request another page could have sent (sessions.Clear), which ends
		// nothing and revokes nothing.
		ended, err := sessions.Clear(ctx, c.Fiber(), db)
		if err != nil {
			return httpx.Fail(c, http.StatusForbidden, err.Error(), "")
		}

		// The hint is verified — a forged or unsigned one yields nil — and is the
		// only thing that can name an application here, for BOTH the revocation and
		// the redirect. Resolved once.
		// id_token_hint first, then client_id. RP-Initiated Logout defines both, and
		// says client_id is there for exactly the case where the hint is not
		// available -- which is every SPA that did not keep the id_token. Without it
		// the lookup returns nil, step (3) refuses the redirect, and the person
		// lands on our sign-in page instead of back in the app they pressed
		// sign-out in. Nothing came back, which reads as sign-out being broken.
		//
		// It gives away nothing: the redirect must still be one the identified
		// application REGISTERED, so naming a client_id can only return a browser
		// to an address that client already owns.
		app := appFromIDTokenHint(ctx, db, param(c, "id_token_hint"))
		if app == nil {
			app = appFromClientId(ctx, db, param(c, "client_id"))
		}

		// (2) Retire the grant this relying party holds for each signed-out user.
		// Scoped to (user, app) deliberately: signing out of one application must
		// not silently tear down every other application the person is signed into,
		// which is what a revoke-everything would do. With no hint, the grant
		// retired is the one for the application the session itself names, so a
		// plain browser logout still leaves no mintable refresh token behind.
		//
		// Unless the person asked for every one (`everywhere=true`): the sign-out a
		// suite of first-party sites shares, where leaving one of them (hanzo.ai)
		// must leave the others (platform.hanzo.ai) too. It reaches only the
		// applications of the SAME organization as the one signed out of, so a
		// third-party app the person signed into through IAM keeps its grant, and
		// like the scoped default it needs the session: a hint alone retires nothing.
		for _, sc := range ended {
			application := sc.Application
			if app != nil {
				application = app.Name
			}
			if application == "" {
				continue
			}
			user := sc.Owner + "/" + sc.Name
			revokeGrant(ctx, db, user, application)
			if everywhere(c) {
				revokeSiblings(ctx, db, user, application, app)
			}
		}

		// (3) Redirect only to an address the identified application registered.
		if redirect := param(c, "post_logout_redirect_uri"); redirect != "" && app != nil && app.IsRedirectUriValid(redirect) {
			if state := param(c, "state"); state != "" {
				sep := "?"
				if strings.Contains(redirect, "?") {
					sep = "&"
				}
				redirect += sep + "state=" + url.QueryEscape(state)
			}
			return c.Redirect(302, redirect)
		}
		// Anything else is refused as a target and falls through: a navigation
		// lands on the sign-in page, an API caller keeps the JSON envelope it
		// parses. Same logout either way — only the way it is reported differs.
		if c.Method() == http.MethodGet || wantsHTML(c) {
			page, err := signInPage(c, app)
			if err != nil {
				return httpx.Fail(c, http.StatusInternalServerError, "server_error", "")
			}
			return c.Redirect(302, page)
		}
		return c.JSON(200, map[string]string{"status": "ok"})
	}
}

// signInPage is this issuer's hosted sign-in page for app, or the issuer's
// default sign-in when no application was identified.
func signInPage(c *zip.Ctx, app *schema.Application) (string, error) {
	iss, err := tokenIssuer(c)
	if err != nil {
		return "", err
	}
	page := iss + PathSignIn
	if app != nil && app.ClientId != "" {
		page += "?" + url.Values{"client_id": {app.ClientId}}.Encode()
	}
	return page, nil
}

// wantsHTML reports whether a POST comes from a browser form rather than a
// program calling the API. Browsers send `Accept: text/html,…` on a form
// navigation and every API client sends either application/json or the `*/*`
// default, so the question is answerable from Accept alone — with one carve-out:
// fetch/XHR from a page inherits nothing useful, so an explicit XMLHttpRequest
// marker or a JSON preference wins regardless.
//
// The default is JSON: a program that POSTs and expresses no preference gets the
// envelope it parses.
func wantsHTML(c *zip.Ctx) bool {
	if strings.EqualFold(c.Header("X-Requested-With"), "XMLHttpRequest") {
		return false
	}
	accept := c.Header("Accept")
	if strings.Contains(accept, "application/json") {
		return false
	}
	return strings.Contains(accept, "text/html")
}

// everywhere reports whether a sign-out asks to leave every application of the
// organization it is signing out of, not only that one.
func everywhere(c *zip.Ctx) bool {
	v := strings.ToLower(param(c, "everywhere"))
	return v == "true" || v == "1"
}

// revokeSiblings retires the grant a user holds for every application of the
// organization `application` belongs to (`app` when the request named it, else
// the one the session was opened for). The organization is read off each
// application row, never the token's own Organization, which some mints stamp
// with the user's org instead. An application that cannot be resolved is left
// alone: retiring a grant nobody can place in the organization would be the
// revoke-everything this exists to avoid.
func revokeSiblings(ctx context.Context, db orm.DB, user, application string, app *schema.Application) {
	if app == nil {
		found, err := store.GetApplicationNamed(ctx, db, application)
		if err != nil || found == nil {
			return
		}
		app = found
	}
	if app.Organization == "" {
		return
	}
	rows, err := store.ListTokensByUser(ctx, db, user)
	if err != nil {
		return
	}
	seen := map[string]bool{application: true}
	for _, row := range rows {
		if row.Application == "" || seen[row.Application] {
			continue
		}
		seen[row.Application] = true
		sibling, err := store.GetApplicationNamed(ctx, db, row.Application)
		if err != nil || sibling == nil || sibling.Organization != app.Organization {
			continue
		}
		revokeGrant(ctx, db, user, row.Application)
	}
}

// revokeGrant deletes every token row a user holds for one application, together
// with the whole refresh-rotation family each belongs to. The family sweep is
// what makes it a revocation rather than a gesture: a refresh chain rotates into
// NEW rows, so deleting only the rows found by (user, app) can leave a rotated
// descendant alive and mintable.
//
// Best-effort by construction — a logout must not fail because a row was already
// gone, and revocation is idempotent (store.DeleteToken treats a missing row as
// success).
func revokeGrant(ctx context.Context, db orm.DB, user, application string) {
	rows, err := store.ListTokensByUserApp(ctx, db, user, application)
	if err != nil {
		return
	}
	for _, row := range rows {
		if row.RefreshFamily != "" {
			family, err := store.ListTokensByRefreshFamily(ctx, db, row.RefreshFamily)
			if err == nil {
				for _, t := range family {
					_ = store.DeleteToken(ctx, db, t)
				}
			}
		}
		_ = store.DeleteToken(ctx, db, row)
	}
}

// appFromIDTokenHint resolves the application an id_token_hint was issued to, but
// only when the hint's signature verifies. A forged or unsigned hint yields nil,
// so it can never authorize a redirect.
//
// verifyHint, so the EXPIRY is not enforced — one parameter, one meaning, the
// same rule the silent authorize applies. A relying party sends the last id
// token it holds, and an id token is short next to the session it describes: a
// browser signed in for longer than one has run out of them entirely, because a
// refresh renews the access token and leaves the id token as first issued. Read
// with expiry enforced, every such logout loses its hint — which is the ONE
// thing that names the application, so the grant stays mintable and the person
// is left at the issuer instead of back where they signed out.
//
// It costs nothing to accept. A hint is not a credential and grants nothing; it
// only names who the client believes is signed in. The signature stays
// mandatory, the application still comes from the token's own audience, and the
// redirect still has to be one that application registered.
// appFromClientId resolves the relying party from a bare client_id. It proves
// nothing about the caller -- the registered-redirect check in step (3) is the
// boundary, not this lookup.
func appFromClientId(ctx context.Context, db orm.DB, clientId string) *schema.Application {
	if clientId == "" {
		return nil
	}
	app, err := store.GetApplicationByClientId(ctx, db, clientId)
	if err != nil {
		return nil
	}
	return app
}

func appFromIDTokenHint(ctx context.Context, db orm.DB, hint string) *schema.Application {
	if hint == "" {
		return nil
	}
	claims, err := verifyHint(ctx, db, hint)
	if err != nil || len(claims.Audience) == 0 {
		return nil
	}
	app, err := store.GetApplicationByClientId(ctx, db, claims.Audience[0])
	if err != nil {
		return nil
	}
	return app
}

// crossSiteForm reports whether a sign-out is a form another site posted, top
// level, with no session cookie, and if so the GET of this endpoint carrying its
// parameters. A form posted into a frame is not one: the GET inside a cross-site
// frame carries no Lax cookie either.
func crossSiteForm(c *zip.Ctx) (string, bool) {
	f := c.Fiber()
	if f.Method() != http.MethodPost || f.Cookies(sessions.CookieName) != "" ||
		f.Get("Sec-Fetch-Site") != "cross-site" || f.Get("Sec-Fetch-Mode") != "navigate" || f.Get("Sec-Fetch-Dest") != "document" {
		return "", false
	}
	q := url.Values{}
	for k, v := range f.Request().URI().QueryArgs().All() {
		q.Add(string(k), string(v))
	}
	for k, v := range f.Request().PostArgs().All() {
		q.Add(string(k), string(v))
	}
	if len(q) == 0 {
		return PathLogout, true
	}
	return PathLogout + "?" + q.Encode(), true
}
