// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/sessions"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// PathSignedOut is the SPA route a signed-out browser lands on. It is the
// portal's own sign-in page (App.tsx routes /login), reached on the issuer origin
// the request arrived at, so a white-labelled brand lands on ITS OWN page rather
// than another tenant's.
const PathSignedOut = "/login?signed_out=1"

// logoutHandler ends a sign-in and sends the browser somewhere sensible. Accepts
// GET or POST, so it works as a plain link.
//
// It ACTUALLY signs you out, which is worth stating because the endpoint spent a
// release not doing it: the whole body computed a redirect and answered
// {"status":"ok"} unconditionally — no session ended, no token revoked. A logout
// that reports success while leaving the session live is worse than no logout at
// all, because the person on the shared machine believes it worked. Three things
// happen here now, in this order:
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
// The open-redirect guard is unchanged: a redirect happens only when a VERIFIED
// id_token_hint identifies the application and that application has registered
// the target. Anything else refuses to redirect — nobody can turn your logout
// link into a redirect to a site of their choosing.
func logoutHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()

		// (1) End the session. Unconditional and first: it must happen whether or
		// not a hint is supplied, whether or not a redirect is asked for, and
		// whether or not any of what follows succeeds.
		owner, name, application, hadSession := sessions.Clear(ctx, c.Fiber(), db)

		// The hint is verified — a forged or unsigned one yields nil — and is the
		// only thing that can name an application here, for BOTH the revocation and
		// the redirect. Resolved once.
		app := appFromIDTokenHint(ctx, db, param(c, "id_token_hint"))

		// (2) Retire the grant this relying party holds for this user. Scoped to
		// (user, app) deliberately: signing out of one application must not silently
		// tear down every other application the person is signed into, which is what
		// a revoke-everything would do.
		if hadSession && app != nil {
			revokeGrant(ctx, db, owner+"/"+name, app.Name)
		} else if hadSession && application != "" {
			// No hint: retire the grant for the application the session itself names,
			// so a plain browser logout still leaves no mintable refresh token behind.
			revokeGrant(ctx, db, owner+"/"+name, application)
		}

		// (3) Redirect only to an address the identified application registered.
		if redirect := param(c, "post_logout_redirect_uri"); redirect != "" {
			if app != nil && app.IsRedirectUriValid(redirect) {
				if state := param(c, "state"); state != "" {
					sep := "?"
					if strings.Contains(redirect, "?") {
						sep = "&"
					}
					redirect += sep + "state=" + url.QueryEscape(state)
				}
				return c.Redirect(302, redirect)
			}
			// No proof the caller owns the target — refuse to redirect, and fall
			// through to the ordinary answer below.
		}

		// A browser gets a page it can read; an API caller keeps the JSON envelope
		// it parses. Same logout either way — only the way it is reported differs.
		if wantsHTML(c) {
			return c.Redirect(302, tokenIssuer(c)+PathSignedOut)
		}
		return c.JSON(200, map[string]string{"status": "ok"})
	}
}

// wantsHTML reports whether the caller is a browser NAVIGATING here rather than a
// program calling the API. Browsers send `Accept: text/html,…` on a navigation
// and every API client sends either application/json or the `*/*` default, so the
// question is answerable from Accept alone — with one carve-out: fetch/XHR from a
// page inherits nothing useful, so an explicit XMLHttpRequest marker or a JSON
// preference wins regardless.
//
// The default is JSON. A caller that expresses no preference keeps the existing
// contract, so nothing that parses this endpoint today starts receiving a
// redirect.
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
