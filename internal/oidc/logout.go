// Copyright 2026 Hanzo AI, Inc. All rights reserved.

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
//     (sessions.Clear/ClearAll). Server-side revocation is the load-bearing
//     half: a copy of the cookie taken before logout must not still resolve.
//  2. The relying party's tokens are revoked when an id_token_hint names it, so
//     the refresh token cannot mint a fresh access token after the human left.
//     Revocation state is authoritative — a JWT's `exp` still reads valid for
//     days, so expiry is necessary but never sufficient.
//  3. Only then is a redirect considered, and only to a REGISTERED uri.
//
// # WHICH identity, now that a browser can hold several
//
// One rule, and it is the safe one in both directions: A REQUEST THAT NAMES AN
// IDENTITY SIGNS OUT THAT IDENTITY; A REQUEST THAT NAMES NONE SIGNS OUT EVERY
// IDENTITY.
//
//	id_token_hint  — the relying party names the human it holds a session for
//	                 (OIDC Core). Precise: signing out of one app must not tear
//	                 down an identity that app never saw.
//	logout_hint    — `owner/name`, the account page's per-identity sign-out.
//	neither        — everything.
//
// The "neither" case is where the security lives. A bare sign-out link, with no
// qualifier, is the shared-machine case: someone got up and pressed the button.
// Leaving a second identity live behind them because it merely was not the
// ACTIVE one would be a logout that reports success while a session survives —
// the same failure this endpoint spent a release having, one identity to the
// right. So a bare logout is complete, and partiality must be asked for.
//
// The open-redirect guard is unchanged: a redirect happens only when a VERIFIED
// id_token_hint identifies the application and that application has registered
// the target. Anything else refuses to redirect — nobody can turn your logout
// link into a redirect to a site of their choosing.
func logoutHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()

		// The hint is verified — a forged or unsigned one yields nil — and is the
		// only thing that can name an application here, for BOTH the revocation and
		// the redirect. Resolved once, BEFORE the session ends, because naming the
		// identity to sign out is part of what it resolves.
		hint := param(c, "id_token_hint")
		app := appFromIDTokenHint(ctx, db, hint)

		// (1) End the session(s). Unconditional and first: it must happen whether or
		// not a hint is supplied, whether or not a redirect is asked for, and
		// whether or not any of what follows succeeds.
		ended := endSession(ctx, c, db, hint)

		// (2) Retire the grant each relying party holds for each signed-out
		// identity. Scoped to (user, app) deliberately: signing out of one
		// application must not silently tear down every other application that
		// person is signed into, which is what a revoke-everything would do.
		for _, id := range ended {
			target := id.Application
			if app != nil {
				target = app.Name
			}
			if target != "" {
				revokeGrant(ctx, db, id.String(), target)
			}
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

// endSession applies the one rule this endpoint states: a request that NAMES an
// identity ends that identity, a request that names none ends every identity.
// It returns the identities actually signed out, so the caller can retire their
// grants — empty when there was no live session to end.
//
// A named identity is matched against the SIGNED SET this browser already holds
// (sessions.Clear), so a hint can only ever end a session the caller was already
// carrying. Naming somebody else's identity ends nothing and leaves this
// browser's session untouched.
func endSession(ctx context.Context, c *zip.Ctx, db orm.DB, hint string) []sessions.Identity {
	if owner, name, named := logoutTarget(ctx, c, db, hint); named {
		if id, ok := sessions.Clear(ctx, c.Fiber(), db, owner, name); ok {
			return []sessions.Identity{*id}
		}
		return nil
	}
	ended, _ := sessions.ClearAll(ctx, c.Fiber(), db)
	return ended
}

// logoutTarget resolves WHICH identity a logout request names, or named=false
// when it names none (which means all of them).
//
// `logout_hint` carries the `owner/name` selector the account page's per-identity
// sign-out sends — the same string form the CLI takes for `hanzo auth logout
// <identity>`. `id_token_hint` is the relying party naming the human IT holds a
// session for, resolved through the token's `sub` to the real (owner, name); it
// is the OIDC-native spelling and it is checked SECOND so an explicit selector
// always wins.
//
// Every failure — an unparseable selector, a forged or expired id_token_hint, a
// subject with no user row — reports named=false and therefore ends EVERY
// identity. That direction is deliberate: a hint this server cannot believe must
// never be allowed to narrow a sign-out, because narrowing is the outcome that
// leaves a session alive. The worst an attacker gains from feeding this endpoint
// a hint it rejects is a more complete logout than they asked for.
func logoutTarget(ctx context.Context, c *zip.Ctx, db orm.DB, hint string) (owner, name string, named bool) {
	if sel := param(c, "logout_hint"); sel != "" {
		return sessions.ParseIdentity(sel)
	}
	if hint == "" {
		return "", "", false
	}
	claims, err := verifyToken(ctx, db, hint)
	if err != nil {
		return "", "", false
	}
	u, err := store.GetUserBySubject(ctx, db, claims.Subject)
	if err != nil || u == nil {
		return "", "", false
	}
	return u.Owner, u.Name, true
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
func appFromIDTokenHint(ctx context.Context, db orm.DB, hint string) *schema.Application {
	if hint == "" {
		return nil
	}
	claims, err := verifyToken(ctx, db, hint)
	if err != nil || len(claims.Audience) == 0 {
		return nil
	}
	app, err := store.GetApplicationByClientId(ctx, db, claims.Audience[0])
	if err != nil {
		return nil
	}
	return app
}
