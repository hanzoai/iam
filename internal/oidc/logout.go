// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// logoutHandler ends a sign-in session and sends the browser back to your
// application. Accepts GET or POST, so it works as a plain link.
//
// It returns only to an address the application has registered, and only when
// the request carries an id_token whose signature verifies — so nobody can turn
// your logout link into a redirect to a site of their choosing.
func logoutHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		redirect := param(c, "post_logout_redirect_uri")
		if redirect == "" {
			return c.JSON(200, map[string]string{"status": "ok"})
		}
		app := appFromIDTokenHint(c.Context(), db, param(c, "id_token_hint"))
		if app == nil || !app.IsRedirectUriValid(redirect) {
			// No proof the caller owns the target — refuse to redirect.
			return c.JSON(200, map[string]string{"status": "ok"})
		}
		if state := param(c, "state"); state != "" {
			sep := "?"
			if strings.Contains(redirect, "?") {
				sep = "&"
			}
			redirect += sep + "state=" + url.QueryEscape(state)
		}
		return c.Redirect(302, redirect)
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
