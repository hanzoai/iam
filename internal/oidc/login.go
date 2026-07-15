// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/httpx"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
	"github.com/hanzoai/iam2/internal/users"
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
	Type         string `json:"type"` // "code" (PKCE authorize) | "login" (bare session)

	// PKCE authorize passthrough (present when type=code).
	ClientId            string `json:"clientId"`
	RedirectUri         string `json:"redirectUri"`
	State               string `json:"state"`
	Scope               string `json:"scope"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	Resource            string `json:"resource"`
}

// MountLogin registers POST /v1/iam/login.
func MountLogin(app *zip.App, db orm.DB) {
	app.Post(PathLogin, loginHandler(db))
}

func loginHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f loginForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		if f.Organization == "" || f.Username == "" || f.Password == "" {
			return httpx.Err(c, "organization, username and password are required")
		}
		ctx := c.Context()

		user, err := resolveLoginUser(ctx, db, f.Organization, f.Username)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		// One opaque failure for "no such user" and "wrong password" — no oracle
		// that reveals whether the account exists.
		if user == nil || !users.VerifyPassword(user, f.Password) {
			return httpx.Err(c, "the username or password is incorrect")
		}

		userID := user.Owner + "/" + user.Name

		// type=login: a bare portal sign-in. Session issuance lands with the
		// session layer; for now report success + the user id (the shape the
		// portal expects for a non-OAuth sign-in).
		if f.Type != "code" {
			return httpx.Ok(c, userID)
		}

		// type=code: mint a PKCE-bound authorization code for the OAuth flow.
		app, err := resolveLoginApp(ctx, db, f)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if app == nil {
			return httpx.Err(c, "the application does not exist")
		}
		if f.CodeChallenge != "" && f.CodeChallengeMethod != "S256" {
			return httpx.Err(c, "only S256 PKCE is supported")
		}
		code, err := MintCode(app, userID, f.Scope, f.CodeChallenge, f.CodeChallengeMethod, f.Resource, nowFunc())
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if err := store.PersistToken(ctx, db, code); err != nil {
			return httpx.Err(c, err.Error())
		}
		// The SDK reads data as the authorization code to exchange at /token.
		return httpx.Ok(c, code.Code)
	}
}

// resolveLoginUser looks a user up by email (contains "@") or username, scoped
// to the org.
func resolveLoginUser(ctx context.Context, db orm.DB, org, identifier string) (*schema.User, error) {
	if strings.Contains(identifier, "@") {
		u, err := store.GetUserByEmail(ctx, db, org, identifier)
		if err != nil || u != nil {
			return u, err
		}
		// Fall through: some accounts set name = email (email is not indexed as
		// a separate login) — try name too.
	}
	return store.GetUserByName(ctx, db, org, identifier)
}

// resolveLoginApp resolves the OAuth app for a type=code login: by clientId when
// present, else by (org, application name).
func resolveLoginApp(ctx context.Context, db orm.DB, f loginForm) (*schema.Application, error) {
	if f.ClientId != "" {
		return store.GetApplicationByClientId(ctx, db, f.ClientId)
	}
	if f.Application != "" {
		return store.GetApplicationByName(ctx, db, "admin", f.Application)
	}
	return nil, nil
}
