// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// Issue is the ONE seam an authenticated user becomes an authorization code
// through. Every login method ends here — the credential login (login.go) and
// the social hop (internal/social) alike — so the checks between "this is the
// user" and "here is the code" are stated once and cannot be true of one method
// and false of another.
//
// That is the whole point of the seam, not an incidental refactor. In v1 the
// social link path minted its own session and skipped the second-factor check
// that the password path ran, so an account with MFA enabled could be taken
// over without it (controllers/auth.go:1235 vs :1054). iam2 has no MFA engine
// yet — only the schema fields — which is exactly when the seam has to exist:
// when the gate lands it lands HERE, once, and no method can be born past it.

// The refusals Issue can return. They carry v1's message text so the front-door
// envelope is unchanged for the SDK and the hosted UI.
var (
	// ErrTenant — the user's organization may not sign in to this application.
	ErrTenant = errors.New("the user is not permitted to sign in to this application")
	// ErrRedirect — the redirect_uri is not registered on the application.
	ErrRedirect = errors.New("invalid redirect_uri")
	// ErrChallenge — a PKCE method other than S256 was presented.
	ErrChallenge = errors.New("only S256 PKCE is supported")
	// ErrPublic — a public client (no secret) did not use PKCE.
	ErrPublic = errors.New("PKCE is required for public clients")
)

// Params are the authorize parameters a minted code is bound to.
type Params struct {
	Scope     string
	Redirect  string
	Nonce     string
	Challenge string
	Method    string
	Resource  string
}

// Issue mints and persists a PKCE-bound authorization code for u at app.
//
// The tenant is read from the USER row — the authenticated principal's own
// organization — never from a request parameter, so a caller cannot name a
// tenant it does not belong to (HIP-0111 Invariant 3).
func Issue(ctx context.Context, db orm.DB, app *schema.Application, u *schema.User, p Params) (*schema.Token, error) {
	// Tenant isolation: the authenticated user's organization must be permitted
	// for this application — its own org, a shared app, or an app that lets
	// users choose their org. Without this a user in one tenant could obtain a
	// token whose `organization` claim names another tenant.
	if u.Owner != app.Organization && !app.IsShared && app.OrgChoiceMode == "" {
		return nil, ErrTenant
	}
	// Bind the code to an EXACTLY-registered redirect URI (RFC 6749 §3.1.2.3);
	// the token endpoint re-checks it. A supplied-but-unregistered URI is
	// refused — never minted against.
	if p.Redirect != "" && !app.IsRedirectUriValid(p.Redirect) {
		return nil, ErrRedirect
	}
	method := normalizeChallengeMethod(p.Challenge, p.Method)
	if p.Challenge != "" && method != "S256" {
		return nil, ErrChallenge
	}
	// A public client (no secret) must use PKCE — no downgrade.
	if app.ClientSecret == "" && p.Challenge == "" {
		return nil, ErrPublic
	}
	code, err := MintCode(app, u.Owner+"/"+u.Name, p.Scope, p.Challenge, method, p.Resource, nowFunc())
	if err != nil {
		return nil, err
	}
	// Bind the redirect_uri and nonce onto the code so the token exchange can
	// re-verify the redirect and echo the nonce into the id_token.
	code.RedirectUri = p.Redirect
	code.Nonce = p.Nonce
	if err := store.PersistToken(ctx, db, code); err != nil {
		return nil, err
	}
	return code, nil
}
