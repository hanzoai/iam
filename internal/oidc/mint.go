// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"strings"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The shared tail of every interactive authentication: given a user who has
// ALREADY proven who they are — by password, by wallet signature, by any future
// factor — decide what the SDK reads back. One place, so a new front door
// inherits the redirect/PKCE/tenant rules instead of restating them.

// Mint is the authorize passthrough an interactive login carries. Type selects
// the shape: "code" mints a PKCE-bound authorization code for the OAuth flow,
// anything else is a bare portal sign-in.
type Mint struct {
	Type                string
	RedirectUri         string
	State               string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

// MintFor resolves what a successful authentication returns to the SDK: the
// user id for a bare portal sign-in, or a fresh PKCE-bound authorization code
// (persisted) for the OAuth flow. userID is "<org>/<name>" — the caller's own
// verified identity, never a client-supplied value.
//
// This is the ONE mint path. Every rule below is a security invariant, so it
// lives here rather than in each front door:
//   - Tenant isolation: the user's org must be permitted for this application —
//     its own org, a shared app, or an app that lets users choose their org.
//     Without it a user in one tenant could obtain a token naming another.
//   - Redirect binding: an exactly-registered redirect_uri (RFC 6749 §3.1.2.3);
//     the token endpoint re-checks it. A supplied-but-unregistered URI is never
//     minted against.
//   - PKCE: S256 only (never "plain"), and a public client must present a
//     challenge — no downgrade.
//   - Reserved-org confinement: a built-in/SuperAdmin principal is grantable
//     ONLY through an application that serves its own reserved org.
func MintFor(ctx context.Context, db orm.DB, app *schema.Application, userID string, p Mint) (string, error) {
	// The user's org is the owner half of its own id, set server-side at
	// authentication — never read from the request.
	org, _, _ := strings.Cut(userID, "/")

	// Reserved-org confinement, ahead of the type split so EVERY grant shape is
	// bound identically — a bare session, an authorization code, a wallet
	// sign-in, and the silent SSO grant alike. A RESERVED-org principal (a
	// SuperAdmin under "admin", a built-in service identity) may be granted only
	// through an application that itself serves that reserved org — the dedicated
	// console. Otherwise any SHARED application (whose tenant rule below accepts
	// every org by design) would mint a real SuperAdmin grant, and silent SSO
	// would mint it with no interaction at all.
	//
	// It lived in login.go, which meant it held for a typed password and for
	// nothing else. Here it holds for every front door, including the ones not
	// written yet.
	if store.IsReservedOrg(org) && (app == nil || org != app.Organization) {
		return "", errors.New("the user is not permitted to sign in to this application")
	}

	// A bare sign-in needs no application: report the identity and stop.
	if p.Type != "code" {
		return userID, nil
	}
	if app == nil {
		return "", errors.New("the application does not exist")
	}
	if org != app.Organization && !app.ServesAnyOrg() {
		return "", errors.New("the user is not permitted to sign in to this application")
	}
	if p.RedirectUri != "" && !app.IsRedirectUriValid(p.RedirectUri) {
		return "", errors.New("invalid redirect_uri")
	}
	method := normalizeChallengeMethod(p.CodeChallenge, p.CodeChallengeMethod)
	if p.CodeChallenge != "" && method != "S256" {
		return "", errors.New("only S256 PKCE is supported")
	}
	if app.ClientSecret == "" && p.CodeChallenge == "" {
		return "", errors.New("PKCE is required for public clients")
	}
	code, err := MintCode(app, userID, p.Scope, p.CodeChallenge, method, p.Resource, nowFunc())
	if err != nil {
		return "", err
	}
	// Bind the redirect_uri and nonce onto the code so the token exchange can
	// re-verify the redirect and echo the nonce into the id_token.
	code.RedirectUri = p.RedirectUri
	code.Nonce = p.Nonce
	if err := store.PersistToken(ctx, db, code); err != nil {
		return "", err
	}
	return code.Code, nil
}

// ResolveApp resolves the OAuth application a front door names: by clientId when
// present, else by name under the "admin" registry owner. Returns (nil, nil)
// when the request names no application. Shared by every interactive login so
// they all resolve the same app from the same fields.
func ResolveApp(ctx context.Context, db orm.DB, clientId, name string) (*schema.Application, error) {
	if clientId != "" {
		return store.GetApplicationByClientId(ctx, db, clientId)
	}
	if name != "" {
		return store.GetApplicationByName(ctx, db, "admin", name)
	}
	return nil, nil
}
