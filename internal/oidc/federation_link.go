// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Connecting a provider to an account you already hold: POST /v1/iam/link. It is
// the deliberate half of the linking law, and unlink (federation_unlink.go) had no
// counterpart — so the only way a provider ever became linked was the coincidence
// in linkOrProvision, an IdP address that happens to match one an account already
// PROVED. A person whose GitHub address differs from their account address got a
// second account instead of a link, and after any unlink, re-linking needed that
// same coincidence, which they cannot arrange from a settings page.
//
// It runs the SAME federation transaction a sign-in runs — one begin, one IdP leg,
// one callback, one burn — and differs in exactly one field: the transaction
// carries the caller's Subject, so the callback ATTACHES the verified provider
// identity to that account instead of resolving one. No second IdP round-trip
// exists to keep in step with the first.
//
// WHY IT IS A POST AND NOT A LINK IN A PAGE. Attaching a provider to a signed-in
// account is an account takeover if an attacker can cause it: their identity, your
// account, and afterwards they sign in as you. A top-level GET is exactly what an
// attacker can cause (a Lax cookie rides a navigation), so INTENT has to be proven
// by a request their page cannot make — a same-site JSON POST that authenticates
// as the account it will act on. That is why the callback must never attach to a
// live session on its own, however convenient that would be.

// PathLink is the canonical begin-a-link endpoint.
const PathLink = "/v1/iam/link"

// routeLink registers POST /v1/iam/link on the PUBLIC group. Like unlink it
// SELF-AUTHENTICATES through callerOf (session cookie, else a verified bearer):
// an oidc handler cannot import authz, and a caller callerOf cannot resolve is
// refused.
func routeLink(r zip.Router, db orm.DB) {
	r.Post(PathLink, link(db))
}

// linkForm is the request body: which provider to connect, and where to return the
// browser afterwards.
type linkForm struct {
	// Provider is the provider RECORD name ("provider-github") — the same string
	// the authorize endpoint takes, matched the same way, so a client names a
	// provider one way for both flows.
	Provider string `json:"provider"`
	// ClientId + ReturnUri say where to send the browser when the round-trip ends.
	// ReturnUri is validated against the application's REGISTERED list, exactly as
	// an authorize redirect_uri is, so this endpoint cannot be turned into an open
	// redirector.
	ClientId  string `json:"clientId"`
	ReturnUri string `json:"returnUri"`
}

// link starts connecting another sign-in identity to the account you are already
// signed in as. It answers with the provider's URL for the browser to follow; when
// the provider returns, that identity is attached and you come back to returnUri.
//
// Your account is fixed here, from the credential you are already holding, and is
// carried server-side for the rest of the round-trip — so nothing that happens at
// the provider can point the link at somebody else.
func link(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		var f linkForm
		if err := c.Bind(&f); err != nil {
			return httpx.Err(c, "invalid request body")
		}
		ctx := c.Context()
		owner, name, ok := callerOf(ctx, c, db)
		if !ok {
			return httpx.Err(c, "Please login first")
		}
		user, err := store.GetUserByName(ctx, db, owner, name)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if user == nil || user.IsForbidden || user.IsDeleted {
			return httpx.Err(c, "the account is not permitted")
		}

		app, err := store.GetApplicationByClientId(ctx, db, f.ClientId)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if app == nil {
			return httpx.Err(c, "the application does not exist")
		}
		if !app.IsRedirectUriValid(f.ReturnUri) {
			return httpx.Err(c, "invalid returnUri")
		}
		// The same tenant-legitimacy and reserved-org gate a federated sign-in
		// passes: an application that may not federate may not link either.
		if !federationOrgAllowed(app) {
			return httpx.Err(c, "federation is not permitted for this application")
		}
		store.EnrichProviders(ctx, db, app)
		prov := federationProvider(app, f.Provider)
		if prov == nil {
			return httpx.Err(c, "unknown or unavailable provider")
		}
		if idpKind(prov) == "" {
			return httpx.Err(c, "provider is not a supported federation type")
		}
		binding, known := connectorFor(prov.Type)
		if !known {
			return httpx.Err(c, "provider has no local identity binding")
		}
		// Already linked here: say so rather than spend a round-trip to learn it.
		if *binding.ref(user) != "" {
			return httpx.Err(c, "this provider is already connected to your account")
		}

		st, secret, err := newFederationState(ctx, db, prov, app, owner+"/"+name, f.ReturnUri, nowFunc())
		if err != nil {
			return httpx.Err(c, "server_error")
		}
		idpURL, err := idpAuthorizeURL(ctx, prov, st, federationCallbackURL(c))
		if err != nil {
			return httpx.Err(c, "the identity provider is unavailable")
		}
		if err := store.PersistFederationState(ctx, db, st); err != nil {
			return httpx.Err(c, "server_error")
		}
		setBindCookie(c, secret)
		// The browser navigates to this; the endpoint does not redirect, because the
		// caller is a page making a request, not a navigation.
		return httpx.Ok(c, idpURL)
	}
}

// newFederationState mints a transaction for a LINK: the same single-use,
// browser-bound, expiring row a sign-in mints, carrying the caller's subject and
// the return target in place of an app-leg authorize request. Returns the row and
// the bind secret to set as the cookie; the row is NOT persisted here, so a
// discovery failure leaves no orphan.
func newFederationState(ctx context.Context, db orm.DB, prov *schema.Provider, app *schema.Application, subject, returnUri string, now time.Time) (*schema.FederationState, string, error) {
	state, err := newOpaqueToken()
	if err != nil {
		return nil, "", err
	}
	verifier, err := newOpaqueToken()
	if err != nil {
		return nil, "", err
	}
	nonce, err := newOpaqueToken()
	if err != nil {
		return nil, "", err
	}
	secret, err := newOpaqueToken()
	if err != nil {
		return nil, "", err
	}
	return &schema.FederationState{
		Owner:       providerOwner(prov),
		Name:        state,
		CreatedTime: now.UTC().Format(time.RFC3339),
		Provider:    prov.Name,
		ClientId:    app.ClientId,
		RedirectUri: returnUri,
		Subject:     subject,
		IdpVerifier: verifier,
		IdpNonce:    nonce,
		BindHash:    hashToken(secret),
		ExpireIn:    now.Add(fedStateTTL).Unix(),
	}, secret, nil
}

// attach stamps a verified provider subject onto the account the transaction was
// minted for. One provider identity, one account: a subject already linked to
// somebody else is refused rather than moved, so a link can never quietly take an
// identity off another account.
//
// The uniqueness is scoped to the account's own organization, which is where
// linkOrProvision's subject match reads from too — so both halves of the law agree
// on what "already linked" means. (A cross-org rule, the wallet's `anywhere`, would
// have to move sign-in with it and is not this change.)
func attach(ctx context.Context, db orm.DB, owner, name string, binding connectorBinding, subject string) error {
	held, err := store.GetUserByConnector(ctx, db, owner, binding.field, subject)
	if err != nil {
		return err
	}
	if held != nil {
		if held.Owner == owner && held.Name == name {
			return nil // already attached here: the round-trip was redundant, not wrong
		}
		return errSubjectLinked
	}
	_, err = updateUser(ctx, db, owner, name, func(_ orm.DB, fresh *schema.User) error {
		*binding.ref(fresh) = subject
		return nil
	})
	return err
}
