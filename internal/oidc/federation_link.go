// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/sessions"
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
// It runs the SAME federation transaction a sign-in runs — one IdP leg, one
// callback, one burn — and differs in exactly one field: the transaction
// carries the caller's Subject, so the callback ATTACHES the verified provider
// identity to that account instead of resolving one. No second IdP round-trip
// exists to keep in step with the first.
//
// A sign-in method outlives every token, so adding one takes two proofs, one per
// leg, and neither leg alone attaches anything:
//
//   - INTENT, by the POST: a request no other page can make, from the person on
//     the issuer (a session this request may spend) or from one of the platform's
//     own applications (PlatformBearer). A top-level GET cannot prove it — a Lax
//     cookie rides any navigation another page starts — which is why the callback
//     never attaches to a live session on its own.
//   - PRESENCE, by the GET: the browser that runs the provider leg is a top-level
//     navigation holding the person's own session here. The browser binding is set
//     on that navigation, as a sign-in's is on its authorize navigation, so the
//     POST's answer carries neither the provider-leg state nor its binding.

// PathLink is the link endpoint: POST starts a link, GET carries it into the
// browser of the person it is for.
const PathLink = "/v1/iam/link"

// routeLink registers both legs of a link on the PUBLIC group. Each
// SELF-AUTHENTICATES — the POST through linker, the GET through the session the
// browser holds — because an oidc handler cannot import authz.
func routeLink(r *zip.Group, db orm.DB) {
	r.Raw(http.MethodPost, PathLink, link(db))
	r.Raw(http.MethodGet, PathLink, follow(db))
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
// signed in as. It answers with an address for your browser to open; from there
// you go to the provider, and when it returns, that identity is attached and you
// come back to returnUri. Only the browser where you are signed in here can carry
// a link through.
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
		owner, name, err := linker(ctx, c, db)
		if errors.Is(err, ErrNotPlatform) {
			return httpx.Fail(c, http.StatusForbidden, err.Error(), "")
		}
		if err != nil {
			return refuseCaller(c, err, "Please login first")
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

		st, err := newFederationState(prov, app.ClientId, owner+"/"+name, f.ReturnUri, nowFunc())
		if err != nil {
			return httpx.Err(c, "server_error")
		}
		base, err := federationBaseURL(c)
		if err != nil {
			return httpx.Fail(c, http.StatusInternalServerError, "server_error", "")
		}
		if err := persist(ctx, db, st, nowFunc()); err != nil {
			return httpx.Err(c, "server_error")
		}
		// The browser navigates to this; the endpoint does not redirect, because the
		// caller is a page making a request, not a navigation.
		return httpx.Ok(c, base+PathLink+"?"+url.Values{"state": {st.Name}}.Encode())
	}
}

// linker is who a link acts for: the person on the issuer, by a session this
// request may spend, or the account a bearer issued to one of the platform's own
// applications names (PlatformBearer). A bearer any other application holds starts
// no link and answers ErrNotPlatform.
func linker(ctx context.Context, c *zip.Ctx, db orm.DB) (owner, name string, err error) {
	if bearer := httpx.Bearer(c); bearer != "" {
		if sc, _ := sessions.Writer(ctx, c.Fiber(), db); sc == nil {
			if _, _, err := PlatformBearer(ctx, db, bearer); err != nil {
				return "", "", err
			}
		}
	}
	return callerOf(ctx, c, db)
}

// follow continues a link in the browser of the person it is for: the browser
// opens the address POST /v1/iam/link answered, as a top-level navigation, signed
// in here as that person, and is sent on to the provider.
//
// The address works once. The provider leg runs on a fresh transaction, bound to
// this browser by a cookie set on this navigation, so that transaction and its
// binding exist only here.
func follow(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		now := nowFunc()
		begun, err := store.GetFederationState(ctx, db, param(c, "state"))
		if err != nil {
			return authorizeUserError(c, "internal error")
		}
		// Only a transaction link minted that no browser has opened yet: a sign-in's
		// names no subject, and an opened one carries its binding.
		if begun == nil || begun.Subject == "" || begun.BindHash != "" {
			return authorizeUserError(c, "this link is not one we issued — start again")
		}
		if !topLevelNavigation(c) || !signedInHere(c, db, begun.Subject) {
			return authorizeUserError(c, "sign in here as the account you are connecting, then start again")
		}
		if _, err := store.BurnFederationState(ctx, db, begun.Name, now); err != nil {
			if errors.Is(err, store.ErrFederationConsumed) {
				return authorizeUserError(c, "this link was already used or has expired — start again")
			}
			return authorizeUserError(c, "internal error")
		}
		prov, err := store.GetProvider(ctx, db, begun.Owner, begun.Provider)
		if err != nil || prov == nil {
			return authorizeUserError(c, "the identity provider is unavailable")
		}
		st, err := newFederationState(prov, begun.ClientId, begun.Subject, begun.RedirectUri, now)
		if err != nil {
			return authorizeUserError(c, "internal error")
		}
		secret, err := newOpaqueToken()
		if err != nil {
			return authorizeUserError(c, "internal error")
		}
		st.BindHash = hashToken(secret)
		callback, err := federationCallbackURL(c)
		if err != nil {
			return authorizeUserError(c, "internal error")
		}
		idpURL, err := idpAuthorizeURL(ctx, prov, st, callback, "")
		if err != nil {
			return authorizeUserError(c, "the identity provider is unavailable")
		}
		if err := persist(ctx, db, st, now); err != nil {
			return authorizeUserError(c, "internal error")
		}
		setBindCookie(c, secret, prov)
		return c.Redirect(302, idpURL)
	}
}

// newFederationState mints a transaction for a LINK: the same single-use,
// expiring row a sign-in mints, carrying the caller's subject and the return
// target in place of an app-leg authorize request. It is bound to no browser:
// follow sets the binding on the transaction the provider leg runs on. The row is
// NOT persisted here.
func newFederationState(prov *schema.Provider, clientID, subject, returnUri string, now time.Time) (*schema.FederationState, error) {
	state, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	verifier, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	nonce, err := newOpaqueToken()
	if err != nil {
		return nil, err
	}
	return &schema.FederationState{
		Owner:       providerOwner(prov),
		Name:        state,
		CreatedTime: now.UTC().Format(time.RFC3339),
		Provider:    prov.Name,
		ClientId:    clientID,
		RedirectUri: returnUri,
		Subject:     subject,
		IdpVerifier: verifier,
		IdpNonce:    nonce,
		ExpireIn:    now.Add(fedStateTTL).Unix(),
	}, nil
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
