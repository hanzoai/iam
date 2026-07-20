// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/idp"
	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
)

// The first half of a social sign-in (HIP-0111 §7): a provider hint on the
// authorize request sends the browser straight to Google/GitHub/GitLab instead
// of to the hosted login. The second half — the /callback landing that turns
// the upstream code into an account — is internal/social; it claims the request
// parked here and issues through Issue.
//
// The hop starts only AFTER the authorize request is validated, so an unknown
// client or an unregistered redirect_uri can never reach a provider. A hint
// that does not resolve is not an error: the request falls through to the
// hosted login, which offers the same buttons.
//
// v1 does this in the browser: a Go filter serves an HTML page whose 400-line
// script re-reads the app config, matches the hint, stashes a PKCE verifier in
// sessionStorage, and posts the result back into a 1700-line login handler.
// The request is parked server-side here instead, so nothing the browser can
// edit decides where the hop goes or what it is worth on the way back.

// stateTTL bounds how long a parked authorize request stays claimable — long
// enough to sign in at the provider, short enough that an abandoned hop is not
// a standing credential.
const stateTTL = 10 * time.Minute

// ErrState — the handle names no live parked request: unknown, already claimed,
// or expired. One opaque reason: a prober learns nothing from the difference.
var ErrState = errors.New("oauth: the sign-in request expired or was already used")

// hint reads the provider hint. Two consumers spell it two ways — the console
// sends provider_hint, @hanzo/ui sends provider — so both are read, and the
// allowlist in authorizeForwardQuery keeps either from leaking onward to the
// hosted login.
func hint(c *zip.Ctx) string {
	if h := param(c, "provider_hint"); h != "" {
		return h
	}
	return param(c, "provider")
}

// pick resolves a hint to one of the application's provider links, or nil to
// fall through to the hosted login.
//
// The two consumers also name two different things: the console sends the
// ProviderItem NAME ("provider-github"), @hanzo/ui sends the provider TYPE
// ("google"). Matching either, case-insensitively, is the one rule that serves
// both. An ambiguous hint — one matching two different links — resolves to
// nothing rather than to a guess.
//
// A link only counts when it can actually complete: it must permit sign-in,
// hold a real credential, and name a provider iam2 connects to. An unusable
// hint falls through to the login page instead of dead-ending at a provider.
func pick(ctx context.Context, db orm.DB, app *schema.Application, h string) *schema.ProviderItem {
	store.EnrichProviders(ctx, db, app)
	var found *schema.ProviderItem
	for _, it := range app.Providers {
		if it == nil || it.Provider == nil || !it.CanSignIn {
			continue
		}
		if !strings.EqualFold(h, it.Name) && !strings.EqualFold(h, it.Provider.Type) {
			continue
		}
		if !isConfigured(it.Provider) || !idp.Supports(it.Provider.Type) {
			continue
		}
		if found != nil && found.Name != it.Name {
			return nil // ambiguous: never guess which provider was meant
		}
		found = it
	}
	return found
}

// hop parks the validated authorize request and redirects the browser to the
// provider. The upstream PKCE verifier stays here, on the parked row: v1 hands
// it to the browser, which is the one party the verifier is meant to bind.
func hop(c *zip.Ctx, db orm.DB, app *schema.Application, item *schema.ProviderItem, q authorizeRequest, method string) error {
	conn, err := idp.Open(item.Provider, tokenIssuer(c))
	if err != nil {
		return authorizeUserError(c, "internal error")
	}
	verifier, challenge := "", ""
	if item.Provider.EnablePkce {
		if verifier, err = newOpaqueToken(); err != nil {
			return authorizeUserError(c, "internal error")
		}
		challenge = ComputeS256Challenge(verifier)
	}
	handle, err := park(c.Context(), db, app, item, q, method, verifier)
	if err != nil {
		return authorizeUserError(c, "internal error")
	}
	return c.Redirect(302, conn.Auth(handle, challenge))
}

// park stores the validated authorize request while the browser is away and
// returns the opaque handle sent to the provider as `state`. The handle is
// unguessable and single-use, so a state echoed back is proof this server
// started the hop — v1's state is base64(the query string), which is neither.
//
// The row is a Token: a parked request and a minted code carry the same
// authorize parameters, so the same entity holds both. Their key spaces are
// disjoint by construction — a parked row's Code is EMPTY, so it is invisible
// to every redemption path (each short-circuits on an empty key), and a code
// row is refused by Claim. Without that, the handle the browser watches travel
// to the provider would be redeemable at the token endpoint as if it were a
// code.
func park(ctx context.Context, db orm.DB, app *schema.Application, item *schema.ProviderItem, q authorizeRequest, method, verifier string) (string, error) {
	handle, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	row := &schema.Token{
		Owner:        app.Owner,
		Name:         handle,
		Organization: app.Organization,
		Application:  app.Name,
		Provider:     item.Name,
		Verifier:     verifier,
		State:        q.state,
		Scope:        q.scope,
		Nonce:        q.nonce,
		RedirectUri:  q.redirectURI,
		Resource:     q.resource,
		// The application's own PKCE challenge: the code minted at the callback
		// binds to it, so the client that started the flow is the only one that
		// can redeem what comes back.
		CodeChallenge:       q.codeChallenge,
		CodeChallengeMethod: method,
		CodeExpireIn:        nowFunc().Add(stateTTL).Unix(),
	}
	if err := store.PersistToken(ctx, db, row); err != nil {
		return "", err
	}
	return handle, nil
}

// Claim consumes a parked authorize request by its handle and returns it. It is
// one-shot: the row is marked used before the caller acts on it, so a replayed
// state cannot drive a second exchange. A code row presented as a handle is
// refused — the two key spaces never meet.
func Claim(ctx context.Context, db orm.DB, handle string) (*schema.Token, error) {
	if handle == "" {
		return nil, ErrState
	}
	t, err := store.GetTokenByName(ctx, db, handle)
	if err != nil {
		return nil, err
	}
	if t == nil || t.Code != "" || t.CodeIsUsed || t.Provider == "" {
		return nil, ErrState
	}
	if t.CodeExpireIn != 0 && nowFunc().Unix() > t.CodeExpireIn {
		return nil, ErrState
	}
	t.CodeIsUsed = true
	if err := store.SaveToken(ctx, db, t); err != nil {
		return nil, err
	}
	return t, nil
}

// Origin is the server origin a hop's redirect URI is built from — the same
// value the issuer is derived from, so the callback the provider was given at
// the authorize hop and the one replayed at the exchange are the same bytes.
func Origin(c *zip.Ctx) string { return tokenIssuer(c) }
