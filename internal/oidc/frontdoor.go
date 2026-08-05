// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Front-door JSON endpoints the @hanzo/iam SDK + hanzo.id portal call: the login
// UI descriptors (auth/application, auth/methods), the account read (account),
// account creation (signup), and OTP send (verification-codes). Login itself is
// routeLogin; the OIDC/OAuth surface is Route. The verb-noun spellings four of
// these once had are in canonical.go, still reachable and taught nowhere.
const PathAuthMethods = "/v1/iam/auth/methods"

// routeFrontDoor registers the front-door endpoints the hosted hanzo.id portal
// and the @hanzo/iam SDK call, on the PUBLIC group r. Each handler RESOLVES the
// caller itself (callerOf: session cookie first, then bearer) and SELF-SCOPES to
// that caller, so — like the rest of this group — they are reachable without a
// Guard-verified bearer yet never act on anyone but the resolved caller.
func routeFrontDoor(r *zip.App, db orm.DB) {
	// The two login-screen descriptors are TYPED ops. Their whole input is a client
	// id off the query string and their answer is this envelope, so nothing about
	// them needed a raw handler — and a raw handler is what kept them out of the
	// schema, the MCP tool list, the CLI and every generated SDK. Registered on the
	// PUBLIC group, which carries no op-invoke authorizer, so typing them changes
	// what they PUBLISH and nothing about who may call them.
	//
	// The older spelling of the first is the SAME op at its legacy address, so one
	// function decides both answers and they cannot drift.
	//
	// It carries the same tag as its canonical twin rather than "compat", and that
	// is a deliberate limit on the blast radius of a TYPING change. The compat tag
	// is how an address is kept OUT of the published document, and this address is
	// in it today — as an untyped route, which has no way to say compat. Tagging it
	// now would delete a published path, and a published path that disappears is
	// what cloud's per-product floor exists to refuse. Retiring the spelling is a
	// surface decision that lowers that floor in the same commit; this is not that
	// commit.
	zip.Get[screen, httpx.Answer](r, PathAuthApplication, getAppLogin(db),
		zip.WithStatus(200, 400), zip.WithTags("auth"))
	zip.Get[screen, httpx.Answer](r, LegacyPathAuthApplication, getAppLogin(db),
		zip.WithStatus(200, 400), zip.WithTags("auth"))
	zip.Get[offer, httpx.Answer](r, PathAuthMethods, authMethods(db),
		zip.WithStatus(200, 400), zip.WithTags("auth"))
	// The account read is anonymous-safe (returns {status:"error"} unauthenticated)
	// and a security contract — the gateway admin-guard reads its `owner`.
	zip.Alias(r.Get, PathAccount, LegacyPathAccount, getAccount(db))
	// Account creation + email/phone OTP send. signup is JSON; the OTP send is
	// multipart/form-data (HIP-0111 §4 invariant), read via fiber's FormValue.
	r.Post(PathSignup, signupHandler(db))
	zip.Alias(r.Post, PathVerificationCodes, LegacyPathVerificationCodes, sendVerificationCode(db))

	// The session/identity front door the console drives once a user is signed in:
	// signin (the code→session exchange), whoami (lightweight identity), onboard
	// (first-run org creation + move), preferences (self, shallow-merge), and
	// linked-accounts (the caller's linked identities).
	r.Post(PathSignin, signinHandler(db))
	r.Get(PathWhoami, whoamiHandler(db))
	r.Post(PathOnboard, onboardHandler(db))
	// Service-token admin provision: the ONE atomic op the cloud onboarding
	// orchestrator calls (on behalf of a named user) instead of a create-org +
	// move-user pair. Self-authenticates via the unified service token.
	r.Post(PathProvision, provisionServiceHandler(db))
	zip.Alias(r.Post, PathPreferences, LegacyPathPreferences, updatePreferencesHandler(db))
	// Account-canonical data-sharing consent (insights + opt-in training) — the ONE
	// source of truth the hanzo.id signup, the browser extension, and hanzo.ai share.
	r.Get(PathConsent, getConsentHandler(db))
	r.Put(PathConsent, putConsentHandler(db))
	r.Get(PathLinkedAccounts, linkedAccountsHandler(db))
}

// getAppLogin returns everything a login screen needs to draw itself for one
// application: its branding, and each sign-in method it offers with the provider
// details that method needs.
//
// The client secret is masked. Read before anyone has signed in, so it carries
// only what is safe for a browser to see.
func getAppLogin(db orm.DB) zip.TypedHandler[screen, httpx.Answer] {
	return func(ctx context.Context, in *screen) (*httpx.Answer, error) {
		if in.ResponseType != "" && in.ResponseType != "code" {
			return httpx.Bad(400, "response_type is required (must be code)", ""), nil
		}
		if in.ClientId == "" {
			return httpx.Bad(400, "clientId is required", ""), nil
		}
		app, err := store.GetApplicationByClientId(ctx, db, in.ClientId)
		if err != nil {
			return httpx.Bad(400, err.Error(), ""), nil
		}
		if app == nil {
			return httpx.Bad(400, "the application does not exist", ""), nil
		}
		store.EnrichProviders(ctx, db, app)
		return httpx.Good(loginView(app)), nil
	}
}

// authMethods returns the sign-in methods one application actually has switched
// on, so a login screen can render the right buttons for it without you
// hard-coding a list that drifts the moment you add a provider.
//
// Public by design: it is read before anyone has signed in, and it exposes only
// which methods exist, never their credentials.
func authMethods(db orm.DB) zip.TypedHandler[offer, httpx.Answer] {
	return func(ctx context.Context, in *offer) (*httpx.Answer, error) {
		if in.ClientId == "" {
			return httpx.Bad(400, "clientId is required", ""), nil
		}
		app, err := store.GetApplicationByClientId(ctx, db, in.ClientId)
		if err != nil {
			return httpx.Bad(400, err.Error(), ""), nil
		}
		if app == nil {
			return httpx.Bad(400, "the application does not exist", ""), nil
		}
		store.EnrichProviders(ctx, db, app)

		oauth := []map[string]string{}
		for _, it := range app.Providers {
			if it == nil || it.Provider == nil || !it.CanSignIn {
				continue
			}
			if !offerable(it.Provider) {
				continue // hidden until real creds land — never a dead-end button
			}
			if strings.EqualFold(it.Provider.Category, "oauth") {
				oauth = append(oauth, map[string]string{
					"name": it.Name,
					"type": it.Provider.Type,
					"logo": it.Provider.CustomLogo,
				})
			}
		}

		// Wallet sign-in is a capability of THIS BINARY, not of an application's
		// provider list, so it is asked of the package that serves it. It used to
		// be read off a linked provider of category "web3" — the seeded
		// Web3Onboard row, whose clientId is the unexpanded literal
		// `${IAM_WEB3_CLIENT_ID}` and which names a third-party library this build
		// does not import. So every login screen reported web3:false while
		// /v1/iam/web3/nonce answered on seven chain families, and the flag tracked
		// a row that governed nothing.
		//
		// The chain list is the SAME one the nonce/verify endpoints gate on, so a
		// screen cannot offer a chain the endpoint refuses.
		names := schema.WalletChains()
		return httpx.Good(map[string]any{
			"password": app.EnablePassword,
			// Offered only when a code can actually be delivered. The app switch says
			// the org WANTS email/SMS codes; DeliveryConfigured says the server can
			// send one. Both must hold, or the screen shows a method that ends in a
			// person waiting for a message nobody sent.
			"code":     app.EnableCodeSignin && DeliveryConfigured(),
			"webauthn": app.EnableWebAuthn,
			"web3":     len(names) > 0,
			// The families a wallet may sign in with, so a screen can render the
			// right options instead of hardcoding a list that drifts from the
			// verifier. Additive: `web3` stays the boolean every client reads.
			"web3Chains": names,
			"oauth":      oauth,
			"signup":     app.EnableSignUp,
		}), nil
	}
}

// screen is what a login screen names when it asks how to draw itself: the
// application, and the OAuth response type it intends to use.
type screen struct {
	// ClientId is the application's OAuth client id — the one field that selects
	// which login screen this is.
	ClientId string `json:"clientId"`
	// ResponseType is the OAuth response type the screen will ask for. Only "code"
	// is served; anything else is refused here rather than at the authorize leg,
	// where the person has already typed a password.
	ResponseType string `json:"responseType"`
}

// offer is the application whose enabled sign-in methods are being asked for.
type offer struct {
	// ClientId is the application's OAuth client id.
	ClientId string `json:"clientId"`
}

// offerable reports whether a provider can actually COMPLETE a sign-in, which is
// the only honest reason to draw a button for it. A method fails that in two
// independent ways, and checking only the first is what put dead buttons on the
// login screen:
//
//   - NO REAL CREDENTIAL — a placeholder client id, never filled in.
//   - NO DIALECT THAT CAN DRIVE IT. idpKind is the ONE authority for "can we
//     federate this?", and it is what the authorize leg already consults. GitLab
//     is the live example: a real-looking client id passes the credential check,
//     so the button rendered, and then beginFederation refused it with "provider
//     is not a supported federation type". The button existed only to fail.
//
// Both callers now ask THIS question — the login screen and the authorize leg —
// so what is offered and what is driveable can no longer disagree. Give GitLab an
// issuerUrl and it becomes a real OIDC provider here and its button returns, with
// nothing else to change.
//
// Web3 is exempt from the dialect check because it never reaches the federation
// broker at all: it is native challenge/response with no OAuth client.
func offerable(p *schema.Provider) bool {
	if p == nil {
		return false
	}
	// Web3 is native challenge/response — no OAuth client to configure.
	if strings.EqualFold(p.Category, "Web3") {
		return true
	}
	if idpKind(p) == "" {
		return false
	}
	id := strings.ToLower(strings.TrimSpace(p.ClientId))
	if id == "" {
		return false
	}
	return !strings.Contains(id, "placeholder") &&
		!strings.HasPrefix(id, "your-") &&
		!strings.HasPrefix(id, "xxx") &&
		!strings.Contains(id, "change")
}

// loginView returns what a login screen may see of an application: no secrets,
// and no sign-in method that cannot complete.
//
// Both halves are here because this response IS the login screen's source of
// truth — the SDK calls it "the canonical source of truth for which methods
// exist" — so a provider present here is a button rendered. It previously
// answered with EVERY provider while /v1/iam/auth/methods answered with the
// offerable ones: two endpoints, two answers to one question, and the browser
// read the unfiltered one. Filtering here is what makes them agree.
func loginView(app *schema.Application) *schema.Application {
	if app == nil {
		return nil
	}
	view := *app
	view.ClientSecret = ""
	// Same rule as the provider list below: this response IS the login screen's
	// source of truth, so a switch left on for a method the server cannot perform
	// would draw the button anyway. The org's stored setting is untouched — only
	// what the browser is told.
	view.EnableCodeSignin = view.EnableCodeSignin && DeliveryConfigured()
	kept := make([]*schema.ProviderItem, 0, len(view.Providers))
	for _, it := range view.Providers {
		if it == nil || it.Provider == nil || !offerable(it.Provider) {
			continue
		}
		p := *it.Provider
		p.ClientSecret = ""
		p.ClientSecret2 = ""
		item := *it
		item.Provider = &p
		kept = append(kept, &item)
	}
	view.Providers = kept
	return &view
}
