// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"strings"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// Front-door JSON endpoints the @hanzo/iam SDK + hanzo.id portal call: the login
// UI descriptors (get-app-login, auth/methods), the account read (get-account),
// account creation (signup), and OTP send (send-verification-code). Login itself
// is routeLogin; the OIDC/OAuth surface is Route.
const (
	PathGetAppLogin = "/v1/iam/get-app-login"
	PathAuthMethods = "/v1/iam/auth/methods"
)

// routeFrontDoor registers the front-door endpoints the hosted hanzo.id portal
// and the @hanzo/iam SDK call, on the PUBLIC group r. Each handler RESOLVES the
// caller itself (callerOf: session cookie first, then bearer) and SELF-SCOPES to
// that caller, so — like the rest of this group — they are reachable without a
// Guard-verified bearer yet never act on anyone but the resolved caller.
func routeFrontDoor(r zip.Router, db orm.DB) {
	r.Get(PathGetAppLogin, getAppLogin(db))
	r.Get(PathAuthMethods, authMethods(db))
	// get-account is anonymous-safe (returns {status:"error"} unauthenticated)
	// and a security contract — the gateway admin-guard reads its `owner`.
	r.Get(PathGetAccount, getAccount(db))
	// Account creation + email/phone OTP send. signup is JSON; send-verification-code
	// is multipart/form-data (HIP-0111 §4 invariant), read via fiber's FormValue.
	r.Post(PathSignup, signupHandler(db))
	r.Post(PathSendVerificationCode, sendVerificationCode(db))

	// The session/identity front door the console drives once a user is signed in:
	// signin (the code→session exchange), whoami (lightweight identity), onboard
	// (first-run org creation + move), update-preferences (self, shallow-merge), and
	// linked-accounts (the caller's linked identities).
	r.Post(PathSignin, signinHandler(db))
	r.Get(PathWhoami, whoamiHandler(db))
	r.Post(PathOnboard, onboardHandler(db))
	// Service-token admin provision: the ONE atomic op the cloud onboarding
	// orchestrator calls (on behalf of a named user) instead of a create-org +
	// move-user pair. Self-authenticates via the unified service token.
	r.Post(PathProvision, provisionServiceHandler(db))
	r.Post(PathUpdatePreferences, updatePreferencesHandler(db))
	// Account-canonical data-sharing consent (insights + opt-in training) — the ONE
	// source of truth the hanzo.id signup, the browser extension, and hanzo.ai share.
	r.Get(PathConsent, getConsentHandler(db))
	r.Put(PathConsent, putConsentHandler(db))
	r.Get(PathLinkedAccounts, linkedAccountsHandler(db))
}

// getAppLogin resolves an application by clientId and returns it with the
// ClientSecret masked and each provider link enriched with its shared provider
// record — the canonical source of truth the login UI reads to decide which
// sign-in methods to render. Mirrors the v1 Casdoor get-app-login contract
// (Response envelope, data = the masked application).
func getAppLogin(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		if rt := c.Query("responseType"); rt != "" && rt != "code" {
			return httpx.Err(c, "response_type is required (must be code)")
		}
		clientId := c.Query("clientId")
		if clientId == "" {
			return httpx.Err(c, "clientId is required")
		}
		app, err := store.GetApplicationByClientId(c.Context(), db, clientId)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if app == nil {
			return httpx.Err(c, "the application does not exist")
		}
		store.EnrichProviders(c.Context(), db, app)
		return httpx.Ok(c, maskApp(app))
	}
}

// authMethods reports the enabled sign-in methods for an application so the SDK
// <Login> self-configures instead of hard-coding a provider list. This endpoint
// does NOT exist in v1 — it is the clean seam that lets one <Login> render the
// right buttons for any app. Pure read over the resolved application.
func authMethods(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		clientId := c.Query("clientId")
		if clientId == "" {
			return httpx.Err(c, "clientId is required")
		}
		app, err := store.GetApplicationByClientId(c.Context(), db, clientId)
		if err != nil {
			return httpx.Err(c, err.Error())
		}
		if app == nil {
			return httpx.Err(c, "the application does not exist")
		}
		store.EnrichProviders(c.Context(), db, app)

		oauth := []map[string]string{}
		web3 := false
		for _, it := range app.Providers {
			if it == nil || it.Provider == nil || !it.CanSignIn {
				continue
			}
			if !isConfigured(it.Provider) {
				continue // hidden until real creds land — never a dead-end button
			}
			switch strings.ToLower(it.Provider.Category) {
			case "web3":
				web3 = true
			case "oauth":
				oauth = append(oauth, map[string]string{
					"name": it.Name,
					"type": it.Provider.Type,
					"logo": it.Provider.CustomLogo,
				})
			}
		}
		return httpx.Ok(c, map[string]any{
			"password": app.EnablePassword,
			"code":     app.EnableCodeSignin,
			"webauthn": app.EnableWebAuthn,
			"web3":     web3,
			"oauth":    oauth,
			"signup":   app.EnableSignUp,
		})
	}
}

// isConfigured reports whether a provider holds a real (non-placeholder)
// credential — the guard that keeps an unconfigured provider's button hidden so
// it never dead-ends the OAuth redirect.
func isConfigured(p *schema.Provider) bool {
	if p == nil {
		return false
	}
	// Web3 is native challenge/response — no OAuth client to configure.
	if strings.EqualFold(p.Category, "Web3") {
		return true
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

// maskApp returns a copy-safe view of the application with the client secret and
// every provider's secret removed — get-app-login is called by the browser, so
// no secret may cross it.
func maskApp(app *schema.Application) *schema.Application {
	if app == nil {
		return nil
	}
	masked := *app
	masked.ClientSecret = ""
	for _, it := range masked.Providers {
		if it != nil && it.Provider != nil {
			p := *it.Provider
			p.ClientSecret = ""
			p.ClientSecret2 = ""
			it.Provider = &p
		}
	}
	return &masked
}
