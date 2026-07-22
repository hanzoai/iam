// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	fiber "github.com/zap-proto/fiber/v3"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
)

// Identity federation — iam2 as an OIDC/OAuth2 Relying Party to external IdPs.
//
// A social sign-in is a DETOUR inside the ordinary authorization-code flow. The
// authorize endpoint, having already validated the client and its EXACT
// redirect_uri (so there is a trusted target before anything is trusted), hands
// a request that names a `provider` to beginFederation, which stashes the whole
// app-leg request server-side and sends the browser to the IdP. When the IdP
// returns to the fixed callback, iam2 verifies the response, LINKS or PROVISIONS
// a local user, and mints ITS OWN authorization code — bound to the original
// PKCE challenge, redirect_uri, and nonce — exactly as a password login would.
// The relying party's existing PKCE code→token exchange then completes unchanged.
//
// The whole surface lives on the PUBLIC group (before the Guard): it
// self-authenticates through the single-use, browser-bound, expiring state, not
// a bearer. Every failure is fail-closed; no IdP token or secret is ever logged.

// PathFederationCallback is the fixed IdP return endpoint. One callback for every
// provider — the provider is recovered from the server-side transaction the
// state keys, never from a spoofable URL segment. It is the redirect_uri iam2
// registers with each external IdP.
const PathFederationCallback = "/v1/iam/oauth/callback"

// PathMfaVerify is the hosted 2FA PAGE (a route in the SPA, not an API path) the
// federation callback sends a second-factor-enrolled user's browser to. The page
// collects the factor and POSTs it to PathFederationMfa; the challenge id rides
// the httpOnly cookie the callback set, never a URL segment.
const PathMfaVerify = "/login/mfa"

// fedCookieName is the per-transaction anti-forgery cookie the begin leg sets and
// the callback checks — the browser binding that defeats login-CSRF.
const fedCookieName = "hanzo_fed"

// fedStateTTL bounds how long a federation transaction (and its cookie) is
// redeemable. Short, because it only has to survive one IdP round-trip.
const fedStateTTL = 10 * time.Minute

// routeFederation registers the IdP callback on the PUBLIC group r. GET only: the
// IdP returns via a top-level browser redirect (Google/GitHub), on which the
// SameSite=Lax browser-binding cookie IS sent. A cross-site form_post (POST) would
// NOT carry a Lax cookie, so the bind check would fail closed — rather than ship a
// half-working POST path, form_post support is a deliberate future change (it needs
// SameSite=None + its own CSRF analysis). The callback self-authenticates via the
// single-use state + the browser cookie.
func routeFederation(r zip.Router, db orm.DB) {
	r.Get(PathFederationCallback, federationCallbackHandler(db))
}

// beginFederation starts an Authorization-Code federation. It is entered from
// authorizeHandler ONLY after the client_id and exact redirect_uri are validated
// and the response_type/PKCE policy is enforced, so a protocol error may now be
// redirected to the trusted redirect_uri (RFC 6749 §4.1.2.1). It resolves the
// named provider, mints a single-use transaction, sets the browser-binding
// cookie, and sends the browser to the IdP.
func beginFederation(c *zip.Ctx, db orm.DB, app *schema.Application, q authorizeRequest, method string) error {
	ctx := c.Context()

	// A federated (external) identity may never be minted into a reserved system
	// org (the SuperAdmin vector) nor into a tenant an attacker-owned app has no
	// right to serve. Refuse BEFORE starting the round-trip (fail fast, no IdP
	// traffic) — defense in depth behind the application-write org authorization.
	if !federationOrgAllowed(app) {
		return authorizeErrorRedirect(c, q, "access_denied", "federation is not permitted for this application")
	}

	store.EnrichProviders(ctx, db, app)
	prov := federationProvider(app, q.provider)
	if prov == nil {
		return authorizeErrorRedirect(c, q, "invalid_request", "unknown or unavailable provider")
	}
	if idpKind(prov) == "" {
		return authorizeErrorRedirect(c, q, "invalid_request", "provider is not a supported federation type")
	}
	if _, ok := connectorFor(prov.Type); !ok {
		return authorizeErrorRedirect(c, q, "invalid_request", "provider has no local identity binding")
	}

	state, err := newOpaqueToken()
	if err != nil {
		return authorizeErrorRedirect(c, q, "server_error", "")
	}
	verifier, err := newOpaqueToken()
	if err != nil {
		return authorizeErrorRedirect(c, q, "server_error", "")
	}
	nonce, err := newOpaqueToken()
	if err != nil {
		return authorizeErrorRedirect(c, q, "server_error", "")
	}
	bindSecret, err := newOpaqueToken()
	if err != nil {
		return authorizeErrorRedirect(c, q, "server_error", "")
	}

	now := nowFunc()
	st := &schema.FederationState{
		Owner:               providerOwner(prov),
		Name:                state,
		CreatedTime:         now.UTC().Format(time.RFC3339),
		Provider:            prov.Name,
		ClientId:            q.clientID,
		RedirectUri:         q.redirectURI,
		AppState:            q.state,
		Scope:               q.scope,
		AppNonce:            q.nonce,
		CodeChallenge:       q.codeChallenge,
		CodeChallengeMethod: method,
		Resource:            q.resource,
		IdpVerifier:         verifier,
		IdpNonce:            nonce,
		BindHash:            hashToken(bindSecret),
		ExpireIn:            now.Add(fedStateTTL).Unix(),
	}

	// Build the IdP authorize URL BEFORE persisting so a discovery/config failure
	// never leaves an orphaned transaction row.
	idpURL, err := idpAuthorizeURL(ctx, prov, st, federationCallbackURL(c))
	if err != nil {
		return authorizeErrorRedirect(c, q, "temporarily_unavailable", "the identity provider is unavailable")
	}
	if err := store.PersistFederationState(ctx, db, st); err != nil {
		return authorizeErrorRedirect(c, q, "server_error", "")
	}
	setBindCookie(c, bindSecret)
	return c.Redirect(302, idpURL)
}

// federationCallbackHandler completes the round-trip: it resolves and burns the
// single-use transaction (checking expiry + browser binding), exchanges and
// verifies the IdP response, links or provisions the local user, and mints the
// iam2 authorization code the relying party expects — then redirects to the
// original redirect_uri with code + state.
func federationCallbackHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		ctx := c.Context()
		now := nowFunc()

		state := param(c, "state")
		if state == "" {
			return authorizeUserError(c, "missing state")
		}
		st, err := store.GetFederationState(ctx, db, state)
		if err != nil {
			return authorizeUserError(c, "internal error")
		}
		// Until the state resolves there is NO trusted redirect target, so an
		// invalid/expired/replayed state is answered in place, never redirected.
		if st == nil || st.Used || (st.ExpireIn != 0 && now.Unix() > st.ExpireIn) {
			return authorizeUserError(c, "the federation session is invalid or expired")
		}
		// Browser binding: the callback must present the same anti-forgery cookie
		// the begin leg set in THIS browser (constant-time) — the login-CSRF /
		// session-fixation defense. A stolen or injected state without the cookie
		// stops here.
		raw := readBindCookie(c)
		if raw == "" || subtle.ConstantTimeCompare([]byte(hashToken(raw)), []byte(st.BindHash)) != 1 {
			return authorizeUserError(c, "the federation session could not be verified")
		}
		// Burn the transaction now (single-use). A concurrent replay reads Used and
		// loses; a later replay finds nothing.
		st.Used = true
		if err := store.SaveFederationState(ctx, db, st); err != nil {
			return authorizeUserError(c, "internal error")
		}
		clearBindCookie(c)

		// Resolve the relying-party app (the trusted redirect target) and re-check
		// its redirect_uri against the live allow-list — never trust the stored
		// value blindly (defense in depth against a tampered row).
		app, err := store.GetApplicationByClientId(ctx, db, st.ClientId)
		if err != nil || app == nil {
			return authorizeUserError(c, "the client application is unavailable")
		}
		if !app.IsRedirectUriValid(st.RedirectUri) {
			return authorizeUserError(c, "invalid redirect_uri")
		}
		// Re-assert the reserved-org / tenant-legitimacy gate at the mint boundary,
		// never trusting that the begin leg still holds or that the app row is honest.
		if !federationOrgAllowed(app) {
			return fedErrorRedirect(c, st, "access_denied", "federation is not permitted for this application")
		}
		prov, err := store.GetProvider(ctx, db, st.Owner, st.Provider)
		if err != nil || prov == nil {
			return fedErrorRedirect(c, st, "temporarily_unavailable", "the identity provider is unavailable")
		}

		// An IdP-reported denial (user declined / error) is surfaced to the RP as
		// access_denied, not a server error.
		if e := param(c, "error"); e != "" {
			return fedErrorRedirect(c, st, "access_denied", "the identity provider denied the request")
		}
		code := param(c, "code")
		if code == "" {
			return fedErrorRedirect(c, st, "invalid_request", "the identity provider returned no code")
		}

		identity, err := idpExchange(ctx, prov, st, code, federationCallbackURL(c), now)
		if err != nil || identity.subject == "" {
			return fedErrorRedirect(c, st, "access_denied", "the identity provider could not be verified")
		}

		user, err := linkOrProvision(ctx, db, app, prov, identity)
		if err != nil {
			return fedErrorRedirect(c, st, "server_error", "")
		}
		if user.IsForbidden || user.IsDeleted {
			return fedErrorRedirect(c, st, "access_denied", "the account is not permitted")
		}

		// The resume parameters — the ORIGINAL authorize request — pinned so the mint
		// (now, or after a second factor) uses exactly these and nothing a later
		// request could supply.
		p := fedResumeParams{
			ClientId:            st.ClientId,
			RedirectUri:         st.RedirectUri,
			AppState:            st.AppState,
			Scope:               st.Scope,
			AppNonce:            st.AppNonce,
			CodeChallenge:       st.CodeChallenge,
			CodeChallengeMethod: st.CodeChallengeMethod,
			Resource:            st.Resource,
		}

		// Second-factor gate: a federated login must NOT skip the factor a password
		// login would demand (the MFA gate, mfa_gate.go). If the resolved user owes a
		// factor, mint NOTHING here — park the resume, bound to the user and these
		// pinned params, and send the browser to the hosted 2FA page.
		org, err := store.GetOrganizationByName(ctx, db, user.Owner)
		if err != nil {
			return fedErrorRedirect(c, st, "server_error", "")
		}
		if factor.Prompt(org, user) {
			// The organization requires a factor this federated user has not enrolled;
			// a federated login cannot enroll one inline, so it fails closed.
			return fedErrorRedirect(c, st, "access_denied", "two-factor authentication must be set up before signing in")
		}
		if factor.Enabled(user) && !remembered(user, now) {
			return federationChallenge(c, db, st, user, p, now)
		}

		// No second factor owed — complete exactly as before, through the one mint.
		loc, err := federationMint(ctx, db, app, user, p, now)
		if err != nil {
			return fedMintErrorRedirect(c, st, err)
		}
		return c.Redirect(302, loc)
	}
}

// fedResumeParams is the ORIGINAL iam2 authorize request, pinned server-side so
// the code minted after a federated login (immediately, or after a second factor)
// binds to exactly these values — never to anything a later request supplies.
type fedResumeParams struct {
	ClientId            string `json:"clientId"`
	RedirectUri         string `json:"redirectUri"`
	AppState            string `json:"appState"`
	Scope               string `json:"scope"`
	AppNonce            string `json:"appNonce"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	Resource            string `json:"resource"`
}

// errPKCERequired is the one distinguished mint error a caller maps to an OAuth
// invalid_request; every other mint failure is an opaque server_error.
var errPKCERequired = errors.New("federation: PKCE is required for public clients")

// federationMint mints iam2's own authorization code — the SAME artifact a
// password login mints — bound to the pinned app-leg PKCE, redirect_uri and nonce,
// and returns the RP redirect (redirect_uri?code&state). It is the ONE mint path
// both the no-factor completion and the post-2FA resume reach, so a federated code
// can never be minted two different ways.
func federationMint(ctx context.Context, db orm.DB, app *schema.Application, user *schema.User, p fedResumeParams, now time.Time) (string, error) {
	// A public client must have carried a PKCE challenge, re-asserted at the mint so
	// a minted code is never redeemable without proof.
	if app.ClientSecret == "" && p.CodeChallenge == "" {
		return "", errPKCERequired
	}
	userID := user.Owner + "/" + user.Name
	codeRow, err := MintCode(app, userID, p.Scope, p.CodeChallenge, p.CodeChallengeMethod, p.Resource, now)
	if err != nil {
		return "", err
	}
	codeRow.RedirectUri = p.RedirectUri
	codeRow.Nonce = p.AppNonce
	if err := store.PersistToken(ctx, db, codeRow); err != nil {
		return "", err
	}
	v := url.Values{}
	v.Set("code", codeRow.Code)
	setIfPresent(v, "state", p.AppState)
	return joinQuery(p.RedirectUri, v), nil
}

// federationChallenge parks a resolved-but-not-yet-second-factored federated login.
// The pending state IS a LoginChallenge (KindFederation) — the same single-use,
// expiring, subject-pinned lifecycle the password MFA gate uses, so there is ONE
// challenge concept — carrying the resume params as its payload. The browser is
// sent to the hosted 2FA page; the challenge id rides the httpOnly cookie, never a
// URL segment.
func federationChallenge(c *zip.Ctx, db orm.DB, st *schema.FederationState, user *schema.User, p fedResumeParams, now time.Time) error {
	payload, err := json.Marshal(p)
	if err != nil {
		return fedErrorRedirect(c, st, "server_error", "")
	}
	id, err := MintChallenge(c.Context(), db, KindFederation, user.Owner+"/"+user.Name, string(payload), now)
	if err != nil {
		return fedErrorRedirect(c, st, "server_error", "")
	}
	SetChallenge(c, id)
	return c.Redirect(302, federationBaseURL(c)+PathMfaVerify)
}

// fedMintErrorRedirect maps a federationMint error to the RP redirect_uri.
func fedMintErrorRedirect(c *zip.Ctx, st *schema.FederationState, err error) error {
	if err == errPKCERequired {
		return fedErrorRedirect(c, st, "invalid_request", "PKCE is required for public clients")
	}
	return fedErrorRedirect(c, st, "server_error", "")
}

// linkOrProvision resolves the local identity for a verified federated login,
// PROVISION-DON'T-PROMOTE: (1) an account already linked to this provider
// subject, else (2) an existing account matched by a VERIFIED IdP email (linked
// now), else (3) a freshly provisioned account. It NEVER sets isAdmin and never
// grants an existing account anything — federation only authenticates.
func linkOrProvision(ctx context.Context, db orm.DB, app *schema.Application, prov *schema.Provider, id federatedIdentity) (*schema.User, error) {
	// Innermost guard on the mint itself: never provision/link a federated identity
	// into a reserved system org (SuperAdmin) or a tenant this app may not serve.
	// This layer assumes the two before it (app-write authorization + the begin/
	// callback checks) both failed.
	if !federationOrgAllowed(app) {
		return nil, errors.New("federation: provisioning into this organization is not permitted")
	}
	org := app.Organization
	binding, ok := connectorFor(prov.Type)
	if !ok {
		return nil, errors.New("federation: provider has no local identity binding")
	}

	// 1. Already linked by the provider's stable subject — the authoritative match
	// for a returning federated user (immune to email churn/ambiguity).
	if u, err := store.GetUserByConnector(ctx, db, org, binding.field, id.subject); err != nil {
		return nil, err
	} else if u != nil {
		return u, nil
	}

	// 2. Link to an existing account ONLY on a VERIFIED IdP email. An unverified
	// email never links (it would let an unproven address take over an account).
	if id.emailVerified && id.email != "" {
		if u, err := store.GetUserByEmail(ctx, db, org, id.email); err != nil {
			return nil, err
		} else if u != nil {
			*binding.ref(u) = id.subject
			u.EmailVerified = true
			if err := saveUser(ctx, db, u); err != nil {
				return nil, err
			}
			return u, nil
		}
	}

	// 3. Provision a fresh account. Federated accounts carry NO password (the
	// digest stays empty, so password login fails closed) and are never admin.
	return provisionFederatedUser(ctx, db, app, prov, binding, id)
}

// provisionFederatedUser creates a new federated account through the ONE
// canonical user-create path (users.Create, no password → no login-able digest),
// stamping the provider subject on its connector column. The username is
// system-generated and collision-checked; the email's verified flag is carried
// straight from the IdP.
func provisionFederatedUser(ctx context.Context, db orm.DB, app *schema.Application, prov *schema.Provider, binding connectorBinding, id federatedIdentity) (*schema.User, error) {
	org := app.Organization
	for attempt := 0; attempt < 4; attempt++ {
		name := federatedUsername(id.email, prov.Type)
		taken, err := userExists(ctx, db, org, name)
		if err != nil {
			return nil, err
		}
		if taken {
			continue
		}
		u := schema.User{
			Owner:             org,
			Name:              name,
			Type:              "normal-user",
			DisplayName:       firstNonEmpty(id.displayName, name),
			Email:             id.email,
			EmailVerified:     id.emailVerified,
			Avatar:            id.avatar,
			SignupApplication: app.Name,
			RegisterType:      "Federation",
			RegisterSource:    org + "/" + prov.Name,
		}
		*binding.ref(&u) = id.subject
		return users.New(db).Create(ctx, &users.CreateInput{User: u})
	}
	return nil, errors.New("federation: could not allocate a unique username")
}

// federationProvider resolves the app's ProviderItem named name to its shared
// Provider record, requiring the link to be sign-in-enabled and configured with
// real credentials — otherwise the request never dead-ends at the IdP.
func federationProvider(app *schema.Application, name string) *schema.Provider {
	if name == "" {
		return nil
	}
	for _, it := range app.Providers {
		if it == nil || it.Name != name || !it.CanSignIn || it.Provider == nil {
			continue
		}
		if !isConfigured(it.Provider) {
			continue
		}
		return it.Provider
	}
	return nil
}

// providerOwner is the Provider record's owner, defaulting to the admin org where
// providers are seeded.
func providerOwner(p *schema.Provider) string {
	if p.Owner != "" {
		return p.Owner
	}
	return "admin"
}

// federationCallbackURL is the iam2 callback iam2 registers with the IdP and
// re-presents at the token exchange. It is PINNED from config, never steered by a
// request header, so an attacker cannot redirect the IdP leg via X-Forwarded-Host.
func federationCallbackURL(c *zip.Ctx) string {
	return federationBaseURL(c) + PathFederationCallback
}

// federationBaseURL is the pinned public origin the IdP callback is registered
// under — the SAME per-brand issuer the tokens carry, resolved through the ONE
// issuer resolver (issuer.go) keyed on the TRUSTED request host (c.Host(), which
// ignores X-Forwarded-Host). So a brand's federation callback is registered at
// that brand's pinned origin, header-immune and never steered to an attacker
// origin. See resolveIssuer for the fail-closed resolution order.
func federationBaseURL(c *zip.Ctx) string {
	return resolveIssuer(c.Host())
}

// federationOrgAllowed reports whether a federated (external) identity may be
// provisioned or linked into the application's Organization. Two invariants,
// both fail-closed:
//
//  1. NEVER a reserved system org (admin/built-in/app). A social sign-in that
//     landed a user in the admin org would make that user a SuperAdmin — the
//     critical escalation. Federation is customer sign-in; system orgs are seeded
//     / onboarded / SuperAdmin-managed, never reached by an external login.
//  2. Tenant legitimacy. A platform app (admin/built-in-owned, and thus only
//     SuperAdmin-creatable) may serve any non-reserved tenant. A tenant-registered
//     app may only land users in the org it legitimately serves — its OWN org, a
//     shared app, or one with an explicit org-choice mode — mirroring the
//     login/signup tenant gate, so an attacker-owned app cannot mint or link
//     identities into a victim tenant.
//
// This is defense in depth behind the application-write authorization (authz
// authorizes the Organization field on create/update); this layer assumes that
// one was bypassed and still refuses the escalation.
func federationOrgAllowed(app *schema.Application) bool {
	org := strings.TrimSpace(app.Organization)
	if org == "" || store.IsReservedOrg(org) {
		return false
	}
	if store.IsSigningCertOwner(app.Owner) {
		return true // platform app — SuperAdmin-configured, may serve any tenant
	}
	if app.IsShared || app.OrgChoiceMode != "" {
		return true
	}
	return org == app.Owner
}

// fedSuccessRedirect returns the browser to the relying party's redirect_uri with
// the iam2 authorization code and the original app state (RFC 6749 §4.1.2).
func fedSuccessRedirect(c *zip.Ctx, st *schema.FederationState, code string) error {
	v := url.Values{}
	v.Set("code", code)
	setIfPresent(v, "state", st.AppState)
	return c.Redirect(302, joinQuery(st.RedirectUri, v))
}

// fedErrorRedirect returns an OAuth error to the relying party's redirect_uri
// (already allow-list-validated) with the original app state.
func fedErrorRedirect(c *zip.Ctx, st *schema.FederationState, code, desc string) error {
	v := url.Values{}
	v.Set("error", code)
	setIfPresent(v, "error_description", desc)
	setIfPresent(v, "state", st.AppState)
	return c.Redirect(302, joinQuery(st.RedirectUri, v))
}

// setBindCookie writes the per-transaction anti-forgery cookie: HttpOnly + Secure,
// SameSite=Lax (so it IS sent on the IdP's top-level GET back to the callback),
// scoped to the callback path, expiring with the transaction.
func setBindCookie(c *zip.Ctx, value string) {
	c.Fiber().Cookie(&fiber.Cookie{
		Name:     fedCookieName,
		Value:    value,
		Path:     PathFederationCallback,
		MaxAge:   int(fedStateTTL / time.Second),
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// readBindCookie returns the anti-forgery cookie value, or "" when absent.
func readBindCookie(c *zip.Ctx) string { return c.Fiber().Cookies(fedCookieName) }

// clearBindCookie expires the anti-forgery cookie once the transaction is
// consumed, so it can never be replayed.
func clearBindCookie(c *zip.Ctx) {
	c.Fiber().Cookie(&fiber.Cookie{
		Name:     fedCookieName,
		Value:    "",
		Path:     PathFederationCallback,
		MaxAge:   -1,
		Secure:   true,
		HTTPOnly: true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// connectorBinding ties a provider type to the User's per-connector identity
// column: the EXACT lowercase orm/json field name to filter on and a pointer
// accessor to read/set the stored subject.
type connectorBinding struct {
	field string
	ref   func(*schema.User) *string
}

// connectorRegistry maps a provider Type to its User connector column. The field
// name is the EXACT json/orm name (already lowercase): orm's filter lowercases
// only the FIRST rune, so a Go field name like "GitHub" would query '$.gitHub'
// (the tag is 'github') — passing the exact json name is the one correct way, and
// this registry is its single source of truth. Only the connectors iam2 can
// federate are listed; anything else fails closed.
var connectorRegistry = map[string]connectorBinding{
	"google":          {"google", func(u *schema.User) *string { return &u.Google }},
	"github":          {"github", func(u *schema.User) *string { return &u.GitHub }},
	"gitlab":          {"gitlab", func(u *schema.User) *string { return &u.Gitlab }},
	"gitee":           {"gitee", func(u *schema.User) *string { return &u.Gitee }},
	"bitbucket":       {"bitbucket", func(u *schema.User) *string { return &u.Bitbucket }},
	"facebook":        {"facebook", func(u *schema.User) *string { return &u.Facebook }},
	"apple":           {"apple", func(u *schema.User) *string { return &u.Apple }},
	"linkedin":        {"linkedin", func(u *schema.User) *string { return &u.LinkedIn }},
	"discord":         {"discord", func(u *schema.User) *string { return &u.Discord }},
	"slack":           {"slack", func(u *schema.User) *string { return &u.Slack }},
	"okta":            {"okta", func(u *schema.User) *string { return &u.Okta }},
	"azuread":         {"azuread", func(u *schema.User) *string { return &u.AzureAD }},
	"microsoftonline": {"microsoftonline", func(u *schema.User) *string { return &u.MicrosoftOnline }},
}

// connectorFor resolves the connector binding for a provider type (case-folded),
// or (zero, false) when the type has no local identity column.
func connectorFor(providerType string) (connectorBinding, bool) {
	b, ok := connectorRegistry[strings.ToLower(strings.TrimSpace(providerType))]
	return b, ok
}

// federatedUsername generates a valid, human-friendly, collision-resistant
// username for a provisioned account: the email local-part (or provider name)
// sanitized to a handle, guaranteed to start with a letter (so it passes the
// username policy), plus a random suffix so concurrent provisions never collide.
func federatedUsername(email, providerType string) string {
	base := ""
	if at := strings.IndexByte(email, '@'); at > 0 {
		base = email[:at]
	}
	base = sanitizeHandle(base)
	if base == "" {
		base = sanitizeHandle(providerType)
	}
	if base == "" {
		base = "user"
	}
	if base[0] < 'a' || base[0] > 'z' {
		base = "u" + base
	}
	return base + "-" + randHex(4)
}

// randHex returns 2n lowercase hex chars of cryptographic randomness.
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// sanitizeHandle reduces s to a lowercase [a-z0-9._-] handle, capped at 24 chars.
func sanitizeHandle(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '-' {
			out = append(out, ch)
		}
	}
	if len(out) > 24 {
		out = out[:24]
	}
	return string(out)
}
