// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
)

// The token endpoint: POST /v1/iam/oauth/token. It dispatches the three grant
// types iam2 issues — authorization_code (PKCE-verified, single-use code →
// access JWT + id_token when openid + rotating refresh), refresh_token
// (rotation with reuse detection, refresh.go), and client_credentials
// (machine-to-machine, no user, no refresh). Every response carries no-store
// caching; every error follows the RFC 6749 §5.2 taxonomy (invalid_client → 401
// with WWW-Authenticate, everything else → 400). Implicit is permanently absent.

// nowFunc is indirected so tests can pin time. Production uses time.Now.
var nowFunc = time.Now

// tokenResponse is the RFC 6749 §5.1 / OIDC success body.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	IdToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

// routeToken registers the ONE token endpoint: POST /v1/iam/oauth/token (the
// RFC 6749 / discovery `token_endpoint`). No legacy `access_token` alias — every
// client posts to the standard path; the stack is fixed to it, not shimmed.
func routeToken(r zip.Router, db orm.DB) {
	r.Post(PathToken, tokenHandler(db))
}

// param reads an OAuth parameter from the query first, then the form body
// (application/x-www-form-urlencoded — what NextAuth and most clients send).
func param(c *zip.Ctx, key string) string {
	if v := c.Query(key); v != "" {
		return v
	}
	return c.Fiber().FormValue(key)
}

// tokenError writes the RFC 6749 §5.2 error body with the right status.
func tokenError(c *zip.Ctx, status int, code, desc string) error {
	body := map[string]string{"error": code}
	if desc != "" {
		body["error_description"] = desc
	}
	return c.JSON(status, body)
}

// tokenErrorClient answers a client-authentication failure: 401 + the
// WWW-Authenticate challenge, per RFC 6749 §5.2.
func tokenErrorClient(c *zip.Ctx, desc string) error {
	c.SetHeader("WWW-Authenticate", `Basic realm="OAuth2"`)
	return tokenError(c, 401, "invalid_client", desc)
}

// setTokenCacheHeaders forbids caching of any token response (RFC 6749 §5.1).
func setTokenCacheHeaders(c *zip.Ctx) {
	c.SetHeader("Cache-Control", "no-store")
	c.SetHeader("Pragma", "no-cache")
}

func tokenHandler(db orm.DB) zip.Handler {
	return func(c *zip.Ctx) error {
		setTokenCacheHeaders(c)
		switch param(c, "grant_type") {
		case "authorization_code":
			return authorizationCodeGrant(c, db)
		case "refresh_token":
			return refreshTokenGrant(c, db)
		case "client_credentials":
			return clientCredentialsGrant(c, db)
		case "password":
			return passwordGrant(c, db)
		case grantTypeTokenExchange:
			return tokenExchangeGrant(c, db)
		case deviceGrant:
			return deviceCodeGrant(c, db)
		case "":
			return tokenError(c, 400, "invalid_request", "grant_type is required")
		default:
			return tokenError(c, 400, "unsupported_grant_type", "unsupported grant_type")
		}
	}
}

// authorizationCodeGrant redeems a single-use, PKCE-bound authorization code for
// an access token (+ id_token when openid + rotating refresh).
func authorizationCodeGrant(c *zip.Ctx, db orm.DB) error {
	ctx := c.Context()
	now := nowFunc()

	code := param(c, "code")
	if code == "" {
		return tokenError(c, 400, "invalid_request", "code is required")
	}
	clientID, clientSecret := clientAuth(c)
	verifier := param(c, "code_verifier")
	redirectURI := param(c, "redirect_uri")

	tok, err := store.GetTokenByCode(ctx, db, code)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	app, err := resolveTokenApp(ctx, db, tok)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	// Unknown code, an app that vanished, or a row that is a DEVICE authorization
	// rather than an authorization code — one opaque answer, no oracle. The kind
	// check is load-bearing: a device row carries no PKCE challenge and no
	// redirect_uri, so redeeming one here would mint on a grant no human approved.
	if app == nil || isDevice(tok) {
		return tokenError(c, 400, "invalid_grant", "invalid authorization code")
	}

	// The presented client_id, when sent, must be the code's client (both paths).
	if clientID != "" && subtle.ConstantTimeCompare([]byte(clientID), []byte(app.ClientId)) != 1 {
		return tokenError(c, 400, "invalid_grant", "client mismatch")
	}
	// Client authentication is discriminated by the CODE, never by whether the request
	// carries a secret. PKCE (RFC 7636) IS the browser-redeem client authentication:
	//
	//   - PKCE-bound code (tok.CodeChallenge != ""): the code_verifier proves the
	//     redeemer is the client instance that began the flow — RedeemCode verifies
	//     verifier ↔ challenge below, and a missing/plain/wrong verifier is refused
	//     there. The client_secret is NOT consulted at all. A public browser client
	//     legitimately holds none; a migrated dual-use record (a stored secret it also
	//     serves confidentially) makes SPAs echo a configured, often-STALE secret, and
	//     verifying that stale value was the defect that 401'd every browser redeem and
	//     forced the rollback. On a PKCE redeem a presented secret is irrelevant —
	//     ignored, never a 401. (The prior fix still verified a presented secret, so a
	//     stale one 401'd; only a secretless request slipped through. The programmatic
	//     gate that sent no secret went green while the browser, which sends the secret,
	//     still broke.)
	//   - Non-PKCE code (tok.CodeChallenge == ""): nothing but a secret can prove the
	//     client, so a matching client_secret is REQUIRED, constant-time. This is the
	//     confidential path — unchanged, and strictly stronger than the fork, which
	//     accepted a secretless non-PKCE redeem. The `app.ClientSecret == ""` disjunct
	//     is load-bearing: without it a secretless redeem against a secretless app would
	//     pass a constant-time compare of "" == "" — so a crafted non-PKCE code for a
	//     public app is refused here, not just at mint time.
	if tok.CodeChallenge == "" {
		if app.ClientSecret == "" || subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
			return tokenErrorClient(c, "client authentication failed")
		}
	}
	// redirect_uri binding (RFC 6749 §4.1.3): if the code carries one, the token
	// request must present the same one.
	if tok.RedirectUri != "" {
		if redirectURI == "" || subtle.ConstantTimeCompare([]byte(redirectURI), []byte(tok.RedirectUri)) != 1 {
			return tokenError(c, 400, "invalid_grant", "redirect_uri mismatch")
		}
	}
	// Core guard: replay / expiry / client-app / PKCE verifier ↔ challenge. On a
	// PKCE-bound code THIS is the client authentication — a missing, plain, or
	// mismatched verifier is refused here (no empty/plain/S256 bypass), which is what
	// makes the secret-free branch above safe. A public client using PKCE is enforced
	// at mint (MintFor) AND, independently, at redeem: a non-PKCE code carrying no
	// stored secret was already refused 401 by the discriminator above.
	if err := RedeemCode(tok, app.Name, verifier, now); err != nil {
		return redeemErrToResponse(c, err)
	}

	// One-shot: burn the code, then mint the grant's tokens onto the same row.
	tok.CodeIsUsed = true
	resp, err := issueTokens(ctx, db, c, app, tok, newFamilyID(tok), now)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if err := store.SaveToken(ctx, db, tok); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	return c.JSON(200, resp)
}

// clientCredentialsGrant issues a machine-to-machine access token. The subject
// is the application itself; there is no end user, no id_token, and no refresh
// token (RFC 6749 §4.4 + OIDC — an id_token requires an authenticated user).
func clientCredentialsGrant(c *zip.Ctx, db orm.DB) error {
	ctx := c.Context()
	now := nowFunc()

	clientID, clientSecret := clientAuth(c)
	if clientID == "" {
		return tokenErrorClient(c, "client authentication required")
	}
	app, err := store.GetApplicationByClientId(ctx, db, clientID)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	// A public client (no secret) can never use client_credentials.
	if app == nil || app.ClientSecret == "" ||
		subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
		return tokenErrorClient(c, "client authentication failed")
	}
	if publicTokenEndpointForbidden(app) {
		return tokenErrorClient(c, "client is not permitted on this endpoint")
	}

	scope := param(c, "scope")
	ttl := appTTL(app)
	signer, err := signerFor(ctx, db, app, tokenIssuer(c))
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	sub := app.GetId() // <appOwner>/<appName>, per v1
	// A machine token has no user and therefore no membership set — nil orgs omits
	// the claim, so an app token can never carry a tenancy it did not earn.
	access, err := signer.Sign(app, sub, "", app.Name, scope, nil, ttl, now)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	row := &schema.Token{
		Owner:           app.Owner,
		Application:     app.Name,
		Organization:    app.Organization,
		User:            sub,
		Scope:           scope,
		TokenType:       "Bearer",
		ExpiresIn:       int(ttl.Seconds()),
		AccessTokenHash: hashToken(access),
	}
	row.Name = "cc-" + hashToken(access)[:32]
	if err := store.PersistToken(ctx, db, row); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	return c.JSON(200, tokenResponse{
		AccessToken: access,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttl.Seconds()),
		Scope:       scope,
	})
}

// passwordGrant issues tokens for a Resource Owner Password Credentials request
// (RFC 6749 §4.3) — the durable first-party console session (session.ts posts
// grant_type=password with username/password).
//
// CASDOOR PARITY — INTENTIONAL SECURITY-POSTURE DECISION (flagged for Red review).
// Casdoor ALLOWS a PUBLIC client (the console/chat apps: no client_secret, no PKCE)
// to complete this grant. During the casdoor→clean-room cutover iam2 defaults to
// the SAME behavior so console/chat logins do not 401 `invalid_client`. The exact,
// bounded relaxation vs the prior confidential-only rule:
//
//   - A PUBLIC client (no registered ClientSecret) MAY now complete the password
//     grant with NO client_secret and NO PKCE. This is the ONLY thing newly allowed.
//   - A CONFIDENTIAL client (one that registered a secret) is UNCHANGED: it MUST
//     still present that secret, verified constant-time — a supplied-but-wrong
//     secret is still 401.
//
// Every OTHER control is untouched: publicTokenEndpointForbidden still bars internal
// (<org>-iam) and reserved-org (admin/built-in/app) apps from this endpoint; the app
// must have password login enabled; the password is verified through the SAME
// algorithm-aware, per-row path the login form uses (argon2id for every live v1 row,
// bcrypt for new rows); unknown-user and bad-password return one generic failure (no
// enumeration oracle); a forbidden/deleted user is denied.
func passwordGrant(c *zip.Ctx, db orm.DB) error {
	ctx := c.Context()
	now := nowFunc()

	clientID, clientSecret := clientAuth(c)
	if clientID == "" {
		return tokenErrorClient(c, "client authentication required")
	}
	app, err := store.GetApplicationByClientId(ctx, db, clientID)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if app == nil {
		return tokenErrorClient(c, "client authentication failed")
	}
	// A confidential client (one that registered a secret) must present it; a public
	// client (no registered secret) authenticates by its clientId alone — casdoor ROPC
	// parity. See the doc comment for the exact new surface.
	if app.ClientSecret != "" &&
		subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
		return tokenErrorClient(c, "client authentication failed")
	}
	if publicTokenEndpointForbidden(app) {
		return tokenErrorClient(c, "client is not permitted on this endpoint")
	}
	if !app.IsPasswordEnabled() {
		return tokenError(c, 400, "unauthorized_client", "password grant is not enabled for this client")
	}

	username, password := param(c, "username"), param(c, "password")
	if username == "" || password == "" {
		return tokenError(c, 400, "invalid_request", "username and password are required")
	}
	// Org scope: an explicit `organization` wins; otherwise the client's own org
	// (a same-org first-party login — the console's default).
	org := param(c, "organization")
	if org == "" {
		org = app.Organization
	}
	// Cross-tenant gate — the SAME guard mint.go, login.go, signup.go and
	// federation.go enforce, which passwordGrant alone was missing (F-D2): the login
	// org must be one this client may serve (its own org, a shared app, or an app
	// that lets users pick), and NEVER a reserved system org (admin/built-in/app).
	// Without it a public zoo-console posting organization=admin resolved
	// admin/<super> and minted a real SuperAdmin token on the correct password.
	// Checked BEFORE the user lookup, with the SAME opaque failure as a bad
	// credential, so it is no org/user existence oracle.
	if store.IsReservedOrg(org) ||
		(org != app.Organization && !app.IsShared && app.OrgChoiceMode == "") {
		return tokenError(c, 400, "invalid_grant", "the username or password is incorrect")
	}

	user, err := resolveLoginUser(ctx, db, org, username)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	orgPasswordType := loginOrgPasswordType(ctx, db, org)
	// Credential verify through the ONE lockout-enforcing choke point (F-D1) —
	// users.Authenticate: a run of wrong passwords locks the account, so the public ROPC
	// endpoint is not an online brute-force oracle. The lockout refusal is distinct from
	// a bad credential but still reveals nothing about correctness.
	ok, locked := users.Authenticate(ctx, db, user, password, orgPasswordType, now)
	if locked {
		return tokenError(c, 400, "invalid_grant", "too many failed attempts; the account is temporarily locked")
	}
	if !ok {
		return tokenError(c, 400, "invalid_grant", "the username or password is incorrect")
	}
	if user.IsForbidden || user.IsDeleted {
		return tokenError(c, 400, "invalid_grant", "the user is forbidden")
	}

	// Build a fresh grant row (owner/name upfront so newFamilyID has a stable id),
	// then mint through the ONE shared token path (access + id_token on openid +
	// rotating refresh) so the password grant's token shape never drifts.
	name, err := newOpaqueToken()
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	row := &schema.Token{
		Owner:        user.Owner,
		Name:         "pwd-" + name[:32],
		Application:  app.Name,
		Organization: user.Owner,
		User:         user.Owner + "/" + user.Name,
		Scope:        param(c, "scope"),
	}
	resp, err := issueTokens(ctx, db, c, app, row, newFamilyID(row), now)
	if err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	if err := store.PersistToken(ctx, db, row); err != nil {
		return tokenError(c, 500, "server_error", "")
	}
	return c.JSON(200, resp)
}

// issueTokens mints the grant's tokens onto row: a signed access JWT, an
// id_token when the openid scope is present (echoing the stored nonce), and a
// rotating opaque refresh token joined to `family`. row already carries the
// grant identity (Owner/Application/User/Scope/Nonce). It is the single path
// both the code grant and refresh rotation mint through, so the token shape can
// never drift between them.
func issueTokens(ctx context.Context, db orm.DB, c *zip.Ctx, app *schema.Application, row *schema.Token, family string, now time.Time) (tokenResponse, error) {
	ttl := appTTL(app)
	signer, err := signerFor(ctx, db, app, tokenIssuer(c))
	if err != nil {
		return tokenResponse{}, err
	}
	sub, email, name, orgs := userClaims(ctx, db, row.User)

	access, err := signer.Sign(app, sub, email, name, row.Scope, orgs, ttl, now)
	if err != nil {
		return tokenResponse{}, err
	}
	refresh, err := newOpaqueToken()
	if err != nil {
		return tokenResponse{}, err
	}

	// Persist only the SHA-256 hashes, never the reusable plaintext tokens: a
	// database dump then exposes no usable bearer or refresh credential. Lookups
	// (userinfo, refresh) go through the hash siblings.
	row.AccessToken = ""
	row.AccessTokenHash = hashToken(access)
	row.RefreshToken = ""
	row.RefreshTokenHash = hashToken(refresh)
	row.RefreshFamily = family
	row.RefreshConsumed = false
	row.RefreshExpireIn = now.Add(refreshTTL(app)).Unix()
	row.ExpiresIn = int(ttl.Seconds())
	row.TokenType = "Bearer"

	resp := tokenResponse{
		AccessToken:  access,
		RefreshToken: refresh,
		TokenType:    "Bearer",
		ExpiresIn:    int(ttl.Seconds()),
		Scope:        row.Scope,
	}
	if hasScope(row.Scope, "openid") {
		idt, err := signer.SignID(app, sub, email, name, row.Scope, row.Nonce, orgs, ttl, now)
		if err != nil {
			return tokenResponse{}, err
		}
		resp.IdToken = idt
	}
	return resp, nil
}

// clientAuth extracts the presented client credentials from EITHER RFC 6749
// §2.3.1 channel — client_secret_post (body / query params) and
// client_secret_basic (Authorization: Basic) — uniformly, so no channel's secret
// is silently dropped. A form value wins for a field it sets; the Basic header
// fills a field the form left empty. The prior version returned as soon as a form
// client_id was present, which dropped a Basic-header secret whenever the client
// also sent client_id in the body — so a form-param wrong secret 401'd while a
// Basic wrong secret was silently ignored, an inconsistency the callers must not
// have to reason about. The caller applies ONE rule to the extracted secret
// regardless of which channel carried it.
func clientAuth(c *zip.Ctx) (id, secret string) {
	id, secret = param(c, "client_id"), param(c, "client_secret")
	if bid, bsecret, ok := parseBasicAuth(c.Header("Authorization")); ok {
		if id == "" {
			id = bid
		}
		if secret == "" {
			secret = bsecret
		}
	}
	return id, secret
}

// parseBasicAuth decodes an HTTP Basic client-authentication header. Per RFC
// 6749 §2.3.1 the id and secret are form-urlencoded before base64.
func parseBasicAuth(header string) (id, secret string, ok bool) {
	const p = "Basic "
	if len(header) <= len(p) || !strings.EqualFold(header[:len(p)], p) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(header[len(p):]))
	if err != nil {
		return "", "", false
	}
	idPart, secretPart, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	if u, err := url.QueryUnescape(idPart); err == nil {
		idPart = u
	}
	if u, err := url.QueryUnescape(secretPart); err == nil {
		secretPart = u
	}
	return idPart, secretPart, true
}

// resolveTokenApp loads the application a token row belongs to. Returns (nil,nil)
// for an unknown code so the handler answers invalid_grant without leaking which
// of code/app was missing.
func resolveTokenApp(ctx context.Context, db orm.DB, tok *schema.Token) (*schema.Application, error) {
	if tok == nil {
		return nil, nil
	}
	return store.GetApplicationByName(ctx, db, tok.Owner, tok.Application)
}

// appTTL is the access-token lifetime for an app (ExpireInHours, default 1h).
func appTTL(app *schema.Application) time.Duration {
	if app.ExpireInHours > 0 {
		return time.Duration(app.ExpireInHours * float64(time.Hour))
	}
	return time.Hour
}

// refreshTTL is the refresh-token lifetime (RefreshExpireInHours); when unset it
// clamps to the access-token lifetime, matching v1.
func refreshTTL(app *schema.Application) time.Duration {
	if app.RefreshExpireInHours > 0 {
		return time.Duration(app.RefreshExpireInHours * float64(time.Hour))
	}
	return appTTL(app)
}

// signerFor loads the application's signing cert from the trusted platform
// signing-cert owners and builds a Signer with the given canonical issuer. Using
// the same trusted resolution as the JWKS and verification keeps the three
// consistent: a token is signed by a key iam2 will also publish and verify.
func signerFor(ctx context.Context, db orm.DB, app *schema.Application, issuer string) (*Signer, error) {
	cert, err := store.GetSigningCert(ctx, db, app.Cert)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, errors.New("token: application has no trusted signing cert")
	}
	return NewSignerFromCert(cert, app, issuer)
}

// signAccessToken signs a bare access token for a token row under the given
// issuer — the direct sign path the end-to-end test drives.
func signAccessToken(ctx context.Context, db orm.DB, app *schema.Application, tok *schema.Token, issuer string, ttl time.Duration, now time.Time) (string, error) {
	signer, err := signerFor(ctx, db, app, issuer)
	if err != nil {
		return "", err
	}
	sub, _, _, orgs := userClaims(ctx, db, tok.User)
	return signer.Sign(app, sub, "", "", tok.Scope, orgs, ttl, now)
}

// tokenIssuer is the canonical OIDC issuer for this request — the value discovery
// advertises and every token carries as `iss`. It routes through the ONE per-host
// issuer resolver (issuer.go), keyed on the TRUSTED request host (c.Host(), which
// ignores X-Forwarded-Host), so the value is always a pinned CONFIG issuer for the
// brand the ingress routed this request to — never a string interpolated from a
// request header. See resolveIssuer for the fail-closed resolution order.
func tokenIssuer(c *zip.Ctx) string {
	return resolveIssuer(c.Host())
}

// subjectOf is the OIDC `sub` for a user: its stable opaque Id (the cutover-
// continuity UUID casdoor emits and the migrator preserves), falling back to the
// (owner/name) natural key ONLY for a pre-cutover row that carries no Id. It is
// the single place the subject is derived, so the token's `sub`, userinfo's `sub`,
// and the introspection `sub` can never disagree, and store.GetUserBySubject
// decodes exactly what this encodes (no "/" ⇒ resolve by Id).
func subjectOf(u *schema.User) string {
	if u == nil {
		return ""
	}
	if u.Id != "" {
		return u.Id
	}
	return u.Owner + "/" + u.Name
}

// userClaims loads a user's token-facing claims in ONE lookup: its subject (the
// stable `sub`), email, display name, and membership set (store.MemberOrgRefs —
// home org first, deduped). It is the single resolution both the
// code/refresh/password mint (issueTokens) and the direct-sign path share, so the
// `sub`, `orgs` claim, and profile can never be sourced two different ways. userID
// is the token row's (owner/name) User key. A subject with no user row (a machine
// token, or a since-deleted user) yields the passed-in id as sub, empty profile,
// and nil orgs — the claim is omitted, not forged.
func userClaims(ctx context.Context, db orm.DB, userID string) (sub, email, name string, orgs []schema.OrgRef) {
	owner, uname := splitSub(userID)
	if owner == "" || uname == "" {
		return userID, "", "", nil
	}
	u, err := store.GetUserByName(ctx, db, owner, uname)
	if err != nil || u == nil {
		return userID, "", "", nil
	}
	name = u.DisplayName
	if name == "" {
		name = u.Name
	}
	return subjectOf(u), u.Email, name, store.MemberOrgRefs(ctx, db, u)
}

// splitSub splits a subject "owner/name" into its two parts.
func splitSub(sub string) (owner, name string) {
	owner, name, _ = strings.Cut(sub, "/")
	return owner, name
}

// hashToken is the SHA-256 hex digest used to index a stored token by a
// presented bearer/refresh string without keeping the plaintext on the lookup
// path.
func hashToken(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// hasScope reports whether a space-delimited scope string contains want.
func hasScope(scope, want string) bool {
	for _, s := range strings.Fields(scope) {
		if s == want {
			return true
		}
	}
	return false
}

// newFamilyID derives a stable refresh-family id for a fresh grant from the
// code row's identity — the anchor every rotation of this grant shares.
func newFamilyID(tok *schema.Token) string {
	return tok.Owner + "/" + tok.Name
}

// isInternalApp reports whether an application is an internal service identity
// (<org>-iam), which may never obtain a token on the public token endpoint.
func isInternalApp(app *schema.Application) bool {
	return strings.HasSuffix(app.Name, "-iam")
}

// publicTokenEndpointForbidden reports whether an application must NEVER obtain a
// token on the PUBLIC token endpoint (the client_credentials and password grants).
// It is the ONE gate both grants apply — two disjoint reasons, one predicate:
//
//   - an internal service identity (<org>-iam), which authenticates through the
//     operator's private provisioning path, never the public endpoint; and
//   - an app that SERVES a reserved system org (admin/built-in/app — store.IsReservedOrg):
//     a platform-internal client whose tokens have no business being minted by a
//     public request. Even though such a token already resolves to NO authority (its
//     subject "admin/<app>" has no user row, so authz grants it nothing — token.go /
//     authz.principal), refusing it at the door makes the invariant STRUCTURAL: an
//     admin-org app cannot mint on the public endpoint, period, independent of how the
//     principal resolver later evolves. Fail-secure defense in depth.
func publicTokenEndpointForbidden(app *schema.Application) bool {
	return isInternalApp(app) || store.IsReservedOrg(app.Organization)
}

// redeemErrToResponse maps a RedeemCode error to the RFC 6749 error body.
func redeemErrToResponse(c *zip.Ctx, err error) error {
	switch err {
	case ErrCodeUsed:
		return tokenError(c, 400, "invalid_grant", "authorization code already used")
	case ErrCodeExpired:
		return tokenError(c, 400, "invalid_grant", "authorization code expired")
	case ErrClientMismatch:
		return tokenError(c, 400, "invalid_grant", "client mismatch")
	case ErrPKCEMismatch, ErrPKCEMissing, ErrPKCEPlainRejected:
		return tokenError(c, 400, "invalid_grant", "PKCE verification failed")
	case ErrCodeUnknown:
		return tokenError(c, 400, "invalid_grant", "invalid authorization code")
	default:
		return tokenError(c, 400, "invalid_grant", "authorization code rejected")
	}
}
