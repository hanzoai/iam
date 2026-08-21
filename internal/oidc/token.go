// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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

	"github.com/hanzoai/account"
	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The token endpoint: POST /v1/iam/oauth/token. It dispatches the three grant
// types iam issues — authorization_code (PKCE-verified, single-use code →
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

// tokenHandler exchanges what your application is holding for the tokens it
// needs — the one-time code from a finished sign-in, a refresh token, or your
// own client credentials when the caller is a program rather than a person.
//
// A refresh returns a NEW refresh token and retires the one you sent. If a
// retired one is ever presented again the whole chain is revoked, on the
// assumption that a token which came back from the dead was copied — so a stolen
// refresh token buys an attacker one use and costs them the session.
//
// Responses are never cached, by any hop.
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

	// The presented client must be the code's client.
	if clientID != "" && subtle.ConstantTimeCompare([]byte(clientID), []byte(app.ClientId)) != 1 {
		return tokenError(c, 400, "invalid_grant", "client mismatch")
	}
	// Client authentication. A client that PRESENTS a secret must present the right
	// one (constant-time). A BROWSER client presents none — it cannot hold one — and
	// the code's PKCE binding is what authenticates it: RedeemCode below verifies the
	// verifier against the challenge, the code is single-use, and it was delivered to
	// a registered redirect_uri.
	//
	// LEGACY PARITY — same bounded relaxation this file already documents for
	// passwordGrant. Registration is not per-flow here: `hanzo-chat` and `hanzo-cloud`
	// keep a secret for their BACKEND paths (chat's passport OpenID, cloud's
	// client_credentials machine auth) while their SPA is a public PKCE client. The
	// clean-room rewrite required the secret unconditionally, so every @hanzo/iam
	// login — hanzo.chat, cloud.hanzo.ai — signed in at hanzo.id, returned to
	// /auth/callback and died on `401 invalid_client`. Deleting those secrets is NOT
	// the fix (it breaks client_credentials, which requires a registered secret).
	//
	// A code with NO PKCE challenge still requires the secret, so this is not a
	// downgrade path: an attacker cannot skip client auth by omitting PKCE.
	clientAuthed := app.ClientSecret != "" && (clientSecret != "" || tok.CodeChallenge == "")
	if clientAuthed {
		if subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
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
	// Core guard: replay / expiry / client / PKCE.
	if err := RedeemCode(tok, app.Name, verifier, now); err != nil {
		return redeemErrToResponse(c, err)
	}
	// A public client MUST have used PKCE — never let a no-secret grant through
	// without a challenge (downgrade / code injection defense).
	if app.ClientSecret == "" && tok.CodeChallenge == "" {
		return tokenError(c, 400, "invalid_grant", "PKCE is required for public clients")
	}

	// One-shot: burn the code, then mint the grant's tokens onto the same row.
	// PublicGrant carries the relaxation above FORWARD: refresh must be decided
	// on how this grant was authenticated, not on whether the registration
	// happens to hold a secret, or the client that just exchanged a code without
	// one is refused the moment it tries to refresh.
	tok.CodeIsUsed, tok.PublicGrant = true, !clientAuthed
	resp, err := issueTokens(ctx, db, c, app, tok, newFamilyID(tok), now)
	if err != nil {
		return mintError(c, err)
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
		return mintError(c, err)
	}
	sub := app.GetId() // <appOwner>/<appName>, per v1
	// A machine token's principal is the APP, so its username is the app name — the
	// `<name>` half of the same `<owner>/<name>` shape a user token carries, which
	// is what lets a resource server read `owner`/`name` without first asking which
	// kind of token it holds. It has no user and therefore no membership set — nil
	// orgs omits the claim, so an app token can never carry a tenancy it did not
	// earn, and no display name means no display claim.
	//
	// The class is resolved HERE, from the grant, for the same reason the billing
	// account is: this endpoint is the only place that knows the token was minted
	// against a client secret with no person present. Said in the token, a consumer
	// reads a fact; left unsaid, it guesses — and the guess available to it reports
	// every shared app's machine as a person.
	// The resource server this token is FOR (RFC 8707), read exactly as the token
	// exchange grant reads it — resource wins, then audience, else the client's own
	// id. A machine credential is spent against something, and a token that can only
	// ever name its minter forces every resource server to accept tokens minted for
	// somebody else or to be handed a second credential of its own.
	//
	// The boundary is the client secret, as it is on the exchange grant beside it: a
	// caller that authenticated as this client may say what the token is for, and the
	// resource server still decides what to honour. `azp` records the minter either way.
	resource := param(c, "resource")
	if resource == "" {
		resource = param(c, "audience")
	}
	access, err := signer.Sign(app, Identity{
		Id:      sub,
		Name:    app.Name,
		Billing: machineBillingAccount(app.Organization),
		Type:    schema.Program,
	}, scope, resource, ttl, now)
	if err != nil {
		return mintError(c, err)
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
// CONFIDENTIAL CLIENTS ONLY. A client that stores no secret cannot complete this
// grant, because the stored secret is the only thing that authenticates the CALLER
// here — unlike the code and device grants, ROPC has neither a PKCE challenge nor a
// human approval step to stand in for it. Without that rule the endpoint takes a
// username and password from anyone who knows a public client_id.
//
// This REPLACES an earlier legacy-parity relaxation that let a public client
// complete the grant so console/chat logins would not 401 `invalid_client` during
// the legacy→clean-room cutover. That relaxation was dormant — every live Hanzo
// registration is confidential and takes the secret path — and it became actively
// dangerous the moment a client had to go public for an unrelated reason:
// `hanzo-cli` needs no stored secret to run the device grant, and under the old
// rule that flip alone would have opened unauthenticated ROPC. Registration shape
// must not be able to open a credential surface.
//
//   - A CONFIDENTIAL client (one that registered a secret) is UNCHANGED: it MUST
//     present that secret, verified constant-time — a supplied-but-wrong
//     secret is still 401.
//   - A PUBLIC client is refused outright, and signs its human in with the device
//     grant (RFC 8628) or the PKCE code flow instead.
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
	// A confidential client (one that registered a secret) must present it.
	if app.ClientSecret != "" &&
		subtle.ConstantTimeCompare([]byte(clientSecret), []byte(app.ClientSecret)) != 1 {
		return tokenErrorClient(c, "client authentication failed")
	}
	// ROPC requires a CONFIDENTIAL client, and this is the check that makes that
	// structural rather than a property of whichever clients happen to exist.
	//
	// A public client stores no secret — that absence is the whole definition
	// (bootstrap.resolveSecret) — so without this the endpoint would accept a
	// username and password from anyone who knows a public client_id. That is an
	// unauthenticated credential-stuffing oracle against every user in the tenant
	// and an account-lockout lever against any named one; the registered secret
	// was the ONLY thing that ever gated it. OAuth 2.1 drops the grant entirely
	// for this reason.
	//
	// It is not hypothetical: `hanzo-cli` had to become public so a CLI could run
	// the device grant at all (a stored secret it cannot present is `invalid_client`
	// at /v1/iam/oauth/device), and the same flip silently made ROPC reachable
	// without a credential. Registration shape must not be able to open this
	// surface, so the rule lives HERE and not in a provision document.
	//
	// A public client signs a human in with the device grant (RFC 8628) or the
	// PKCE code flow, both of which authenticate the USER rather than trusting the
	// caller with their password.
	if app.ClientSecret == "" {
		return tokenErrorClient(c, "the password grant requires a confidential client")
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
	if policy.IsReservedOrg(org) ||
		(org != app.Organization && !app.ServesAnyOrg()) {
		return tokenError(c, 400, "invalid_grant", "the username or password is incorrect")
	}

	user, err := resolveLoginUser(ctx, db, app, org, username)
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
		return mintError(c, err)
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
	id, err := userClaims(ctx, db, row.User)
	if err != nil {
		return tokenResponse{}, err
	}

	access, err := signer.Sign(app, id, row.Scope, "", ttl, now)
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
		idt, err := signer.SignID(app, id, row.Scope, row.Nonce, ttl, now)
		if err != nil {
			return tokenResponse{}, err
		}
		resp.IdToken = idt
	}
	return resp, nil
}

// clientAuth extracts client credentials, preferring client_secret_post (body /
// query) and falling back to client_secret_basic (Authorization: Basic).
func clientAuth(c *zip.Ctx) (id, secret string) {
	id, secret = param(c, "client_id"), param(c, "client_secret")
	if id != "" {
		return id, secret
	}
	if bid, bsecret, ok := parseBasicAuth(c.Header("Authorization")); ok {
		return bid, bsecret
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
	return time.Duration(schema.DefaultExpireInHours * float64(time.Hour))
}

// refreshTTL is the refresh-token lifetime (RefreshExpireInHours); when unset it
// clamps to the access-token lifetime, matching v1.
func refreshTTL(app *schema.Application) time.Duration {
	if app.RefreshExpireInHours > 0 {
		return time.Duration(app.RefreshExpireInHours * float64(time.Hour))
	}
	return appTTL(app)
}

// ErrNoSigningCert is an application registered with no resolvable signing cert.
//
// It is a MISCONFIGURED REGISTRATION, not a bad request, and it is the one
// internal failure this endpoint names out loud. Everything else answers a bare
// `server_error` because describing it would build an oracle — but this describes
// the caller's own registration, reveals nothing about any credential, code or
// user, and is otherwise undiagnosable from outside: the user authenticates, the
// code is minted and redeemed, and only then does the exchange die on a 500 that
// looks exactly like an outage, with nothing but `{"error":"server_error"}` for
// the client to act on — which is why this one failure names itself.
//
// bootstrap.resolveCert now prevents an application from being CREATED this way;
// this is the answer for one that already was.
var ErrNoSigningCert = errors.New("token: application has no trusted signing cert")

// signerFor loads the application's signing cert from the trusted platform
// signing-cert owners and builds a Signer with the given canonical issuer. Using
// the same trusted resolution as the JWKS and verification keeps the three
// consistent: a token is signed by a key iam will also publish and verify.
func signerFor(ctx context.Context, db orm.DB, app *schema.Application, issuer string) (*Signer, error) {
	cert, err := store.GetSigningCert(ctx, db, app.Cert)
	if err != nil {
		return nil, err
	}
	if cert == nil {
		return nil, ErrNoSigningCert
	}
	return NewSignerFromCert(cert, app, issuer)
}

// mintError answers a token-minting failure: the opaque `server_error` for
// anything internal, and a named one for the misconfiguration a client operator
// can actually act on. ONE place, so every grant answers alike.
func mintError(c *zip.Ctx, err error) error {
	if errors.Is(err, ErrNoSigningCert) {
		return tokenError(c, 500, "server_error",
			"this application has no signing cert, so no token can be issued for it")
	}
	// The grant's subject no longer names a usable user. That is the holder's
	// credential being dead, not this server being broken, so it is a 400
	// invalid_grant: a client that retries a 500 forever would spin, while
	// invalid_grant tells it to sign in again (RFC 6749 §5.2).
	if errors.Is(err, ErrNoSubject) {
		return tokenError(c, 400, "invalid_grant", "the grant's subject no longer names a user")
	}
	return tokenError(c, 500, "server_error", "")
}

// signAccessToken signs a bare access token for a token row under the given
// issuer — the direct sign path the end-to-end test drives.
func signAccessToken(ctx context.Context, db orm.DB, app *schema.Application, tok *schema.Token, issuer string, ttl time.Duration, now time.Time) (string, error) {
	signer, err := signerFor(ctx, db, app, issuer)
	if err != nil {
		return "", err
	}
	id, err := userClaims(ctx, db, tok.User)
	if err != nil {
		return "", err
	}
	return signer.Sign(app, Identity{Id: id.Id, Orgs: id.Orgs}, tok.Scope, "", ttl, now)
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
// continuity UUID legacy emits and the migrator preserves), falling back to the
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

// identityOf is the ONE resolution of a loaded user into token claims: its stable
// `sub`, email, USERNAME, display name, ledger, and membership set
// (store.MemberOrgRefs — home org first, deduped). Every mint path — the
// code/refresh/password grant, the console's issue-user-token, and the RFC 8693
// exchange — builds its Identity here, so the `sub`, `orgs` claim and profile
// cannot be sourced three different ways.
//
// They were. Each of those paths separately wrote `name = DisplayName, else
// Name`, which put a human's display name in the claim the CLI files its
// credential under: a login as "z" minted `name: "Zach Kelling"` and every
// downstream surface then named a principal that does not exist. `name` is the
// username here and nowhere else decides.
func identityOf(ctx context.Context, db orm.DB, u *schema.User) Identity {
	refs := store.MemberOrgRefs(ctx, db, u)
	return Identity{
		Id:      subjectOf(u),
		Email:   u.Email,
		Name:    u.Name,
		Display: u.DisplayName,
		Billing: store.BillingAccount(u, refs),
		Orgs:    refs,
	}
}

// userClaims resolves the token-facing Identity for a token row's (owner/name)
// User key, in ONE lookup, through identityOf.
//
// A SUBJECT THAT NAMES NO USER FAILS THE MINT. It used to yield the passed-in id
// as sub and an otherwise zero Identity, on the reasoning that omitting a profile
// claim is safer than forging one. That is true of the profile and false of the
// rest: the nameless Identity carries no Name, no Orgs and no Billing either, and
// downstream those absences are not "unknown", they are ANSWERS. account.Payer
// reads a missing name in the signup org as "not a person" and bills the account
// beside it — the platform's own. So the safest-looking value in this function was
// a credential that spends a balance its holder was never granted.
//
// The subject can stop resolving while a live token still pins it: the refresh
// grant copies its predecessor's User key forward at every rotation, so a user
// that is deleted, or RE-KEYED underneath that key (which founding a personal org
// does), leaves a token family whose every future rotation mints one of these. It
// renews itself, which is why refusing at the mint is the fix and not a check at
// one door.
//
// The two failures are DIFFERENT and must not be flattened. A store error is a
// fault — the row may well exist — so the request fails and the caller retries.
// A resolved-but-absent row is a dead credential: the grant's subject is gone, the
// holder must obtain a new one, and no retry will help.
//
// Gone, banned and soft-deleted are ONE answer here: none of them may be handed a
// fresh credential. The password grant already refused the latter two before
// minting; the code, device and refresh grants did not, so a ban took effect
// everywhere except on the paths that renew access. Stated once, at the single
// place every grant resolves its subject, rather than three times at three doors.
//
// This never touches a machine: client_credentials signs its own Identity from the
// app (see clientCredentialsGrant) and never calls this. Every path that does is a
// grant made to a PERSON, where the user row must exist by construction.
func userClaims(ctx context.Context, db orm.DB, userID string) (Identity, error) {
	owner, uname := splitSub(userID)
	if owner == "" || uname == "" {
		return Identity{}, ErrNoSubject
	}
	u, err := store.GetUserByName(ctx, db, owner, uname)
	if err != nil {
		return Identity{}, err
	}
	if u == nil || u.IsDeleted || u.IsForbidden {
		return Identity{}, ErrNoSubject
	}
	return identityOf(ctx, db, u), nil
}

// ErrNoSubject is a grant whose subject no longer names a usable user: deleted,
// banned, or re-keyed while a token that pinned the old key was still alive. It is
// a dead credential rather than a fault, so the token endpoint answers
// invalid_grant — the holder must sign in again, and a retry cannot help.
var ErrNoSubject = errors.New("oidc: the grant's subject no longer names a user")

// machineBillingAccount decides WHICH LEDGER a MACHINE credential spends from.
//
// A client_credentials token has no person behind it — the app IS the org acting
// — so it spends the ORG POOL. That is already what account.Payer's shape rule
// concludes for a machine in EVERY org but one: the rule makes the signup org
// special and hands anyone in it a PERSONAL wallet. A machine has no person, so
// that wallet is a ghost — no funding path can name "<signupOrg>/<appName>", an
// admin grant credits the pool and a deposit names a real member — leaving it $0
// forever while the org's balance sits one key away. Hanzo's own first-party
// services all authenticate this way and all live in the signup org, so every one
// of them billed a wallet that could not be funded and 402'd against a funded org.
//
// The claim is not new authority, it is the same answer stated where it cannot be
// lost: Payer only INFERRED machine-ness before, from a User.Type a user can set
// on themselves, and no layer populated it on the token path at all.
//
// THE AUTHORITY WAS ALREADY CHECKED, at registration. Pointing an application at
// an org requires SuperAdmin or that org's own admin (applications.
// authorizeOrganization → authz.CanSetOrg), which is the SAME bar billingAccountFor
// applies to a person before it names the pool. A plain member of the signup org
// cannot register an app there, so this cannot become the free-rider path onto the
// platform's balance that the personal-wallet rule exists to prevent.
//
// Only the app's OWN organization is ever named — the same value the `owner` claim
// carries — so a machine token can never name another tenant's ledger, and an
// org-less app yields the zero Account, hence no claim and the unchanged fallback.
func machineBillingAccount(org string) string {
	return account.Org(org).String()
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
//   - an app that SERVES a reserved system org (admin/built-in/app — policy.IsReservedOrg):
//     a platform-internal client whose tokens have no business being minted by a
//     public request. Even though such a token already resolves to NO authority (its
//     subject "admin/<app>" has no user row, so authz grants it nothing — token.go /
//     authz.principal), refusing it at the door makes the invariant STRUCTURAL: an
//     admin-org app cannot mint on the public endpoint, period, independent of how the
//     principal resolver later evolves. Fail-secure defense in depth.
func publicTokenEndpointForbidden(app *schema.Application) bool {
	return isInternalApp(app) || policy.IsReservedOrg(app.Organization)
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
