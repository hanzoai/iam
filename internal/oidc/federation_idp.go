// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/schema"
)

// The Relying-Party side of federation: iam as an OIDC/OAuth2 CLIENT of an
// external identity provider. Two dialects, one contract (federatedIdentity):
//
//   - OIDC (Google + any provider with an IssuerUrl): OIDC Discovery resolves the
//     endpoints and JWKS; the end user is authenticated by the id_token, whose
//     SIGNATURE (against the published JWKS), issuer, audience, expiry, and nonce
//     are all verified before a single claim is trusted. email_verified is read
//     from the signed token.
//   - GitHub (OAuth2, no id_token): the code is exchanged for an access token,
//     then the user + verified-email endpoints are read. Only a GitHub-verified,
//     primary email is treated as verified.
//
// Every outbound call is hardened: a bounded-timeout client that never follows
// redirects (a 3xx on a token/JWKS endpoint is answered as a failure, not
// chased), a response-body size cap, an https-except-loopback URL guard, and
// alg-pinned JWT verification (RS/ES only — never `none`, never an HMAC that a
// public key could be abused as the secret for). No secret or token is logged.

// federatedIdentity is the VERIFIED identity an external IdP asserts about the
// end user — the only thing the broker trusts out of the round-trip. Subject is
// the IdP's stable, opaque user id (the connector-column value); Email is linked
// against a local account ONLY when EmailVerified is true.
type federatedIdentity struct {
	subject       string
	email         string
	emailVerified bool
	displayName   string
	avatar        string
}

// federationHTTPClient is the hardened client every IdP call rides. The timeout
// bounds a slow/hostile IdP; CheckRedirect refuses to chase a redirect (an IdP
// token/userinfo/JWKS endpoint answering 3xx is a fault, not a hop), closing the
// SSRF-via-redirect vector; and the dialer Control refuses to connect to a
// private/loopback/link-local/metadata address AT DIAL TIME — after DNS
// resolution, on the ACTUAL connecting IP — so a hostile IssuerUrl/Custom*Url (or
// a DNS-rebinding hostname) cannot make iam reach an internal service or the
// cloud metadata endpoint.
var federationHTTPClient = &http.Client{
	Timeout: 12 * time.Second,
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	},
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Control:   federationDialControl,
		}).DialContext,
		TLSHandshakeTimeout:   8 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
		MaxIdleConns:          8,
		IdleConnTimeout:       30 * time.Second,
	},
}

// federationDialAllowsPrivate relaxes the SSRF dial guard to permit
// private/loopback addresses. It is a TEST SEAM ONLY (the mock IdPs bind to
// 127.0.0.1); production code never sets it, so the guard is always fully armed
// in a real deployment.
var federationDialAllowsPrivate = false

// federationDialControl is the net.Dialer.Control hook: it inspects the resolved
// address every connection actually dials and refuses a private, loopback,
// link-local, ULA, unspecified, multicast, or CGNAT target — the SSRF gate that a
// literal-URL check cannot provide because it sees the post-DNS IP (defeating
// DNS-rebinding). Fails closed on an unparseable address.
func federationDialControl(_, address string, _ syscall.RawConn) error {
	if federationDialAllowsPrivate {
		return nil
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return errors.New("federation: refusing an unparseable dial address")
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return errors.New("federation: dial host did not resolve to an IP")
	}
	if ipBlockedForFederation(ip) {
		return errors.New("federation: refusing to dial a private/loopback/link-local address")
	}
	return nil
}

// ipBlockedForFederation reports whether an IP is in a range iam must never
// fetch from during federation. net.IP.IsPrivate covers RFC1918 and IPv6 ULA
// (fc00::/7); IsLinkLocalUnicast covers 169.254.0.0/16 (incl. the 169.254.169.254
// cloud-metadata address) and fe80::/10.
func ipBlockedForFederation(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || isCGNAT(ip)
}

// isCGNAT reports whether ip is in 100.64.0.0/10 (carrier-grade NAT), a shared
// range net.IP.IsPrivate does not cover.
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127
}

// maxIdPBodyBytes caps every IdP response read — a hostile or broken IdP cannot
// exhaust memory (discovery/JWKS/token/userinfo are all a few KB).
const maxIdPBodyBytes = 1 << 20 // 1 MiB

// defaultGoogleIssuer is the OIDC issuer for a Google provider that pins none of
// its own — the value the id_token carries as `iss` and the discovery origin.
const defaultGoogleIssuer = "https://accounts.google.com"

// GitHub's fixed OAuth2 endpoints (overridable per-Provider for GitHub
// Enterprise / tests via Custom{Auth,Token,UserInfo}Url).
const (
	githubAuthorizeEndpoint = "https://github.com/login/oauth/authorize"
	githubTokenEndpoint     = "https://github.com/login/oauth/access_token"
	githubUserEndpoint      = "https://api.github.com/user"
)

// idpKind classifies a provider into its federation dialect. A provider with an
// explicit OIDC issuer — or Google — is OIDC; GitHub is OAuth2+userinfo.
// Anything else is unsupported and fails closed (""), never guessed.
func idpKind(p *schema.Provider) string {
	switch {
	case strings.EqualFold(p.Type, "GitHub"):
		return "github"
	case strings.EqualFold(p.Type, "Google") || strings.TrimSpace(p.IssuerUrl) != "":
		return "oidc"
	default:
		return ""
	}
}

// idpAuthorizeURL builds the IdP authorization-endpoint URL the browser is sent
// to at the begin leg — dialect-dispatched, with iam's callback as the IdP
// redirect_uri, our single-use state, IdP-leg PKCE, and (OIDC) the nonce.
func idpAuthorizeURL(ctx context.Context, p *schema.Provider, st *schema.FederationState, callback string) (string, error) {
	switch idpKind(p) {
	case "oidc":
		cfg, err := oidcResolve(ctx, p)
		if err != nil {
			return "", err
		}
		return oidcAuthorizeURL(cfg, p, st, callback), nil
	case "github":
		return githubAuthorizeURL(p, st, callback), nil
	default:
		return "", fmt.Errorf("federation: provider %q is not a supported federation type", p.Name)
	}
}

// idpExchange completes the callback leg: it exchanges the IdP authorization
// code and returns the VERIFIED identity, or an error if any verification fails.
func idpExchange(ctx context.Context, p *schema.Provider, st *schema.FederationState, code, callback string, now time.Time) (federatedIdentity, error) {
	switch idpKind(p) {
	case "oidc":
		cfg, err := oidcResolve(ctx, p)
		if err != nil {
			return federatedIdentity{}, err
		}
		return oidcExchange(ctx, cfg, p, st, code, callback, now)
	case "github":
		return githubExchange(ctx, p, st, code, callback)
	default:
		return federatedIdentity{}, fmt.Errorf("federation: provider %q is not a supported federation type", p.Name)
	}
}

// --- OIDC dialect (Google + any IssuerUrl provider) ---

// oidcConfig is the resolved OIDC endpoint set for a provider.
type oidcConfig struct {
	issuer   string
	authURL  string
	tokenURL string
	jwksURL  string
}

// oidcResolve determines the issuer and runs OIDC Discovery to fill the endpoint
// set. A per-Provider Custom{Auth,Token}Url overrides the discovered
// authorize/token endpoint (a provider that publishes discovery but pins a
// vanity endpoint); the JWKS URI always comes from the signed discovery document
// so id_token verification keys are never attacker-chosen.
func oidcResolve(ctx context.Context, p *schema.Provider) (oidcConfig, error) {
	issuer := strings.TrimRight(strings.TrimSpace(p.IssuerUrl), "/")
	if issuer == "" && strings.EqualFold(p.Type, "Google") {
		issuer = defaultGoogleIssuer
	}
	if issuer == "" {
		return oidcConfig{}, errors.New("federation: OIDC provider has no issuerUrl")
	}
	disco, err := oidcDiscover(ctx, issuer)
	if err != nil {
		return oidcConfig{}, err
	}
	cfg := oidcConfig{
		issuer:   issuer,
		authURL:  disco.AuthorizationEndpoint,
		tokenURL: disco.TokenEndpoint,
		jwksURL:  disco.JwksURI,
	}
	if v := strings.TrimSpace(p.CustomAuthUrl); v != "" {
		cfg.authURL = v
	}
	if v := strings.TrimSpace(p.CustomTokenUrl); v != "" {
		cfg.tokenURL = v
	}
	if cfg.authURL == "" || cfg.tokenURL == "" || cfg.jwksURL == "" {
		return oidcConfig{}, errors.New("federation: OIDC discovery is missing required endpoints")
	}
	return cfg, nil
}

// oidcDiscoveryDocument is the subset of the OIDC Discovery document iam reads.
type oidcDiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// oidcDiscover fetches and validates the issuer's discovery document. The
// document's own `issuer` MUST equal the configured issuer (OIDC Discovery §4.3)
// — a mismatch means the origin is impersonating another issuer, so it fails
// closed.
func oidcDiscover(ctx context.Context, issuer string) (oidcDiscoveryDocument, error) {
	var doc oidcDiscoveryDocument
	if err := getJSON(ctx, issuer+"/.well-known/openid-configuration", &doc); err != nil {
		return doc, err
	}
	if strings.TrimRight(doc.Issuer, "/") != strings.TrimRight(issuer, "/") {
		return oidcDiscoveryDocument{}, fmt.Errorf("federation: discovery issuer mismatch")
	}
	return doc, nil
}

// oidcAuthorizeURL builds the OIDC authorization request: response_type=code,
// the app-or-default scope, our callback, the single-use state, S256 PKCE, and
// the nonce that the returned id_token must echo.
func oidcAuthorizeURL(cfg oidcConfig, p *schema.Provider, st *schema.FederationState, callback string) string {
	v := url.Values{}
	v.Set("response_type", "code")
	v.Set("client_id", p.ClientId)
	v.Set("redirect_uri", callback)
	// The OIDC leg MUST request openid, or the IdP returns no id_token and the
	// exchange fails closed — force it in even if the provider's configured scopes
	// omit it, so a scope misconfiguration can never silently disable verification.
	v.Set("scope", ensureOpenID(providerScopes(p, "openid email profile")))
	v.Set("state", st.Name)
	v.Set("nonce", st.IdpNonce)
	v.Set("code_challenge", pkce.Challenge(st.IdpVerifier))
	v.Set("code_challenge_method", "S256")
	return joinQuery(cfg.authURL, v)
}

// oidcTokenResponse is the token-endpoint response the OIDC exchange reads.
type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
}

// oidcExchange redeems the code at the token endpoint (proving the IdP-leg PKCE
// verifier), then VERIFIES the id_token — signature against the discovered JWKS,
// issuer, audience (== our client id), expiry, and nonce — before trusting any
// claim. The identity comes from the signed id_token, never from an unverified
// userinfo body.
func oidcExchange(ctx context.Context, cfg oidcConfig, p *schema.Provider, st *schema.FederationState, code, callback string, now time.Time) (federatedIdentity, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", callback)
	form.Set("client_id", p.ClientId)
	form.Set("client_secret", p.ClientSecret)
	form.Set("code_verifier", st.IdpVerifier)

	var tr oidcTokenResponse
	if err := postFormJSON(ctx, cfg.tokenURL, form, nil, &tr); err != nil {
		return federatedIdentity{}, err
	}
	if tr.IDToken == "" {
		return federatedIdentity{}, errors.New("federation: OIDC token response carried no id_token")
	}
	claims, err := verifyIDToken(ctx, tr.IDToken, cfg.jwksURL, cfg.issuer, p.ClientId, st.IdpNonce, now)
	if err != nil {
		return federatedIdentity{}, err
	}
	return federatedIdentity{
		subject:       claims.Subject,
		email:         strings.ToLower(strings.TrimSpace(claims.Email)),
		emailVerified: truthy(claims.EmailVerified),
		displayName:   claims.Name,
		avatar:        claims.Picture,
	}, nil
}

// idTokenClaims is the id_token claim set iam reads. Nonce is a top-level OIDC
// claim (not a registered JWT claim), verified against the transaction's stored
// nonce. email_verified is `any` because providers send it as a JSON bool or
// (legacy) the string "true".
type idTokenClaims struct {
	jwt.RegisteredClaims
	Nonce         string `json:"nonce"`
	Email         string `json:"email"`
	EmailVerified any    `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

// verifyIDToken parses and fully validates an id_token. The signing method is
// PINNED to the asymmetric set (RS/ES) so a `none` token or an HMAC-with-public-
// key confusion attack is rejected outright; the key comes from the issuer's
// JWKS, selected by `kid`; issuer, audience, and expiry are enforced by the
// parser (now is injected for testability); and the nonce is compared in
// constant time. A subject-less token is refused.
func verifyIDToken(ctx context.Context, idToken, jwksURL, issuer, audience, nonce string, now time.Time) (idTokenClaims, error) {
	var claims idTokenClaims
	tok, err := jwt.ParseWithClaims(idToken, &claims, jwksKeyfunc(ctx, jwksURL),
		jwt.WithValidMethods([]string{"RS256", "RS384", "RS512", "ES256", "ES384", "ES512"}),
		jwt.WithIssuer(issuer),
		jwt.WithAudience(audience),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if err != nil || !tok.Valid {
		return idTokenClaims{}, fmt.Errorf("federation: id_token verification failed")
	}
	if subtle.ConstantTimeCompare([]byte(claims.Nonce), []byte(nonce)) != 1 {
		return idTokenClaims{}, errors.New("federation: id_token nonce mismatch")
	}
	if strings.TrimSpace(claims.Subject) == "" {
		return idTokenClaims{}, errors.New("federation: id_token has no subject")
	}
	return claims, nil
}

// --- GitHub dialect (OAuth2 + userinfo) ---

// githubAuthorizeURL builds GitHub's OAuth2 authorization request. GitHub OAuth
// Apps support neither PKCE nor a nonce, so the single-use, browser-bound state
// carries the CSRF defense; PKCE is added only when the provider opts in
// (EnablePkce) for a compatible deployment.
func githubAuthorizeURL(p *schema.Provider, st *schema.FederationState, callback string) string {
	v := url.Values{}
	v.Set("client_id", p.ClientId)
	v.Set("redirect_uri", callback)
	v.Set("scope", providerScopes(p, "read:user user:email"))
	v.Set("state", st.Name)
	v.Set("allow_signup", "true")
	if p.EnablePkce {
		v.Set("code_challenge", pkce.Challenge(st.IdpVerifier))
		v.Set("code_challenge_method", "S256")
	}
	return joinQuery(firstNonEmpty(p.CustomAuthUrl, githubAuthorizeEndpoint), v)
}

// githubTokenResponse is GitHub's (JSON, via Accept) token response.
type githubTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
}

// githubUser / githubEmail are the userinfo shapes iam reads.
type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

// githubExchange redeems the code for an access token, then reads the user and
// the verified-email list. The subject is GitHub's immutable numeric id; an
// email is treated as verified ONLY when GitHub reports it verified (primary
// preferred), so a local account is never linked to an unproven address.
func githubExchange(ctx context.Context, p *schema.Provider, st *schema.FederationState, code, callback string) (federatedIdentity, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", callback)
	form.Set("client_id", p.ClientId)
	form.Set("client_secret", p.ClientSecret)
	if p.EnablePkce {
		form.Set("code_verifier", st.IdpVerifier)
	}

	var tr githubTokenResponse
	if err := postFormJSON(ctx, firstNonEmpty(p.CustomTokenUrl, githubTokenEndpoint), form, http.Header{"Accept": {"application/json"}}, &tr); err != nil {
		return federatedIdentity{}, err
	}
	if tr.Error != "" || tr.AccessToken == "" {
		return federatedIdentity{}, errors.New("federation: GitHub token exchange failed")
	}

	userURL := firstNonEmpty(p.CustomUserInfoUrl, githubUserEndpoint)
	var gu githubUser
	if err := getJSONBearer(ctx, userURL, tr.AccessToken, &gu); err != nil {
		return federatedIdentity{}, err
	}
	if gu.ID == 0 {
		return federatedIdentity{}, errors.New("federation: GitHub user has no id")
	}

	email, verified := githubPrimaryEmail(ctx, userURL, tr.AccessToken, gu.Email)
	name := gu.Name
	if name == "" {
		name = gu.Login
	}
	return federatedIdentity{
		subject:       strconv.FormatInt(gu.ID, 10),
		email:         strings.ToLower(strings.TrimSpace(email)),
		emailVerified: verified,
		displayName:   name,
		avatar:        gu.AvatarURL,
	}, nil
}

// githubPrimaryEmail resolves the address to link on: the GitHub /user/emails
// list's primary-and-verified entry (then any verified entry). It returns
// (email, verified); when nothing is verified it returns verified=false so the
// broker provisions a fresh account rather than link by an unproven email. A
// failure to read the list is not fatal — it degrades to unverified.
func githubPrimaryEmail(ctx context.Context, userURL, token, fallback string) (string, bool) {
	var emails []githubEmail
	if err := getJSONBearer(ctx, strings.TrimRight(userURL, "/")+"/emails", token, &emails); err == nil {
		var anyVerified string
		for _, e := range emails {
			if !e.Verified {
				continue
			}
			if e.Primary {
				return e.Email, true
			}
			if anyVerified == "" {
				anyVerified = e.Email
			}
		}
		if anyVerified != "" {
			return anyVerified, true
		}
	}
	// No verified address available — the profile email is unproven.
	return fallback, false
}

// --- hardened HTTP + JWKS ---

// getJSON GETs a URL and decodes a JSON body, with the safety guard, a 200-only
// contract, and a body-size cap.
func getJSON(ctx context.Context, rawURL string, out any) error {
	req, err := newIdPRequest(ctx, http.MethodGet, rawURL, nil, nil)
	if err != nil {
		return err
	}
	return doJSON(req, out)
}

// getJSONBearer GETs a bearer-authenticated JSON endpoint (GitHub userinfo).
func getJSONBearer(ctx context.Context, rawURL, token string, out any) error {
	req, err := newIdPRequest(ctx, http.MethodGet, rawURL, nil, http.Header{
		"Authorization": {"Bearer " + token},
		"Accept":        {"application/vnd.github+json"},
	})
	if err != nil {
		return err
	}
	return doJSON(req, out)
}

// postFormJSON POSTs a urlencoded form and decodes a JSON body.
func postFormJSON(ctx context.Context, rawURL string, form url.Values, header http.Header, out any) error {
	req, err := newIdPRequest(ctx, http.MethodPost, rawURL, strings.NewReader(form.Encode()), header)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if req.Header.Get("Accept") == "" {
		req.Header.Set("Accept", "application/json")
	}
	return doJSON(req, out)
}

// newIdPRequest builds a context-bound request to a guard-checked URL with a
// stable User-Agent and the caller's headers.
func newIdPRequest(ctx context.Context, method, rawURL string, body io.Reader, header http.Header) (*http.Request, error) {
	safe, err := requireSafeURL(rawURL)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, method, safe, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hanzo-iam-federation")
	for k, vs := range header {
		for _, v := range vs {
			req.Header.Add(k, v)
		}
	}
	return req, nil
}

// doJSON executes a request and decodes a 200 JSON body under the size cap. A
// non-200 status is a hard failure — no partial trust in an error body.
func doJSON(req *http.Request, out any) error {
	resp, err := federationHTTPClient.Do(req)
	if err != nil {
		return fmt.Errorf("federation: idp request failed")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIdPBodyBytes))
	if err != nil {
		return fmt.Errorf("federation: reading idp response failed")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("federation: idp returned status %d", resp.StatusCode)
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("federation: decoding idp response failed")
	}
	return nil
}

// requireSafeURL parses rawURL and enforces the transport guard: http(s) only,
// a non-empty host, and https EXCEPT for loopback (so the production path is
// always TLS while tests may target 127.0.0.1). This also rejects file://, and
// any non-web scheme — an SSRF/exfiltration hygiene gate on the (admin-supplied)
// endpoint configuration.
func requireSafeURL(rawURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", fmt.Errorf("federation: invalid idp url")
	}
	if u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return "", fmt.Errorf("federation: idp url must be http(s) with a host")
	}
	if u.Scheme == "http" && !isLoopbackHost(u.Hostname()) {
		return "", fmt.Errorf("federation: idp url must use https")
	}
	return u.String(), nil
}

// isLoopbackHost reports whether host is a loopback name/address.
func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// jwkSet / jwk are the JSON Web Key Set shapes iam verifies id_tokens against.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// jwksKeyfunc returns a jwt.Keyfunc that fetches the issuer's JWKS and selects
// the verification key by the token's `kid`. When the token carries a kid, an
// exact match is required; a kid-less token is accepted only against a
// single-key set. The fetch happens inside the closure so it is bounded by the
// same hardened client and request context.
func jwksKeyfunc(ctx context.Context, jwksURL string) jwt.Keyfunc {
	return func(t *jwt.Token) (any, error) {
		var set jwkSet
		if err := getJSON(ctx, jwksURL, &set); err != nil {
			return nil, err
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			if len(set.Keys) != 1 {
				return nil, errors.New("federation: id_token has no kid and JWKS is not single-key")
			}
			return set.Keys[0].publicKey()
		}
		for _, k := range set.Keys {
			if k.Kid == kid {
				return k.publicKey()
			}
		}
		return nil, errors.New("federation: no JWKS key matches the id_token kid")
	}
}

// publicKey materializes a JWK into a crypto public key (RSA or EC). Only the
// two families iam signs with are supported; any other key type is refused.
func (k jwk) publicKey() (any, error) {
	switch k.Kty {
	case "RSA":
		n, err := b64uBigInt(k.N)
		if err != nil {
			return nil, err
		}
		eb, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
		if err != nil {
			return nil, errors.New("federation: bad JWKS RSA exponent")
		}
		e := 0
		for _, b := range eb {
			e = e<<8 | int(b)
		}
		if e == 0 {
			return nil, errors.New("federation: zero JWKS RSA exponent")
		}
		return &rsa.PublicKey{N: n, E: e}, nil
	case "EC":
		curve, err := ecCurve(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := b64uBigInt(k.X)
		if err != nil {
			return nil, err
		}
		y, err := b64uBigInt(k.Y)
		if err != nil {
			return nil, err
		}
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, fmt.Errorf("federation: unsupported JWKS key type %q", k.Kty)
	}
}

// ecCurve maps a JWK curve name to its elliptic.Curve.
func ecCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("federation: unsupported JWKS curve %q", crv)
	}
}

// b64uBigInt decodes a base64url (unpadded) big-endian integer — the JWK
// encoding for RSA modulus/exponent and EC coordinates.
func b64uBigInt(s string) (*big.Int, error) {
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, errors.New("federation: bad JWKS integer encoding")
	}
	return new(big.Int).SetBytes(b), nil
}

// --- small shared helpers ---

// providerScopes returns the provider's configured scopes, or a dialect default
// when it configures none.
func providerScopes(p *schema.Provider, fallback string) string {
	if s := strings.TrimSpace(p.Scopes); s != "" {
		return s
	}
	return fallback
}

// ensureOpenID guarantees the space-delimited scope contains "openid" (the OIDC
// requirement for an id_token), prepending it when absent.
func ensureOpenID(scope string) string {
	for _, s := range strings.Fields(scope) {
		if s == "openid" {
			return scope
		}
	}
	return strings.TrimSpace("openid " + scope)
}

// joinQuery appends encoded query values to a base URL, honoring an existing
// query string.
func joinQuery(base string, v url.Values) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	return base + sep + v.Encode()
}

// firstNonEmpty returns the first non-blank string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

// truthy interprets an id_token email_verified value (bool or string form).
func truthy(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	default:
		return false
	}
}
