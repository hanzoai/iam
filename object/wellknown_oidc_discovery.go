// Copyright 2021 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"strings"

	"github.com/go-jose/go-jose/v4"
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/util"
)

type OidcDiscovery struct {
	Issuer                                    string   `json:"issuer"`
	AuthorizationEndpoint                     string   `json:"authorization_endpoint"`
	TokenEndpoint                             string   `json:"token_endpoint"`
	UserinfoEndpoint                          string   `json:"userinfo_endpoint"`
	DeviceAuthorizationEndpoint               string   `json:"device_authorization_endpoint"`
	RegistrationEndpoint                      string   `json:"registration_endpoint,omitempty"`
	JwksUri                                   string   `json:"jwks_uri"`
	IntrospectionEndpoint                     string   `json:"introspection_endpoint"`
	RevocationEndpoint                        string   `json:"revocation_endpoint"`
	ResponseTypesSupported                    []string `json:"response_types_supported"`
	ResponseModesSupported                    []string `json:"response_modes_supported"`
	GrantTypesSupported                       []string `json:"grant_types_supported"`
	SubjectTypesSupported                     []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported          []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                           []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported         []string `json:"token_endpoint_auth_methods_supported"`
	IntrospectionEndpointAuthMethodsSupported []string `json:"introspection_endpoint_auth_methods_supported"`
	RevocationEndpointAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported             []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                           []string `json:"claims_supported"`
	RequestParameterSupported                 bool     `json:"request_parameter_supported"`
	RequestObjectSigningAlgValuesSupported    []string `json:"request_object_signing_alg_values_supported"`
	EndSessionEndpoint                        string   `json:"end_session_endpoint"`
}

type WebFinger struct {
	Subject    string             `json:"subject"`
	Links      []WebFingerLink    `json:"links"`
	Aliases    *[]string          `json:"aliases,omitempty"`
	Properties *map[string]string `json:"properties,omitempty"`
}

type WebFingerLink struct {
	Rel  string `json:"rel"`
	Href string `json:"href"`
}

func isIpAddress(host string) bool {
	// Attempt to split the host and port, ignoring the error
	hostWithoutPort, _, err := net.SplitHostPort(host)
	if err != nil {
		// If an error occurs, it might be because there's no port
		// In that case, use the original host string
		hostWithoutPort = host
	}

	// Attempt to parse the host as an IP address (both IPv4 and IPv6)
	ip := net.ParseIP(hostWithoutPort)
	// if host is not nil is an IP address else is not an IP address
	return ip != nil
}

// SplitOriginList parses a comma-separated origin config value into a slice
// of trimmed origins. Empty entries are dropped. Returns nil for empty input.
//
// Multi-tenant IAM serves many host names from one backend, so `origin` (and
// `originFrontend`) in app.conf may be either a single origin or a CSV. The
// discovery endpoint must emit exactly one issuer per request — the one that
// matches the incoming host — not the entire CSV joined back together.
func SplitOriginList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// originHostname extracts the bare hostname (no scheme, path, or port) from an
// origin URL ("https://hanzo.id:443/x" -> "hanzo.id") or a bare Host header
// ("iam.hanzo.ai:443" -> "iam.hanzo.ai"). One implementation, shared by every
// host-matching path below.
func originHostname(s string) string {
	h := s
	if i := strings.Index(h, "://"); i >= 0 {
		h = h[i+3:]
	}
	if i := strings.IndexByte(h, '/'); i >= 0 {
		h = h[:i]
	}
	if i := strings.IndexByte(h, ':'); i >= 0 {
		h = h[:i]
	}
	return h
}

// selectOriginForHost picks the origin whose host (without scheme/port) matches
// the incoming Host header. Falls back to the first entry if no match.
// Empty input returns "".
func selectOriginForHost(originList []string, host string) string {
	if len(originList) == 0 {
		return ""
	}
	hostOnly := originHostname(host)
	for _, o := range originList {
		if strings.EqualFold(originHostname(o), hostOnly) {
			return o
		}
	}
	// No match: fall back to the first entry. This is the
	// expected path when origin is single-valued.
	return originList[0]
}

// brandLabel reduces a host to its brand label so every host of one brand maps
// to the same canonical issuer: the service prefix (iam/id/auth/www/api) is
// stripped, then the first label of the remaining registrable domain is taken.
// "iam.hanzo.ai" -> "hanzo", "hanzo.id" -> "hanzo", "id.lux.network" -> "lux".
func brandLabel(host string) string {
	h := strings.ToLower(originHostname(host))
	for _, p := range []string{"iam.", "id.", "auth.", "www.", "api."} {
		if strings.HasPrefix(h, p) {
			h = h[len(p):]
			break
		}
	}
	if i := strings.IndexByte(h, '.'); i >= 0 {
		return h[:i]
	}
	return h
}

// canonicalIssuer resolves the ONE canonical token issuer for the brand serving
// `host`. The JWT `iss`, the OIDC discovery issuer, and OAuth audience checks all
// use it so a brand's issuer is STABLE regardless of which host minted the token
// — a token minted via iam.hanzo.ai (the API host) carries iss=https://hanzo.id
// (the login origin), which is exactly what the gateway and cloud-api validate.
//
// White-label by construction: the canonical issuer is the matching entry from
// originFrontend (the per-brand login origins), selected by exact host first,
// then by brand label (so iam./id./auth. API hosts fold into their brand's login
// origin). It NEVER returns another brand's origin, and falls back to the
// host-derived backend origin only when no brand frontend is configured.
func canonicalIssuer(host string) string {
	_, originBackend := getOriginFromHost(host)
	frontList := SplitOriginList(conf.GetConfigString("originFrontend"))
	return resolveCanonicalIssuer(host, frontList, originBackend)
}

// resolveCanonicalIssuer is the pure core of canonicalIssuer (no config lookup,
// so it is unit-testable): given the request host, the configured per-brand login
// origins, and the host-derived backend fallback, it returns the brand's
// canonical issuer.
func resolveCanonicalIssuer(host string, frontList []string, originBackend string) string {
	if len(frontList) == 0 {
		return originBackend
	}
	hostOnly := originHostname(host)
	// Exact frontend host match: a login origin is its own issuer.
	for _, o := range frontList {
		if strings.EqualFold(originHostname(o), hostOnly) {
			return o
		}
	}
	// Brand-label match: fold iam.hanzo.ai / id.hanzo.ai / hanzo.ai -> hanzo.id.
	if want := brandLabel(host); want != "" {
		for _, o := range frontList {
			if brandLabel(o) == want {
				return o
			}
		}
	}
	// Unknown brand: preserve the host-derived behavior (no cross-brand leak).
	return originBackend
}

func getOriginFromHostInternal(host string) (string, string) {
	originList := SplitOriginList(conf.GetConfigString("origin"))
	if matched := selectOriginForHost(originList, host); matched != "" {
		return matched, matched
	}

	isDev := conf.GetConfigString("runmode") == "dev"
	// "door.iam.com"
	protocol := "https://"
	if !strings.Contains(host, ".") {
		// "localhost:8000" or "computer-name:80"
		protocol = "http://"
	} else if isIpAddress(host) {
		// "192.168.0.10"
		protocol = "http://"
	}

	if host == "localhost:8000" && isDev {
		return fmt.Sprintf("%s%s", protocol, "localhost:7001"), fmt.Sprintf("%s%s", protocol, "localhost:8000")
	} else {
		return fmt.Sprintf("%s%s", protocol, host), fmt.Sprintf("%s%s", protocol, host)
	}
}

func getOriginFromHost(host string) (string, string) {
	originF, originB := getOriginFromHostInternal(host)

	frontList := SplitOriginList(conf.GetConfigString("originFrontend"))
	if matched := selectOriginForHost(frontList, host); matched != "" {
		originF = matched
	}

	return originF, originB
}

// Canonical public OIDC paths. The IAM service publishes its discovery doc
// using ONLY these — external consumers (IdPs, SDKs, OIDC libraries) see
// exactly one shape per endpoint. /v1/iam/* is the law.
const (
	OidcPathAuthorize     = "/v1/iam/oauth/authorize"
	OidcPathToken         = "/v1/iam/oauth/token"
	OidcPathUserinfo      = "/v1/iam/oauth/userinfo"
	OidcPathDevice        = "/v1/iam/oauth/device"
	OidcPathRegister      = "/v1/iam/oauth/register"
	OidcPathIntrospect    = "/v1/iam/oauth/introspect"
	OidcPathRevoke        = "/v1/iam/oauth/revoke"
	OidcPathEndSession    = "/v1/iam/oauth/logout"
	OidcPathWellKnownBase = "/v1/iam/.well-known"
)

// buildIssuerAndJwks composes the canonical issuer and JWKS URI from a
// single backend origin. Pure string composition — kept separate from
// GetOidcDiscovery so it stays testable without the application DB
// lookup that GetOidcDiscovery performs to merge per-app scopes.
//
// origin MUST be a single URL (no CSV). selectOriginForHost in
// getOriginFromHost guarantees this for the request-scoped path.
func buildIssuerAndJwks(origin, applicationName string) (issuer, jwksUri string) {
	if applicationName != "" {
		return fmt.Sprintf("%s%s/%s", origin, OidcPathWellKnownBase, applicationName),
			fmt.Sprintf("%s%s/%s/jwks", origin, OidcPathWellKnownBase, applicationName)
	}
	return origin, fmt.Sprintf("%s%s/jwks", origin, OidcPathWellKnownBase)
}

func GetOidcDiscovery(host string, applicationName string) OidcDiscovery {
	originFrontend, originBackend := getOriginFromHost(host)

	// Issuer + JWKS are brand-canonical (e.g. https://hanzo.id) so the discovery
	// doc's issuer matches the JWT `iss` and the JWKS URI the gateway validates
	// against, regardless of which host served the request.
	issuer, jwksUri := buildIssuerAndJwks(canonicalIssuer(host), applicationName)

	// Default OIDC scopes
	scopes := []string{"openid", "email", "profile", "address", "phone", "offline_access"}

	// Merge application-specific custom scopes if application is provided
	if applicationName != "" {
		applicationId := util.GetId("admin", applicationName)
		application, err := GetApplication(applicationId)
		if err == nil && application != nil && len(application.Scopes) > 0 {
			for _, scope := range application.Scopes {
				// Add custom scope names to the scopes list
				if scope.Name != "" {
					scopes = append(scopes, scope.Name)
				}
			}
		}
	}

	// Examples:
	// https://login.okta.com/.well-known/openid-configuration
	// https://auth0.auth0.com/.well-known/openid-configuration
	// https://accounts.google.com/.well-known/openid-configuration
	// https://access.line.me/.well-known/openid-configuration
	// Auth methods supported at token/introspection/revocation endpoints.
	// RFC 6749 §2.3, RFC 7523 §2.2
	authMethods := []string{"client_secret_basic", "client_secret_post", "private_key_jwt"}

	oidcDiscovery := OidcDiscovery{
		Issuer:                                    issuer,
		AuthorizationEndpoint:                     fmt.Sprintf("%s%s", originFrontend, OidcPathAuthorize),
		TokenEndpoint:                             fmt.Sprintf("%s%s", originBackend, OidcPathToken),
		UserinfoEndpoint:                          fmt.Sprintf("%s%s", originBackend, OidcPathUserinfo),
		DeviceAuthorizationEndpoint:               fmt.Sprintf("%s%s", originBackend, OidcPathDevice),
		RegistrationEndpoint:                      fmt.Sprintf("%s%s", originBackend, OidcPathRegister),
		JwksUri:                                   jwksUri,
		IntrospectionEndpoint:                     fmt.Sprintf("%s%s", originBackend, OidcPathIntrospect),
		RevocationEndpoint:                        fmt.Sprintf("%s%s", originBackend, OidcPathRevoke),
		ResponseTypesSupported:                    []string{"code"},
		ResponseModesSupported:                    []string{"query", "fragment", "form_post"},
		GrantTypesSupported:                       []string{"authorization_code", "client_credentials", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code", "urn:ietf:params:oauth:grant-type:token-exchange"},
		SubjectTypesSupported:                     []string{"public"},
		IdTokenSigningAlgValuesSupported:          []string{"RS256", "RS512", "ES256", "ES384", "ES512", algMLDSA65},
		ScopesSupported:                           scopes,
		TokenEndpointAuthMethodsSupported:         authMethods,
		IntrospectionEndpointAuthMethodsSupported: authMethods,
		RevocationEndpointAuthMethodsSupported:    authMethods,
		CodeChallengeMethodsSupported:             []string{"S256"},
		ClaimsSupported:                           []string{"iss", "ver", "sub", "aud", "iat", "exp", "id", "type", "owner", "organization", "groups", "displayName", "avatar", "permanentAvatar", "email", "phone", "location", "affiliation", "title", "homepage", "bio", "tag", "region", "language", "score", "ranking", "isOnline", "isAdmin", "isForbidden", "signupApplication", "ldap"},
		RequestParameterSupported:                 true,
		RequestObjectSigningAlgValuesSupported:    []string{"HS256", "HS384", "HS512"},
		EndSessionEndpoint:                        fmt.Sprintf("%s%s", originBackend, OidcPathEndSession),
	}

	return oidcDiscovery
}

// JsonWebKeySet is a JWKS container that supports both traditional (RSA/EC)
// and post-quantum (ML-DSA-65) keys. Traditional keys use go-jose serialization;
// ML-DSA-65 keys use the IETF draft format (kty=MLDSA, alg=MLDSA65).
type JsonWebKeySet struct {
	Keys []interface{} `json:"keys"`
}

// MLDSA65WebKey is the JWK representation of an ML-DSA-65 public key,
// following the IETF draft convention for post-quantum JWK.
type MLDSA65WebKey struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	X   string `json:"x"` // base64url-encoded raw public key
}

func GetJsonWebKeySet(applicationName string) (JsonWebKeySet, error) {
	jwks := JsonWebKeySet{}

	// Get certs - use application-specific cert if applicationName is provided
	var certs []*Cert
	var err error
	if applicationName != "" {
		// Try to get application-specific cert (owner is always "admin")
		applicationId := util.GetId("admin", applicationName)
		application, err := GetApplication(applicationId)
		if err == nil && application != nil && application.Cert != "" {
			certId := util.GetId(application.Owner, application.Cert)
			cert, err := GetCert(certId)
			if err == nil && cert != nil {
				certs = []*Cert{cert}
			}
		}
	}

	// Fallback to global certs if no application-specific cert found
	if len(certs) == 0 {
		certs, err = GetCerts("")
		if err != nil {
			return jwks, err
		}
	}

	// follows the protocol rfc 7517(draft)
	// link here: https://self-issued.info/docs/draft-ietf-jose-json-web-key.html
	// or https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-key
	// Dedupe by kid (cert.Name): an identical cert can be collected from
	// multiple owners (e.g. a global "admin" cert plus an org-scoped copy of
	// the same key), which would emit two JWKS entries with the same kid.
	// go-jose rejects a duplicate kid with JWKSMultipleMatchingKeys, which
	// fails JWT verification for every app that signs with that kid. One key
	// per kid, always.
	seen := make(map[string]bool)
	for _, cert := range certs {
		if seen[cert.Name] {
			continue
		}
		seen[cert.Name] = true
		if cert.Certificate == "" {
			return jwks, fmt.Errorf("the certificate field should not be empty for the cert: %v", cert)
		}

		// ML-DSA-65 (FIPS 204) keys use raw key material, not x509.
		if cert.Type == "pq" && cert.CryptoAlgorithm == algMLDSA65 {
			pk, err := parseMLDSA65PublicKey(cert.Certificate)
			if err != nil {
				return jwks, err
			}
			jwks.Keys = append(jwks.Keys, mldsa65JWK(cert.Name, pk))
			continue
		}

		if cert.Type != "x509" {
			continue
		}

		certPemBlock := []byte(cert.Certificate)
		certDerBlock, _ := pem.Decode(certPemBlock)
		x509Cert, err := x509.ParseCertificate(certDerBlock.Bytes)
		if err != nil {
			return jwks, err
		}

		var jwk jose.JSONWebKey
		jwk.Key = x509Cert.PublicKey
		jwk.Certificates = []*x509.Certificate{x509Cert}
		jwk.KeyID = cert.Name
		jwk.Algorithm = cert.CryptoAlgorithm
		jwk.Use = "sig"
		jwks.Keys = append(jwks.Keys, jwk)
	}

	return jwks, nil
}

func GetWebFinger(resource string, rels []string, host string, applicationName string) (WebFinger, error) {
	wf := WebFinger{}

	resourceSplit := strings.Split(resource, ":")

	if len(resourceSplit) != 2 {
		return wf, fmt.Errorf("invalid resource")
	}

	resourceType := resourceSplit[0]
	resourceValue := resourceSplit[1]

	oidcDiscovery := GetOidcDiscovery(host, applicationName)

	switch resourceType {
	case "acct":
		user, err := GetUserByEmailOnly(resourceValue)
		if err != nil {
			return wf, err
		}

		if user == nil {
			return wf, fmt.Errorf("user not found")
		}

		wf.Subject = resource

		for _, rel := range rels {
			if rel == "http://openid.net/specs/connect/1.0/issuer" {
				wf.Links = append(wf.Links, WebFingerLink{
					Rel:  "http://openid.net/specs/connect/1.0/issuer",
					Href: oidcDiscovery.Issuer,
				})
			}
		}
	}

	return wf, nil
}

func GetDeviceAuthResponse(deviceCode string, userCode string, host string) DeviceAuthResponse {
	originFrontend, _ := getOriginFromHost(host)

	// The verification URI already embeds the user_code, so it doubles as the
	// RFC 8628 `verification_uri_complete` (one-click approval — what the `dev`
	// CLI and IDE plugins render as a clickable link on a headless box).
	verificationUri := fmt.Sprintf("%s%s/%s", originFrontend, OidcPathDevice, userCode)

	return DeviceAuthResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationUri:         verificationUri,
		VerificationUriComplete: verificationUri,
		ExpiresIn:               DeviceCodeExpirySeconds,
		Interval:                DeviceCodePollInterval,
	}
}
