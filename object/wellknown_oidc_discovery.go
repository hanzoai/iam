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

// selectOriginForHost picks the origin whose host (without scheme/port) matches
// the incoming Host header. Falls back to the first entry if no match.
// Empty input returns "".
func selectOriginForHost(originList []string, host string) string {
	if len(originList) == 0 {
		return ""
	}
	// Strip port from host: "iam.hanzo.ai:443" -> "iam.hanzo.ai".
	hostOnly := host
	if i := strings.IndexByte(host, ':'); i >= 0 {
		hostOnly = host[:i]
	}
	for _, o := range originList {
		// o is like "https://hanzo.id" — extract hostname for comparison.
		oHost := o
		// strip scheme
		if i := strings.Index(oHost, "://"); i >= 0 {
			oHost = oHost[i+3:]
		}
		// strip path
		if i := strings.IndexByte(oHost, '/'); i >= 0 {
			oHost = oHost[:i]
		}
		// strip port
		if i := strings.IndexByte(oHost, ':'); i >= 0 {
			oHost = oHost[:i]
		}
		if strings.EqualFold(oHost, hostOnly) {
			return o
		}
	}
	// No match: fall back to the first entry. This is the
	// expected path when origin is single-valued.
	return originList[0]
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

func GetOidcDiscovery(host string, applicationName string) OidcDiscovery {
	originFrontend, originBackend := getOriginFromHost(host)

	// If application is provided, use application-specific URLs
	var issuer, jwksUri string
	if applicationName != "" {
		// Application-specific issuer and endpoints (owner is always "admin")
		issuer = fmt.Sprintf("%s/.well-known/%s", originBackend, applicationName)
		jwksUri = fmt.Sprintf("%s/.well-known/%s/jwks", originBackend, applicationName)
	} else {
		// Default global issuer and endpoints
		issuer = originBackend
		jwksUri = fmt.Sprintf("%s/.well-known/jwks", originBackend)
	}

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
		AuthorizationEndpoint:                     fmt.Sprintf("%s/oauth/authorize", originFrontend),
		TokenEndpoint:                             fmt.Sprintf("%s/oauth/token", originBackend),
		UserinfoEndpoint:                          fmt.Sprintf("%s/oauth/userinfo", originBackend),
		DeviceAuthorizationEndpoint:               fmt.Sprintf("%s/oauth/device", originBackend),
		RegistrationEndpoint:                      fmt.Sprintf("%s/oauth/register", originBackend),
		JwksUri:                                   jwksUri,
		IntrospectionEndpoint:                     fmt.Sprintf("%s/oauth/introspect", originBackend),
		RevocationEndpoint:                        fmt.Sprintf("%s/oauth/revoke", originBackend),
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
		ClaimsSupported:                           []string{"iss", "ver", "sub", "aud", "iat", "exp", "id", "type", "displayName", "avatar", "permanentAvatar", "email", "phone", "location", "affiliation", "title", "homepage", "bio", "tag", "region", "language", "score", "ranking", "isOnline", "isAdmin", "isForbidden", "signupApplication", "ldap"},
		RequestParameterSupported:                 true,
		RequestObjectSigningAlgValuesSupported:    []string{"HS256", "HS384", "HS512"},
		EndSessionEndpoint:                        fmt.Sprintf("%s/oauth/logout", originBackend),
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
	for _, cert := range certs {
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

	return DeviceAuthResponse{
		DeviceCode:      deviceCode,
		UserCode:        userCode,
		VerificationUri: fmt.Sprintf("%s/login/oauth/device/%s", originFrontend, userCode),
		ExpiresIn:       120,
	}
}
