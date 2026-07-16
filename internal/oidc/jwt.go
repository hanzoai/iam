// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam2/internal/schema"
)

// JWT token signing. The signing algorithm is a property of the signing Cert's
// key, not a global: an RSA cert signs RS256 (the interoperable default that the
// live hanzo.id JWKS serves), an EC cert signs ES256/384/512, and a post-quantum
// ML-DSA-65 cert signs MLDSA65 (mldsa.go, behind the same jwt.SigningMethod
// seam). The classical path is the load-bearing interop path — every existing
// verifier reads the RS256 keys published in the JWKS; ML-DSA is additive and
// inert until an ML-DSA Cert is configured. Keys come from the Cert entity
// (KMS-backed); tests inject an ephemeral in-memory key through the same path.

// Claims is the iam2 token claim set: the standard registered claims plus the
// Hanzo first-class claims the SDK and downstream validators read. owner and
// organization are the tenant (both the org slug); scope carries the granted
// scopes; nonce is echoed into the id_token; tokenType distinguishes an
// access-token from an id-token. A field is emitted only when populated, so one
// struct serves both token shapes without leaking empty claims.
type Claims struct {
	jwt.RegisteredClaims
	Scope        string `json:"scope,omitempty"`
	Owner        string `json:"owner,omitempty"`
	Organization string `json:"organization,omitempty"`
	Email        string `json:"email,omitempty"`
	Name         string `json:"name,omitempty"`
	Nonce        string `json:"nonce,omitempty"`
	Azp          string `json:"azp,omitempty"`
	TokenType    string `json:"tokenType,omitempty"`
}

// Signer signs tokens with one key under one algorithm. Immutable after
// construction; the (method, key, kid, alg) tuple is fixed to the Cert it was
// built from so a token can never be signed under a key/alg mismatch.
type Signer struct {
	method jwt.SigningMethod
	key    any    // *rsa.PrivateKey | *ecdsa.PrivateKey | *mldsa65.PrivateKey
	kid    string // JWKS key id — the Cert name
	alg    string // JOSE alg — "RS256" | "ES256" | … | "MLDSA65"
	issuer string
}

// NewSignerFromCert builds a Signer from a Cert, selecting the algorithm from
// the cert's key type: RSA → RS256 (or RS512 when the app pins it), EC → ES256/
// ES384/ES512 by curve, ML-DSA → MLDSA65. issuer is the canonical OIDC issuer
// (https://<host>) that discovery advertises; it is pinned into every token so
// id_token `iss` matches the discovery document. app may be nil (the method is
// then chosen purely from the key type).
func NewSignerFromCert(cert *schema.Cert, app *schema.Application, issuer string) (*Signer, error) {
	if cert == nil {
		return nil, errors.New("jwt: nil cert")
	}
	// Post-quantum ML-DSA-65 cert: raw key material, own signing method.
	if isMLDSACert(cert) {
		key, err := parseMLDSA65PrivateKey(cert.PrivateKey)
		if err != nil {
			return nil, err
		}
		return &Signer{method: SigningMethodMLDSA65, key: key, kid: cert.Name, alg: algMLDSA65, issuer: issuer}, nil
	}
	if cert.PrivateKey == "" {
		return nil, errors.New("jwt: cert has no private key")
	}
	key, err := parsePrivateKeyPEM(cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	method, alg, err := methodForKey(key, pinnedMethod(app))
	if err != nil {
		return nil, err
	}
	return &Signer{method: method, key: key, kid: cert.Name, alg: alg, issuer: issuer}, nil
}

// NewRSASignerFromCert builds an RS256 Signer from a Cert whose PrivateKey is a
// PEM RSA key. Retained as the explicit RSA constructor; NewSignerFromCert is
// the general dispatch used by the token endpoint.
func NewRSASignerFromCert(cert *schema.Cert, issuer string) (*Signer, error) {
	if cert == nil || cert.PrivateKey == "" {
		return nil, errors.New("jwt: cert has no private key")
	}
	key, err := parseRSAPrivateKeyPEM(cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &Signer{method: jwt.SigningMethodRS256, key: key, kid: cert.Name, alg: "RS256", issuer: issuer}, nil
}

// NewRSASigner builds an RS256 Signer directly from an RSA key (tests and, in
// dev, an ephemeral key when no Cert is configured).
func NewRSASigner(key *rsa.PrivateKey, kid, issuer string) *Signer {
	return &Signer{method: jwt.SigningMethodRS256, key: key, kid: kid, alg: "RS256", issuer: issuer}
}

// Sign issues a signed access token for (app, user) with the given scope. now is
// injected for testability; ttl is the token lifetime. The audience is the app's
// clientId (validators fail closed when aud != clientId).
func (s *Signer) Sign(app *schema.Application, userID, email, name, scope string, ttl time.Duration, now time.Time) (string, error) {
	if s == nil {
		return "", errors.New("jwt: nil signer")
	}
	jti, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  audienceFor(app, ""),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope:        scope,
		Owner:        app.Organization,
		Organization: app.Organization,
		Email:        email,
		Name:         name,
		Azp:          app.ClientId,
		TokenType:    "access-token",
	}
	return s.signClaims(claims)
}

// SignUserToken mints an access token a confidential client issues ON BEHALF OF a
// target user — the issue-user-token primitive. Unlike Sign (which stamps the
// APP's org as the owner claim), every authority claim here is the TARGET USER's:
// the subject and owner are the user's, so a resource server that scopes on the
// validated `owner` claim (cloud's SanitizeIdentity) scopes to the USER's tenant,
// never the minting client's. `aud` is the caller-resolved audience (an explicit
// RFC 8707 resource, else the user's own app) and `azp` records the minting
// client. Signed under this signer's trusted cert + canonical issuer, so the same
// JWKS verifies it — the token is indistinguishable from one the user obtained
// directly, which is the point. The Signer stays decoupled from schema.User: the
// handler resolves and passes the values it authorized.
func (s *Signer) SignUserToken(subject, owner, aud, azp, email, name, scope string, ttl time.Duration, now time.Time) (string, error) {
	if s == nil {
		return "", errors.New("jwt: nil signer")
	}
	jti, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{aud},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope:        scope,
		Owner:        owner,
		Organization: owner,
		Email:        email,
		Name:         name,
		Azp:          azp,
		TokenType:    "access-token",
	}
	return s.signClaims(claims)
}

// SignID issues an OIDC id_token for (app, user). It differs from the access
// token by carrying the echoed nonce and by declaring tokenType "id-token"; the
// audience is the client the token was minted for (the RP), and iss matches the
// discovery issuer so a standard OIDC client validates it.
func (s *Signer) SignID(app *schema.Application, userID, email, name, scope, nonce string, ttl time.Duration, now time.Time) (string, error) {
	if s == nil {
		return "", errors.New("jwt: nil signer")
	}
	jti, err := newOpaqueToken()
	if err != nil {
		return "", err
	}
	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{app.ClientId},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope:        scope,
		Owner:        app.Organization,
		Organization: app.Organization,
		Email:        email,
		Name:         name,
		Nonce:        nonce,
		Azp:          app.ClientId,
		TokenType:    "id-token",
	}
	return s.signClaims(claims)
}

// signClaims is the single choke point that turns a claim set into a signed
// compact JWS under this signer's fixed (method, key, kid).
func (s *Signer) signClaims(claims Claims) (string, error) {
	tok := jwt.NewWithClaims(s.method, claims)
	if s.kid != "" {
		tok.Header["kid"] = s.kid
	}
	return tok.SignedString(s.key)
}

// PublicKey returns the signer's RSA public key, or nil for a non-RSA signer
// (JWKS + verification read the public key from the Cert, not the Signer).
func (s *Signer) PublicKey() *rsa.PublicKey {
	if k, ok := s.key.(*rsa.PrivateKey); ok {
		return &k.PublicKey
	}
	return nil
}

// Kid returns the key id (the Cert name).
func (s *Signer) Kid() string { return s.kid }

// Alg returns the JOSE algorithm this signer uses (matches the JWKS `alg`).
func (s *Signer) Alg() string { return s.alg }

// audienceFor computes the token audience per RFC 8707: an explicit resource
// indicator wins; a shared application scopes the audience to the org; otherwise
// the audience is the client id (the value validators check).
func audienceFor(app *schema.Application, resource string) jwt.ClaimStrings {
	if resource != "" {
		return jwt.ClaimStrings{resource}
	}
	if app.IsShared && app.Organization != "" {
		return jwt.ClaimStrings{app.ClientId + "-org-" + app.Organization}
	}
	return jwt.ClaimStrings{app.ClientId}
}

// pinnedMethod is the app's requested signing method (TokenSigningMethod), or ""
// to let the key type decide.
func pinnedMethod(app *schema.Application) string {
	if app == nil {
		return ""
	}
	return app.TokenSigningMethod
}

// methodForKey maps a parsed private key (and an optional app-pinned method
// within the same family) to a jwt.SigningMethod and its JOSE alg name.
func methodForKey(key any, pinned string) (jwt.SigningMethod, string, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if pinned == "RS512" {
			return jwt.SigningMethodRS512, "RS512", nil
		}
		return jwt.SigningMethodRS256, "RS256", nil
	case *ecdsa.PrivateKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return jwt.SigningMethodES256, "ES256", nil
		case 384:
			return jwt.SigningMethodES384, "ES384", nil
		case 521:
			return jwt.SigningMethodES512, "ES512", nil
		}
		return nil, "", fmt.Errorf("jwt: unsupported EC curve bit size %d", k.Curve.Params().BitSize)
	default:
		return nil, "", errors.New("jwt: unsupported private key type")
	}
}

// parsePrivateKeyPEM decodes a classical (RSA or EC) PEM private key.
func parsePrivateKeyPEM(pemText string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("jwt: private key is not valid PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	if k, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwt: parse private key: %w", err)
	}
	signer, ok := k8.(crypto.Signer)
	if !ok {
		return nil, errors.New("jwt: PKCS#8 key is not a signing key")
	}
	return signer, nil
}

// parseRSAPrivateKeyPEM decodes a PEM RSA private key (PKCS#1 or PKCS#8).
func parseRSAPrivateKeyPEM(pemText string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("jwt: private key is not valid PEM")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k8, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwt: parse private key: %w", err)
	}
	rk, ok := k8.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("jwt: private key is not RSA")
	}
	return rk, nil
}
