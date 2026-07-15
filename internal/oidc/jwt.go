// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam2/internal/schema"
)

// JWT access-token signing. iam2 signs RS256 today (the interoperable default);
// the ML-DSA-65 hybrid method rides in behind the same Signer interface via
// luxfi/crypto — kept out of this increment so the token core has no heavy
// crypto dep. The signing key comes from the Cert entity (PEM private key);
// tests use an ephemeral in-memory RSA key through the same path.

// Claims is the iam2 access-token claim set: the standard registered claims plus
// scope and owner (the org — a first-class Hanzo claim the SDK/validators read,
// scope-independent).
type Claims struct {
	jwt.RegisteredClaims
	Scope string `json:"scope,omitempty"`
	Owner string `json:"owner,omitempty"`
	Email string `json:"email,omitempty"`
	Name  string `json:"name,omitempty"`
}

// Signer signs access tokens with one key. Immutable after construction.
type Signer struct {
	method jwt.SigningMethod
	key    any    // *rsa.PrivateKey (RS256) — extend behind this interface
	kid    string // JWKS key id — the Cert name
	issuer string
}

// NewRSASignerFromCert builds a Signer from a Cert entity whose PrivateKey is a
// PEM-encoded RSA key. issuer is the host-relative issuer (https://<host>).
func NewRSASignerFromCert(cert *schema.Cert, issuer string) (*Signer, error) {
	if cert == nil || cert.PrivateKey == "" {
		return nil, errors.New("jwt: cert has no private key")
	}
	key, err := parseRSAPrivateKeyPEM(cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &Signer{method: jwt.SigningMethodRS256, key: key, kid: cert.Name, issuer: issuer}, nil
}

// NewRSASigner builds a Signer directly from an RSA key (used by tests and, in
// dev, from an ephemeral key when no Cert is configured).
func NewRSASigner(key *rsa.PrivateKey, kid, issuer string) *Signer {
	return &Signer{method: jwt.SigningMethodRS256, key: key, kid: kid, issuer: issuer}
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
			Audience:  jwt.ClaimStrings{app.ClientId},
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			NotBefore: jwt.NewNumericDate(now),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        jti,
		},
		Scope: scope,
		Owner: app.Organization,
		Email: email,
		Name:  name,
	}
	tok := jwt.NewWithClaims(s.method, claims)
	if s.kid != "" {
		tok.Header["kid"] = s.kid
	}
	return tok.SignedString(s.key)
}

// PublicKey returns the signer's RSA public key (for JWKS + test verification).
func (s *Signer) PublicKey() *rsa.PublicKey {
	if k, ok := s.key.(*rsa.PrivateKey); ok {
		return &k.PublicKey
	}
	return nil
}

// Kid returns the key id.
func (s *Signer) Kid() string { return s.kid }

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
