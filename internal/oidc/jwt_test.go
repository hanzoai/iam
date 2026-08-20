// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam2/internal/schema"
)

// testKey is a small (fast) RSA key — fine for tests; production uses the Cert.
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	// A fixed 2048-bit key generated once would be faster, but generating keeps
	// the test self-contained. 2048 is the JWKS minimum.
	k, err := rsaGenTest()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSign_RoundTripAndClaims(t *testing.T) {
	key := testKey(t)
	s := NewRSASigner(key, "cert-hanzo", "https://iam.hanzo.ai")
	now := time.Unix(1_800_000_000, 0)
	app := testApp()

	tokenStr, err := s.Sign(app, "hanzo/alice", "alice@hanzo.ai", "Alice", "openid profile", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with the public key + assert every claim.
	var claims Claims
	parsed, err := jwt.ParseWithClaims(tokenStr, &claims, func(*jwt.Token) (any, error) {
		return &key.PublicKey, nil
	}, jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) }))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token not valid")
	}
	if kid, _ := parsed.Header["kid"].(string); kid != "cert-hanzo" {
		t.Fatalf("kid = %q, want cert-hanzo", kid)
	}
	if claims.Issuer != "https://iam.hanzo.ai" {
		t.Fatalf("iss = %q", claims.Issuer)
	}
	if claims.Subject != "hanzo/alice" {
		t.Fatalf("sub = %q", claims.Subject)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "hanzo-console" {
		t.Fatalf("aud = %v, want [hanzo-console]", claims.Audience)
	}
	if claims.Owner != "hanzo" {
		t.Fatalf("owner = %q, want hanzo", claims.Owner)
	}
	if claims.Scope != "openid profile" || claims.Email != "alice@hanzo.ai" {
		t.Fatalf("scope/email wrong: %q / %q", claims.Scope, claims.Email)
	}
	if claims.ID == "" {
		t.Fatal("jti empty — every token must be uniquely identifiable")
	}
}

func TestSign_ExpiredTokenRejected(t *testing.T) {
	key := testKey(t)
	s := NewRSASigner(key, "cert-hanzo", "https://iam.hanzo.ai")
	now := time.Unix(1_800_000_000, 0)
	tokenStr, err := s.Sign(testApp(), "u", "", "", "openid", time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	// Validate well after expiry.
	var claims Claims
	_, err = jwt.ParseWithClaims(tokenStr, &claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(2 * time.Minute) }))
	if err == nil {
		t.Fatal("expired token accepted")
	}
}

func TestSign_WrongKeyRejected(t *testing.T) {
	s := NewRSASigner(testKey(t), "cert-hanzo", "https://iam.hanzo.ai")
	other := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	tokenStr, _ := s.Sign(testApp(), "u", "", "", "openid", time.Hour, now)
	var claims Claims
	_, err := jwt.ParseWithClaims(tokenStr, &claims, func(*jwt.Token) (any, error) { return &other.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}))
	if err == nil {
		t.Fatal("token verified under the wrong key")
	}
}

func TestParseRSAPrivateKeyPEM_RejectsGarbage(t *testing.T) {
	if _, err := parseRSAPrivateKeyPEM("not a pem"); err == nil {
		t.Fatal("garbage PEM accepted")
	}
}

func TestNewRSASignerFromCert_PEMRoundTrip(t *testing.T) {
	key := testKey(t)
	pemText := rsaKeyToPEM(t, key)
	cert := &schema.Cert{PrivateKey: pemText}
	cert.Name = "cert-hanzo"
	s, err := NewRSASignerFromCert(cert, "https://iam.hanzo.ai")
	if err != nil {
		t.Fatalf("load from cert PEM: %v", err)
	}
	if s.Kid() != "cert-hanzo" || s.PublicKey() == nil {
		t.Fatal("signer from cert missing kid/public key")
	}
	// Sign+verify to prove the parsed key works.
	now := time.Unix(1_800_000_000, 0)
	str, err := s.Sign(testApp(), "u", "", "", "openid", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	var claims Claims
	if _, err := jwt.ParseWithClaims(str, &claims, func(*jwt.Token) (any, error) { return s.PublicKey(), nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) })); err != nil {
		t.Fatalf("verify with cert-loaded key: %v", err)
	}
}
