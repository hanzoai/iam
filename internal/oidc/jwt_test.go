// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto/rsa"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam/internal/schema"
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

	tokenStr, err := s.Sign(app, "hanzo/alice", "alice@hanzo.ai", "Alice", "", "openid profile", nil, time.Hour, now)
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
	tokenStr, err := s.Sign(testApp(), "u", "", "", "", "openid", nil, time.Minute, now)
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
	tokenStr, _ := s.Sign(testApp(), "u", "", "", "", "openid", nil, time.Hour, now)
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
	str, err := s.Sign(testApp(), "u", "", "", "", "openid", nil, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	var claims Claims
	if _, err := jwt.ParseWithClaims(str, &claims, func(*jwt.Token) (any, error) { return s.PublicKey(), nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) })); err != nil {
		t.Fatalf("verify with cert-loaded key: %v", err)
	}
}

// TestSignEmitsPreferredUsername pins that the username reaches the wire. Discovery
// has advertised preferred_username in claims_supported all along while no token
// emitted it, and `name` carries the DISPLAY name — so a resource server needing the
// `<owner>/<name>` username had nothing to read. cloud's money path addresses a
// wallet as `<org>/<username>`; without this claim it fell back to `name` and
// addressed `hanzo/Zach Kelling` while the balance sat in `hanzo/z`.
func TestSignEmitsPreferredUsername(t *testing.T) {
	s := NewRSASigner(testKey(t), "cert-hanzo", "https://iam.hanzo.ai")
	now := time.Unix(1_800_000_000, 0)
	tokenStr, err := s.Sign(testApp(), "hanzo/z", "z@hanzo.ai", "Zach Kelling", "z", "openid profile", nil, time.Hour, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var got Claims
	if _, _, err := jwt.NewParser().ParseUnverified(tokenStr, &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.PreferredUsername != "z" {
		t.Fatalf("preferred_username = %q; want %q", got.PreferredUsername, "z")
	}
	// The display name is still carried, and must NOT be the username.
	if got.Name != "Zach Kelling" {
		t.Fatalf("name = %q; want the display name preserved", got.Name)
	}
	// A machine token has no user, so the claim is omitted entirely rather than
	// emitted empty — omitempty is what keeps one struct serving both shapes.
	machine, err := s.Sign(testApp(), "hanzo/app", "", "app", "", "openid", nil, time.Hour, now)
	if err != nil {
		t.Fatalf("Sign machine: %v", err)
	}
	if strings.Contains(machine, "preferred_username") {
		t.Fatal("machine token must omit preferred_username, not emit it empty")
	}
}
