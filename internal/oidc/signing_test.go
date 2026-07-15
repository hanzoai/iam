// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
)

// NewSignerFromCert picks the algorithm from the key type — RSA→RS256,
// EC-P256→ES256, ML-DSA→MLDSA65 — so a token can never be signed under a
// mismatched alg.
func TestNewSignerFromCert_DispatchesByKeyType(t *testing.T) {
	cases := []struct {
		name string
		cert *schema.Cert
		want string
	}{
		{"rsa", rsaCert(t, "cert-rsa"), "RS256"},
		{"ec", ecCert(t, "cert-ec"), "ES256"},
		{"mldsa", mldsaCert(t, "cert-pq"), "MLDSA65"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := NewSignerFromCert(tc.cert, testApp(), "https://hanzo.id")
			if err != nil {
				t.Fatalf("build signer: %v", err)
			}
			if s.Alg() != tc.want {
				t.Fatalf("alg = %q, want %q", s.Alg(), tc.want)
			}
		})
	}
}

// An ES256 token round-trips: signed under the EC key, verified under its public
// half, with the expected claims.
func TestSigner_ES256RoundTrip(t *testing.T) {
	cert := ecCert(t, "cert-ec")
	s, err := NewSignerFromCert(cert, testApp(), "https://hanzo.id")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	tok, err := s.Sign(testApp(), "hanzo/alice", "alice@hanzo.ai", "Alice", "openid", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	pub, _, _, err := certPublicKey(cert)
	if err != nil {
		t.Fatal(err)
	}
	var claims Claims
	parsed, err := jwt.ParseWithClaims(tok, &claims, func(*jwt.Token) (any, error) { return pub, nil },
		jwt.WithValidMethods([]string{"ES256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) }))
	if err != nil || !parsed.Valid {
		t.Fatalf("verify ES256: %v", err)
	}
	if claims.Subject != "hanzo/alice" || claims.Owner != "hanzo" {
		t.Fatalf("claims wrong: %+v", claims)
	}
}

// The post-quantum path is real: an ML-DSA-65 token signed by the Signer
// verifies through the full package verify path (resolve kid → cert → public
// key → circl Verify).
func TestSigner_MLDSA65RoundTripThroughVerify(t *testing.T) {
	db := openTestDB(t)
	cert := mldsaCert(t, "cert-pq")
	persistCert(t, db, cert)

	s, err := NewSignerFromCert(cert, testApp(), "https://hanzo.id")
	if err != nil {
		t.Fatal(err)
	}
	if s.Alg() != algMLDSA65 {
		t.Fatalf("alg = %q, want MLDSA65", s.Alg())
	}
	now := time.Unix(1_800_000_000, 0)
	nowFuncSet(t, now.Add(time.Minute))

	tok, err := s.SignID(testApp(), "hanzo/alice", "alice@hanzo.ai", "Alice", "openid", "nonce-xyz", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := verifyToken(context.Background(), db, tok)
	if err != nil {
		t.Fatalf("verify MLDSA65 token: %v", err)
	}
	if claims.Subject != "hanzo/alice" || claims.Nonce != "nonce-xyz" || claims.TokenType != "id-token" {
		t.Fatalf("claims wrong: %+v", claims)
	}
}

// SignID echoes the nonce and marks the token as an id-token (OIDC Core).
func TestSignID_EchoesNonce(t *testing.T) {
	key := sharedKey(t)
	s := NewRSASigner(key, "cert-hanzo", "https://hanzo.id")
	now := time.Unix(1_800_000_000, 0)
	tok, err := s.SignID(testApp(), "hanzo/alice", "a@h.ai", "Alice", "openid", "n-123", time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	var claims Claims
	if _, err := jwt.ParseWithClaims(tok, &claims, func(*jwt.Token) (any, error) { return &key.PublicKey, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithTimeFunc(func() time.Time { return now.Add(time.Minute) })); err != nil {
		t.Fatal(err)
	}
	if claims.Nonce != "n-123" {
		t.Fatalf("nonce = %q, want n-123", claims.Nonce)
	}
	if claims.TokenType != "id-token" {
		t.Fatalf("tokenType = %q, want id-token", claims.TokenType)
	}
}

// verifyToken refuses alg:none — a forged unsigned token can never select a
// trusting verification path.
func TestVerifyToken_RejectsAlgNone(t *testing.T) {
	db := openTestDB(t)
	persistCert(t, db, rsaCert(t, "cert-hanzo"))

	header := b64url(t, `{"alg":"none","typ":"JWT","kid":"cert-hanzo"}`)
	payload := b64url(t, `{"sub":"hanzo/attacker","iss":"https://hanzo.id"}`)
	forged := header + "." + payload + "."
	if _, err := verifyToken(context.Background(), db, forged); err == nil {
		t.Fatal("alg:none token accepted")
	}
}

// verifyToken fails closed on a kid that resolves to no signing cert.
func TestVerifyToken_RejectsUnknownKid(t *testing.T) {
	db := openTestDB(t)
	persistCert(t, db, rsaCert(t, "cert-hanzo"))
	other := rsaCert(t, "cert-ghost") // never persisted
	s, _ := NewSignerFromCert(other, testApp(), "https://hanzo.id")
	now := time.Unix(1_800_000_000, 0)
	nowFuncSet(t, now.Add(time.Minute))
	tok, _ := s.Sign(testApp(), "hanzo/alice", "", "", "openid", time.Hour, now)
	if _, err := verifyToken(context.Background(), db, tok); err == nil {
		t.Fatal("token with an unknown kid was accepted")
	}
}

// A tenant cannot shadow a platform signing key: a cert created under a
// non-platform owner with a colliding name (kid) never verifies a forged token,
// even when a real platform cert of the same name also exists.
func TestVerify_TenantCannotShadowSigningKey(t *testing.T) {
	db := openTestDB(t)
	base := time.Unix(1_800_000_000, 0)
	nowFuncSet(t, base.Add(time.Minute))

	// Legit platform signing cert (admin owner, shared key), kid = cert-hanzo.
	persistCert(t, db, rsaCert(t, "cert-hanzo"))

	// Attacker creates a cert with the SAME name under their own org + their key.
	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ac := &schema.Cert{CryptoAlgorithm: "RS256", PrivateKey: rsaKeyToPEM(t, attackerKey)}
	ac.Owner, ac.Name = "attacker-org", "cert-hanzo"
	persistCert(t, db, ac)

	// Attacker forges a token signed with THEIR key, kid=cert-hanzo, claiming admin.
	forger := NewRSASigner(attackerKey, "cert-hanzo", "https://hanzo.id")
	forged, err := forger.Sign(&schema.Application{ClientId: "victim"}, "admin/superadmin", "", "", "openid", time.Hour, base)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyToken(context.Background(), db, forged); err == nil {
		t.Fatal("FORGERY ACCEPTED: a tenant cert shadowed a platform signing key")
	}
}

// A cert under a non-platform owner is never a trusted signing key, even when it
// is the only cert with that name.
func TestVerify_NonPlatformCertNeverTrusted(t *testing.T) {
	db := openTestDB(t)
	base := time.Unix(1_800_000_000, 0)
	nowFuncSet(t, base.Add(time.Minute))

	attackerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ac := &schema.Cert{CryptoAlgorithm: "RS256", PrivateKey: rsaKeyToPEM(t, attackerKey)}
	ac.Owner, ac.Name = "attacker-org", "cert-evil"
	persistCert(t, db, ac)

	forger := NewRSASigner(attackerKey, "cert-evil", "https://hanzo.id")
	forged, _ := forger.Sign(&schema.Application{ClientId: "victim"}, "admin/superadmin", "", "", "openid", time.Hour, base)
	if _, err := verifyToken(context.Background(), db, forged); err == nil {
		t.Fatal("a non-platform cert must never verify a token")
	}
}

// --- cert builders + helpers ---

func rsaCert(t *testing.T, name string) *schema.Cert {
	t.Helper()
	c := &schema.Cert{CryptoAlgorithm: "RS256", PrivateKey: rsaKeyToPEM(t, sharedKey(t))}
	c.Owner, c.Name = "admin", name
	return c
}

func ecCert(t *testing.T, name string) *schema.Cert {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	pemText := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	c := &schema.Cert{CryptoAlgorithm: "ES256", PrivateKey: pemText}
	c.Owner, c.Name = "admin", name
	return c
}

func mldsaCert(t *testing.T, name string) *schema.Cert {
	t.Helper()
	_, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &schema.Cert{CryptoAlgorithm: "MLDSA65", PrivateKey: base64.StdEncoding.EncodeToString(sk.Bytes())}
	c.Owner, c.Name = "admin", name
	return c
}

func persistCert(t *testing.T, db orm.DB, cert *schema.Cert) {
	t.Helper()
	c := orm.New[schema.Cert](db)
	model := c.Model
	*c = *cert
	c.Model = model
	c.SetId(cert.Owner + "/" + cert.Name)
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("persist cert: %v", err)
	}
}

func b64url(t *testing.T, s string) string {
	t.Helper()
	return base64.RawURLEncoding.EncodeToString([]byte(s))
}

// nowFuncSet pins the package clock for the duration of a test.
func nowFuncSet(t *testing.T, at time.Time) {
	t.Helper()
	prev := nowFunc
	nowFunc = func() time.Time { return at }
	t.Cleanup(func() { nowFunc = prev })
}
