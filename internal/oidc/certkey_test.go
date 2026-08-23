// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/luxfi/crypto/pq/mldsa/mldsa65"

	"github.com/hanzoai/iam/pkg/schema"
)

// certkey resolves the PUBLIC half of a signing Cert and encodes it as a JWK.
// These tests pin the pure encoding helpers (leftPad, ecJWK), the cert→public
// resolution across every key family and material shape, and the halves-agree
// guard that a rotation must not slip past.

// selfSignedPEM issues a self-signed x509 certificate for priv and returns its
// PEM — the PUBLISHED half a Cert row carries in Certificate.
func selfSignedPEM(t *testing.T, priv crypto.Signer) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(1_900_000_000, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// leftPad left-zero-pads to a fixed width and never truncates.
func TestLeftPad(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		size int
		want []byte
	}{
		{"pads short", []byte{0x01, 0x02}, 4, []byte{0x00, 0x00, 0x01, 0x02}},
		{"exact length unchanged", []byte{0x01, 0x02, 0x03, 0x04}, 4, []byte{0x01, 0x02, 0x03, 0x04}},
		{"longer returned as-is", []byte{0x01, 0x02, 0x03, 0x04, 0x05}, 4, []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
		{"empty pads to zeros", []byte{}, 3, []byte{0x00, 0x00, 0x00}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := leftPad(tc.in, tc.size)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d, want %d", len(got), len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("byte %d = %#x, want %#x", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// ecJWK encodes each supported curve with fixed-width coordinates and refuses
// any other curve.
func TestECJWK(t *testing.T) {
	cases := []struct {
		name    string
		curve   elliptic.Curve
		wantCrv string
		wantLen int
	}{
		{"p256", elliptic.P256(), "P-256", 32},
		{"p384", elliptic.P384(), "P-384", 48},
		{"p521", elliptic.P521(), "P-521", 66},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			jwk, err := ecJWK(&key.PublicKey)
			if err != nil {
				t.Fatalf("ecJWK: %v", err)
			}
			if jwk["kty"] != "EC" || jwk["crv"] != tc.wantCrv {
				t.Fatalf("kty/crv = %v/%v, want EC/%s", jwk["kty"], jwk["crv"], tc.wantCrv)
			}
			for _, coord := range []string{"x", "y"} {
				raw, err := base64.RawURLEncoding.DecodeString(jwk[coord].(string))
				if err != nil {
					t.Fatalf("decode %s: %v", coord, err)
				}
				if len(raw) != tc.wantLen {
					t.Fatalf("%s width = %d, want %d", coord, len(raw), tc.wantLen)
				}
			}
		})
	}
	t.Run("unsupported curve", func(t *testing.T) {
		if _, err := ecJWK(&ecdsa.PublicKey{Curve: elliptic.P224()}); err == nil {
			t.Fatal("P-224 accepted, want unsupported-curve error")
		}
	})
}

// classicalAlg is key-type authoritative; the declared value only refines RSA.
func TestClassicalAlg(t *testing.T) {
	rsaPub := &sharedKey(t).PublicKey
	ecPub := func(c elliptic.Curve) *ecdsa.PublicKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return &k.PublicKey
	}
	cases := []struct {
		name     string
		pub      crypto.PublicKey
		declared string
		want     string
		wantErr  bool
	}{
		{"rsa default", rsaPub, "", "RS256", false},
		{"rsa pinned rs512", rsaPub, "RS512", "RS512", false},
		{"rsa declared ignored when not rs512", rsaPub, "ES256", "RS256", false},
		{"ec p256", ecPub(elliptic.P256()), "", "ES256", false},
		{"ec p384", ecPub(elliptic.P384()), "", "ES384", false},
		{"ec p521", ecPub(elliptic.P521()), "", "ES512", false},
		{"ec unsupported curve", &ecdsa.PublicKey{Curve: elliptic.P224()}, "", "", true},
		{"unsupported key type", ed25519.PublicKey{}, "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := classicalAlg(tc.pub, tc.declared)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got alg %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("classicalAlg: %v", err)
			}
			if got != tc.want {
				t.Fatalf("alg = %q, want %q", got, tc.want)
			}
		})
	}
}

// certPublicKey resolves the public half from every material shape a Cert row
// stores, and fails closed on the ones it cannot.
func TestCertPublicKey(t *testing.T) {
	rsaKey := sharedKey(t)
	rsaWithX509 := &schema.Cert{CryptoAlgorithm: "RS256", PrivateKey: rsaKeyToPEM(t, rsaKey), Certificate: selfSignedPEM(t, rsaKey)}
	rsaWithX509.Owner, rsaWithX509.Name = "admin", "cert-x5c"

	t.Run("nil cert", func(t *testing.T) {
		if _, _, _, err := certPublicKey(nil); err == nil {
			t.Fatal("nil cert accepted")
		}
	})
	t.Run("rsa from private key only", func(t *testing.T) {
		pub, alg, x5c, err := certPublicKey(rsaCert(t, "cert-rsa"))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := pub.(*rsa.PublicKey); !ok {
			t.Fatalf("pub type = %T, want *rsa.PublicKey", pub)
		}
		if alg != "RS256" || len(x5c) != 0 {
			t.Fatalf("alg/x5c = %q/%v, want RS256/none", alg, x5c)
		}
	})
	t.Run("rsa rs512 declared", func(t *testing.T) {
		c := rsaCert(t, "cert-rsa512")
		c.CryptoAlgorithm = "RS512"
		_, alg, _, err := certPublicKey(c)
		if err != nil {
			t.Fatal(err)
		}
		if alg != "RS512" {
			t.Fatalf("alg = %q, want RS512", alg)
		}
	})
	t.Run("ec from private key only", func(t *testing.T) {
		pub, alg, _, err := certPublicKey(ecCert(t, "cert-ec"))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := pub.(*ecdsa.PublicKey); !ok {
			t.Fatalf("pub type = %T, want *ecdsa.PublicKey", pub)
		}
		if alg != "ES256" {
			t.Fatalf("alg = %q, want ES256", alg)
		}
	})
	t.Run("mldsa", func(t *testing.T) {
		pub, alg, x5c, err := certPublicKey(mldsaCert(t, "cert-pq"))
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := pub.(*mldsa65.PublicKey); !ok {
			t.Fatalf("pub type = %T, want *mldsa65.PublicKey", pub)
		}
		if alg != algMLDSA65 || len(x5c) != 0 {
			t.Fatalf("alg/x5c = %q/%v, want %s/none", alg, x5c, algMLDSA65)
		}
	})
	t.Run("rsa from published x509 yields x5c", func(t *testing.T) {
		pub, alg, x5c, err := certPublicKey(rsaWithX509)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := pub.(*rsa.PublicKey); !ok {
			t.Fatalf("pub type = %T, want *rsa.PublicKey", pub)
		}
		if alg != "RS256" || len(x5c) != 1 {
			t.Fatalf("alg/x5c = %q/%v, want RS256/one chain entry", alg, x5c)
		}
	})
	t.Run("valid PEM but non-cert DER", func(t *testing.T) {
		bad := &schema.Cert{CryptoAlgorithm: "RS256", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not-der")}))}
		if _, _, _, err := certPublicKey(bad); err == nil {
			t.Fatal("garbage cert DER accepted")
		}
	})
	t.Run("no material at all", func(t *testing.T) {
		empty := &schema.Cert{CryptoAlgorithm: "RS256"}
		if _, _, _, err := certPublicKey(empty); err == nil {
			t.Fatal("cert with no key material accepted")
		}
	})
}

// certToJWK encodes each family's public key with the shared JWK envelope, and
// propagates the resolution error.
func TestCertToJWK(t *testing.T) {
	rsaKey := sharedKey(t)
	rsaWithX509 := &schema.Cert{CryptoAlgorithm: "RS256", PrivateKey: rsaKeyToPEM(t, rsaKey), Certificate: selfSignedPEM(t, rsaKey)}
	rsaWithX509.Owner, rsaWithX509.Name = "admin", "cert-x5c-jwk"

	cases := []struct {
		name    string
		cert    *schema.Cert
		wantKty string
		wantX5c bool
	}{
		{"rsa", rsaCert(t, "cert-rsa-jwk"), "RSA", false},
		{"ec", ecCert(t, "cert-ec-jwk"), "EC", false},
		{"mldsa", mldsaCert(t, "cert-pq-jwk"), "MLDSA", false},
		{"rsa with x5c", rsaWithX509, "RSA", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			jwk, err := certToJWK(tc.cert)
			if err != nil {
				t.Fatalf("certToJWK: %v", err)
			}
			if jwk["kty"] != tc.wantKty {
				t.Fatalf("kty = %v, want %s", jwk["kty"], tc.wantKty)
			}
			if jwk["use"] != "sig" || jwk["kid"] != tc.cert.Name || jwk["alg"] == nil {
				t.Fatalf("envelope = %v, want use=sig kid=%s alg set", jwk, tc.cert.Name)
			}
			if _, has := jwk["x5c"]; has != tc.wantX5c {
				t.Fatalf("x5c present = %v, want %v", has, tc.wantX5c)
			}
		})
	}
	t.Run("nil cert errors", func(t *testing.T) {
		if _, err := certToJWK(nil); err == nil {
			t.Fatal("nil cert accepted")
		}
	})
}

// SigningHalvesAgree reports whether a Cert's PUBLISHED and SIGNING halves are
// the same key, and fails closed on material it cannot compare.
func TestSigningHalvesAgree(t *testing.T) {
	rsaA, err := rsaGenTest()
	if err != nil {
		t.Fatal(err)
	}
	rsaB, err := rsaGenTest()
	if err != nil {
		t.Fatal(err)
	}
	match := &schema.Cert{CryptoAlgorithm: "RS256", Certificate: selfSignedPEM(t, rsaA), PrivateKey: rsaKeyToPEM(t, rsaA)}
	mismatch := &schema.Cert{CryptoAlgorithm: "RS256", Certificate: selfSignedPEM(t, rsaA), PrivateKey: rsaKeyToPEM(t, rsaB)}

	pqPub, pqSk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqPub2, _, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pqMatch := &schema.Cert{CryptoAlgorithm: "MLDSA65",
		Certificate: base64.StdEncoding.EncodeToString(pqPub.Bytes()),
		PrivateKey:  base64.StdEncoding.EncodeToString(pqSk.Bytes())}
	pqMismatch := &schema.Cert{CryptoAlgorithm: "MLDSA65",
		Certificate: base64.StdEncoding.EncodeToString(pqPub2.Bytes()),
		PrivateKey:  base64.StdEncoding.EncodeToString(pqSk.Bytes())}

	cases := []struct {
		name     string
		cert     *schema.Cert
		want     bool
		wantErr  bool
	}{
		{"nil cert", nil, true, false},
		{"empty certificate", &schema.Cert{PrivateKey: rsaKeyToPEM(t, rsaA)}, true, false},
		{"empty private key", &schema.Cert{Certificate: selfSignedPEM(t, rsaA)}, true, false},
		{"rsa halves agree", match, true, false},
		{"rsa halves disagree", mismatch, false, false},
		{"mldsa halves agree", pqMatch, true, false},
		{"mldsa halves disagree", pqMismatch, false, false},
		{"certificate not PEM", &schema.Cert{Certificate: "nope", PrivateKey: rsaKeyToPEM(t, rsaA)}, false, true},
		{"private key not PEM", &schema.Cert{Certificate: selfSignedPEM(t, rsaA), PrivateKey: "nope"}, false, true},
		{"mldsa bad published", &schema.Cert{CryptoAlgorithm: "MLDSA65", Certificate: "!!!", PrivateKey: base64.StdEncoding.EncodeToString(pqSk.Bytes())}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SigningHalvesAgree(tc.cert)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got agree=%v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("SigningHalvesAgree: %v", err)
			}
			if got != tc.want {
				t.Fatalf("agree = %v, want %v", got, tc.want)
			}
		})
	}
}
