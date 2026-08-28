// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"

	"github.com/hanzoai/iam/pkg/schema"
)

// ML-DSA-65 (FIPS 204) is the post-quantum half of the signing story. These
// tests pin its material decoding (PEM / std-base64 / url-base64), key parsing,
// cert→public resolution, and the signing-method contract (type + length +
// signature checks).

// decodeKeyMaterial accepts the three shapes a Cert row stores raw keys in and
// rejects everything else.
func TestDecodeKeyMaterial(t *testing.T) {
	raw := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	cases := []struct {
		name     string
		material string
		want     []byte
		wantErr  bool
	}{
		{"pem envelope", string(pem.EncodeToMemory(&pem.Block{Type: "MLDSA65 PRIVATE KEY", Bytes: raw})), raw, false},
		{"std base64", base64.StdEncoding.EncodeToString(raw), raw, false},
		{"raw url base64", base64.RawURLEncoding.EncodeToString([]byte{0xFB, 0xEF, 0xFF}), []byte{0xFB, 0xEF, 0xFF}, false},
		{"leading/trailing space trimmed", "  " + base64.StdEncoding.EncodeToString(raw) + "  ", raw, false},
		{"empty", "", nil, true},
		{"whitespace only", "   ", nil, true},
		{"not pem nor base64", "@@@not-valid@@@", nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := decodeKeyMaterial(tc.material)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got %x", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("decodeKeyMaterial: %v", err)
			}
			if string(got) != string(tc.want) {
				t.Fatalf("got %x, want %x", got, tc.want)
			}
		})
	}
}

// parseMLDSA65PrivateKey / parseMLDSA65PublicKey round-trip a real key and
// refuse material of the wrong length or shape.
func TestParseMLDSA65Keys(t *testing.T) {
	pub, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	t.Run("private round-trip", func(t *testing.T) {
		got, err := parseMLDSA65PrivateKey(base64.StdEncoding.EncodeToString(sk.Bytes()))
		if err != nil {
			t.Fatalf("parse private: %v", err)
		}
		gotPub, ok := got.Public().(*mldsa65.PublicKey)
		if !ok || string(gotPub.Bytes()) != string(pub.Bytes()) {
			t.Fatal("parsed private key does not carry the original public half")
		}
	})
	t.Run("public round-trip", func(t *testing.T) {
		got, err := parseMLDSA65PublicKey(base64.StdEncoding.EncodeToString(pub.Bytes()))
		if err != nil {
			t.Fatalf("parse public: %v", err)
		}
		if string(got.Bytes()) != string(pub.Bytes()) {
			t.Fatal("parsed public key bytes differ")
		}
	})
	t.Run("private rejects wrong length", func(t *testing.T) {
		if _, err := parseMLDSA65PrivateKey(base64.StdEncoding.EncodeToString([]byte{1, 2, 3})); err == nil {
			t.Fatal("short private material accepted")
		}
	})
	t.Run("public rejects wrong length", func(t *testing.T) {
		if _, err := parseMLDSA65PublicKey(base64.StdEncoding.EncodeToString([]byte{1, 2, 3})); err == nil {
			t.Fatal("short public material accepted")
		}
	})
	t.Run("private rejects garbage material", func(t *testing.T) {
		if _, err := parseMLDSA65PrivateKey("@@@"); err == nil {
			t.Fatal("garbage private material accepted")
		}
	})
	t.Run("public rejects garbage material", func(t *testing.T) {
		if _, err := parseMLDSA65PublicKey("@@@"); err == nil {
			t.Fatal("garbage public material accepted")
		}
	})
}

// mldsa65PublicFromCert reads the published half when present and derives it
// from the private key otherwise; it never returns private material.
func TestMLDSA65PublicFromCert(t *testing.T) {
	pub, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("from published certificate", func(t *testing.T) {
		c := &schema.Cert{CryptoAlgorithm: "MLDSA65",
			Certificate: base64.StdEncoding.EncodeToString(pub.Bytes()),
			PrivateKey:  "ignored-because-published-present"}
		got, err := mldsa65PublicFromCert(c)
		if err != nil {
			t.Fatalf("from cert: %v", err)
		}
		if string(got.Bytes()) != string(pub.Bytes()) {
			t.Fatal("published public half not returned")
		}
	})
	t.Run("derived from private key", func(t *testing.T) {
		c := &schema.Cert{CryptoAlgorithm: "MLDSA65", PrivateKey: base64.StdEncoding.EncodeToString(sk.Bytes())}
		got, err := mldsa65PublicFromCert(c)
		if err != nil {
			t.Fatalf("derive: %v", err)
		}
		if string(got.Bytes()) != string(pub.Bytes()) {
			t.Fatal("derived public half differs from the key's own public half")
		}
	})
	t.Run("bad published falls through to private", func(t *testing.T) {
		c := &schema.Cert{CryptoAlgorithm: "MLDSA65",
			Certificate: "not-decodable",
			PrivateKey:  base64.StdEncoding.EncodeToString(sk.Bytes())}
		got, err := mldsa65PublicFromCert(c)
		if err != nil {
			t.Fatalf("fallback: %v", err)
		}
		if string(got.Bytes()) != string(pub.Bytes()) {
			t.Fatal("fallback did not derive the correct public half")
		}
	})
	t.Run("no usable material errors", func(t *testing.T) {
		c := &schema.Cert{CryptoAlgorithm: "MLDSA65", PrivateKey: "@@@"}
		if _, err := mldsa65PublicFromCert(c); err == nil {
			t.Fatal("cert with no usable material accepted")
		}
	})
}

// isMLDSACert normalizes the declared algorithm before matching.
func TestIsMLDSACert(t *testing.T) {
	cases := []struct {
		alg  string
		want bool
	}{
		{"MLDSA65", true},
		{"ML-DSA-65", true},
		{"mldsa65", true},
		{"RS256", false},
		{"ES256", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isMLDSACert(&schema.Cert{CryptoAlgorithm: tc.alg}); got != tc.want {
			t.Fatalf("isMLDSACert(%q) = %v, want %v", tc.alg, got, tc.want)
		}
	}
	if isMLDSACert(nil) {
		t.Fatal("nil cert reported as ML-DSA")
	}
}

// The ML-DSA signing method signs and verifies a real signature and rejects
// every off-contract input (wrong key type, wrong signature length, tampered
// signature) as an error, never a panic.
func TestSigningMethodMLDSA65(t *testing.T) {
	pub, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const input = "eyJhbGciOiJNTERTQTY1In0.eyJzdWIiOiJhbGljZSJ9"

	sig, err := SigningMethodMLDSA65.Sign(input, sk)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := SigningMethodMLDSA65.Verify(input, sig, pub); err != nil {
		t.Fatalf("verify valid: %v", err)
	}
	if SigningMethodMLDSA65.Alg() != algMLDSA65 {
		t.Fatalf("alg = %q, want %s", SigningMethodMLDSA65.Alg(), algMLDSA65)
	}

	t.Run("sign wrong key type", func(t *testing.T) {
		if _, err := SigningMethodMLDSA65.Sign(input, "not-a-key"); err != jwt.ErrInvalidKeyType {
			t.Fatalf("err = %v, want ErrInvalidKeyType", err)
		}
	})
	t.Run("verify wrong key type", func(t *testing.T) {
		if err := SigningMethodMLDSA65.Verify(input, sig, "not-a-key"); err != jwt.ErrInvalidKeyType {
			t.Fatalf("err = %v, want ErrInvalidKeyType", err)
		}
	})
	t.Run("verify wrong signature length", func(t *testing.T) {
		if err := SigningMethodMLDSA65.Verify(input, []byte{0x00, 0x01}, pub); err != jwt.ErrSignatureInvalid {
			t.Fatalf("err = %v, want ErrSignatureInvalid", err)
		}
	})
	t.Run("verify tampered signature", func(t *testing.T) {
		bad := make([]byte, len(sig))
		copy(bad, sig)
		bad[0] ^= 0xFF
		if err := SigningMethodMLDSA65.Verify(input, bad, pub); err != jwt.ErrSignatureInvalid {
			t.Fatalf("err = %v, want ErrSignatureInvalid", err)
		}
	})
	t.Run("verify wrong input", func(t *testing.T) {
		if err := SigningMethodMLDSA65.Verify(input+"x", sig, pub); err != jwt.ErrSignatureInvalid {
			t.Fatalf("err = %v, want ErrSignatureInvalid", err)
		}
	})
}
