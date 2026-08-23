// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

// A grab-bag of pure decision helpers behind signup and signing: the password
// floor + org options, the display-name precedence, and the private-key PEM
// parsers that pick a signing method by key family.

// passwordPolicyError enforces the platform floor first, then the org's additive
// options.
func TestPasswordPolicyError(t *testing.T) {
	cases := []struct {
		name     string
		options  []string
		password string
		wantMsg  string // "" means accepted
	}{
		{"empty", nil, "", "password cannot be empty"},
		{"below floor", nil, "abcdefg", "the password must have at least 8 characters"},
		{"single repeated rune", nil, "aaaaaaaa", "the password must not be a single repeated character"},
		{"floor met no options", nil, "abcdefgh", ""},
		{"Aa123 missing classes", []string{"Aa123"}, "abcdefgh", "the password must contain at least one uppercase letter, one lowercase letter and one digit"},
		{"Aa123 satisfied", []string{"Aa123"}, "Abcdefg1", ""},
		{"SpecialChar missing", []string{"SpecialChar"}, "Abcdefg1", "the password must contain at least one special character"},
		{"SpecialChar satisfied", []string{"SpecialChar"}, "Abcdef1!", ""},
		{"NoRepeat adjacent", []string{"NoRepeat"}, "aabcdefg", "the password must not contain any repeated characters"},
		{"NoRepeat satisfied", []string{"NoRepeat"}, "abcdefgh", ""},
		{"AtLeast6 arm runs above floor", []string{"AtLeast6"}, "abcdefgh", ""},
		{"AtLeast8 arm runs above floor", []string{"AtLeast8"}, "abcdefgh", ""},
		{"all options satisfied", []string{"Aa123", "SpecialChar", "NoRepeat"}, "Abcdef1!", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := passwordPolicyError(tc.options, tc.password); got != tc.wantMsg {
				t.Fatalf("passwordPolicyError = %q, want %q", got, tc.wantMsg)
			}
		})
	}
}

// isSingleRepeatedRune is the length-floor's trivial-evasion guard.
func TestIsSingleRepeatedRune(t *testing.T) {
	cases := []struct {
		s    string
		want bool
	}{
		{"a", true},
		{"aaaaaaaa", true},
		{"……", true},
		{"ab", false},
		{"aaab", false},
	}
	for _, tc := range cases {
		if got := isSingleRepeatedRune(tc.s); got != tc.want {
			t.Errorf("isSingleRepeatedRune(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

// displayName follows v1's precedence: composite name, then explicit name, then
// the username as a last resort.
func TestDisplayName(t *testing.T) {
	cases := []struct {
		name string
		form signupForm
		want string
	}{
		{"first and last", signupForm{FirstName: "Jane", LastName: "Doe", Name: "ignored", Username: "jd"}, "Jane Doe"},
		{"first only", signupForm{FirstName: "Jane", Username: "jd"}, "Jane"},
		{"last only", signupForm{LastName: "Doe", Username: "jd"}, "Doe"},
		{"blank names fall to display name", signupForm{FirstName: " ", LastName: " ", Name: "Display", Username: "jd"}, "Display"},
		{"display name only", signupForm{Name: "Display", Username: "jd"}, "Display"},
		{"username last resort", signupForm{Username: "jd"}, "jd"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := displayName(tc.form); got != tc.want {
				t.Fatalf("displayName = %q, want %q", got, tc.want)
			}
		})
	}
}

// methodForKey maps a parsed key (and an in-family pinned method) to a signing
// method, and refuses key families it does not sign with.
func TestMethodForKey(t *testing.T) {
	ecOf := func(c elliptic.Curve) *ecdsa.PrivateKey {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}
	cases := []struct {
		name    string
		key     any
		pinned  string
		wantAlg string
		wantErr bool
	}{
		{"rsa default", sharedKey(t), "", "RS256", false},
		{"rsa pinned rs512", sharedKey(t), "RS512", "RS512", false},
		{"ec p256", ecOf(elliptic.P256()), "", "ES256", false},
		{"ec p384", ecOf(elliptic.P384()), "", "ES384", false},
		{"ec p521", ecOf(elliptic.P521()), "", "ES512", false},
		{"ec unsupported bit size", ecOf(elliptic.P224()), "", "", true},
		{"unsupported key type", ed25519.PrivateKey{}, "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, alg, err := methodForKey(tc.key, tc.pinned)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("want error, got alg %q", alg)
				}
				return
			}
			if err != nil {
				t.Fatalf("methodForKey: %v", err)
			}
			if alg != tc.wantAlg || m == nil || m.Alg() != tc.wantAlg {
				t.Fatalf("alg = %q (method %v), want %q", alg, m, tc.wantAlg)
			}
		})
	}
}

// parsePrivateKeyPEM decodes every classical PEM shape a Cert row may hold and
// fails closed on non-PEM.
func TestParsePrivateKeyPEM(t *testing.T) {
	rsaKey := sharedKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	ecPEM := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8PEM := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}))

	t.Run("pkcs1 rsa", func(t *testing.T) {
		if _, err := parsePrivateKeyPEM(rsaKeyToPEM(t, rsaKey)); err != nil {
			t.Fatalf("pkcs1: %v", err)
		}
	})
	t.Run("sec1 ec", func(t *testing.T) {
		if _, err := parsePrivateKeyPEM(ecPEM); err != nil {
			t.Fatalf("ec: %v", err)
		}
	})
	t.Run("pkcs8", func(t *testing.T) {
		if _, err := parsePrivateKeyPEM(pkcs8PEM); err != nil {
			t.Fatalf("pkcs8: %v", err)
		}
	})
	t.Run("not pem", func(t *testing.T) {
		if _, err := parsePrivateKeyPEM("not a pem"); err == nil {
			t.Fatal("non-PEM accepted")
		}
	})
	t.Run("pem but garbage der", func(t *testing.T) {
		bad := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}))
		if _, err := parsePrivateKeyPEM(bad); err == nil {
			t.Fatal("garbage DER accepted")
		}
	})
}

// parseRSAPrivateKeyPEM accepts PKCS#1 and PKCS#8-RSA and refuses a non-RSA key.
func TestParseRSAPrivateKeyPEM(t *testing.T) {
	rsaKey := sharedKey(t)
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8RSA := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER}))

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER, err := x509.MarshalPKCS8PrivateKey(ecKey)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8EC := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: ecDER}))

	t.Run("pkcs1 rsa", func(t *testing.T) {
		if _, err := parseRSAPrivateKeyPEM(rsaKeyToPEM(t, rsaKey)); err != nil {
			t.Fatalf("pkcs1: %v", err)
		}
	})
	t.Run("pkcs8 rsa", func(t *testing.T) {
		if _, err := parseRSAPrivateKeyPEM(pkcs8RSA); err != nil {
			t.Fatalf("pkcs8 rsa: %v", err)
		}
	})
	t.Run("pkcs8 ec rejected", func(t *testing.T) {
		_, err := parseRSAPrivateKeyPEM(pkcs8EC)
		if err == nil || !strings.Contains(err.Error(), "not RSA") {
			t.Fatalf("err = %v, want a not-RSA error", err)
		}
	})
	t.Run("not pem", func(t *testing.T) {
		if _, err := parseRSAPrivateKeyPEM("nope"); err == nil {
			t.Fatal("non-PEM accepted")
		}
	})
}
