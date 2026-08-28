// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// The IdP-facing helpers are the SSRF/transport hygiene and JWKS-decoding seam:
// pure functions that decide which endpoints are reachable and how a fetched
// JWK becomes a verification key. These tests pin each edge.

// isCGNAT covers the shared 100.64.0.0/10 range net.IP.IsPrivate misses.
func TestIsCGNAT(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"100.64.0.1", true},
		{"100.100.50.2", true},
		{"100.127.255.255", true},
		{"100.63.255.255", false},
		{"100.128.0.0", false},
		{"10.0.0.1", false},
		{"192.168.1.1", false},
		{"8.8.8.8", false},
		{"2001:db8::1", false},
	}
	for _, tc := range cases {
		if got := isCGNAT(net.ParseIP(tc.ip)); got != tc.want {
			t.Errorf("isCGNAT(%s) = %v, want %v", tc.ip, got, tc.want)
		}
	}
}

// isLoopbackHost recognizes the loopback name and addresses, nothing else.
func TestIsLoopbackHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"127.0.0.1", true},
		{"127.5.6.7", true},
		{"::1", true},
		{"example.com", false},
		{"8.8.8.8", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isLoopbackHost(tc.host); got != tc.want {
			t.Errorf("isLoopbackHost(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// requireSafeURL is https-only except for loopback, host-required, web-scheme
// only — the SSRF gate on admin-supplied endpoints.
func TestRequireSafeURL(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
	}{
		{"https ok", "https://idp.example.com/authorize", false},
		{"http loopback ok", "http://127.0.0.1:8080/token", false},
		{"http localhost ok", "http://localhost/token", false},
		{"trims whitespace", "  https://idp.example.com/x  ", false},
		{"http non-loopback rejected", "http://idp.example.com", true},
		{"ftp scheme rejected", "ftp://idp.example.com/x", true},
		{"file scheme rejected", "file:///etc/passwd", true},
		{"no host rejected", "https://", true},
		{"empty rejected", "   ", true},
		{"unparseable rejected", "://nope", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := requireSafeURL(tc.in)
			if tc.wantErr != (err != nil) {
				t.Fatalf("requireSafeURL(%q) err = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
		})
	}
}

// ecCurve maps the three JWK curve names and refuses any other.
func TestECCurve(t *testing.T) {
	for _, tc := range []struct {
		crv     string
		want    elliptic.Curve
		wantErr bool
	}{
		{"P-256", elliptic.P256(), false},
		{"P-384", elliptic.P384(), false},
		{"P-521", elliptic.P521(), false},
		{"P-999", nil, true},
		{"", nil, true},
	} {
		got, err := ecCurve(tc.crv)
		if tc.wantErr {
			if err == nil {
				t.Errorf("ecCurve(%q) accepted, want error", tc.crv)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ecCurve(%q) = %v, %v; want %v", tc.crv, got, err, tc.want)
		}
	}
}

// truthy interprets an email_verified value in bool or string form.
func TestTruthy(t *testing.T) {
	cases := []struct {
		v    any
		want bool
	}{
		{true, true},
		{false, false},
		{"true", true},
		{"TRUE", true},
		{"True", true},
		{"false", false},
		{"1", false},
		{1, false},
		{nil, false},
	}
	for _, tc := range cases {
		if got := truthy(tc.v); got != tc.want {
			t.Errorf("truthy(%#v) = %v, want %v", tc.v, got, tc.want)
		}
	}
}

// providerScopes returns configured scopes or the dialect fallback.
func TestProviderScopes(t *testing.T) {
	if got := providerScopes(&schema.Provider{Scopes: "openid email"}, "openid"); got != "openid email" {
		t.Errorf("configured = %q, want 'openid email'", got)
	}
	if got := providerScopes(&schema.Provider{Scopes: ""}, "openid profile"); got != "openid profile" {
		t.Errorf("empty fallback = %q, want 'openid profile'", got)
	}
	if got := providerScopes(&schema.Provider{Scopes: "   "}, "openid"); got != "openid" {
		t.Errorf("blank fallback = %q, want 'openid'", got)
	}
}

// jwk.publicKey materializes RSA and EC keys and refuses malformed or
// unsupported material.
func TestJWKPublicKey(t *testing.T) {
	rsaKey := sharedKey(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	rsaJWKGood := jwk{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(rsaKey.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(rsaKey.E)).Bytes()),
	}
	ecJWKGood := jwk{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(ecKey.X.Bytes()),
		Y:   base64.RawURLEncoding.EncodeToString(ecKey.Y.Bytes()),
	}

	t.Run("rsa materializes", func(t *testing.T) {
		pub, err := rsaJWKGood.publicKey()
		if err != nil {
			t.Fatalf("publicKey: %v", err)
		}
		rp, ok := pub.(*rsa.PublicKey)
		if !ok || rp.N.Cmp(rsaKey.N) != 0 || rp.E != rsaKey.E {
			t.Fatal("RSA public key differs from the source key")
		}
	})
	t.Run("ec materializes", func(t *testing.T) {
		pub, err := ecJWKGood.publicKey()
		if err != nil {
			t.Fatalf("publicKey: %v", err)
		}
		ep, ok := pub.(*ecdsa.PublicKey)
		if !ok || ep.X.Cmp(ecKey.X) != 0 || ep.Y.Cmp(ecKey.Y) != 0 {
			t.Fatal("EC public key coordinates differ")
		}
	})
	t.Run("rsa bad modulus", func(t *testing.T) {
		if _, err := (jwk{Kty: "RSA", N: "@@@", E: rsaJWKGood.E}).publicKey(); err == nil {
			t.Fatal("bad modulus accepted")
		}
	})
	t.Run("rsa bad exponent", func(t *testing.T) {
		if _, err := (jwk{Kty: "RSA", N: rsaJWKGood.N, E: "@@@"}).publicKey(); err == nil {
			t.Fatal("bad exponent accepted")
		}
	})
	t.Run("rsa zero exponent", func(t *testing.T) {
		if _, err := (jwk{Kty: "RSA", N: rsaJWKGood.N, E: ""}).publicKey(); err == nil {
			t.Fatal("zero exponent accepted")
		}
	})
	t.Run("ec bad curve", func(t *testing.T) {
		if _, err := (jwk{Kty: "EC", Crv: "P-999", X: ecJWKGood.X, Y: ecJWKGood.Y}).publicKey(); err == nil {
			t.Fatal("bad curve accepted")
		}
	})
	t.Run("ec bad x", func(t *testing.T) {
		if _, err := (jwk{Kty: "EC", Crv: "P-256", X: "@@@", Y: ecJWKGood.Y}).publicKey(); err == nil {
			t.Fatal("bad x coordinate accepted")
		}
	})
	t.Run("ec bad y", func(t *testing.T) {
		if _, err := (jwk{Kty: "EC", Crv: "P-256", X: ecJWKGood.X, Y: "@@@"}).publicKey(); err == nil {
			t.Fatal("bad y coordinate accepted")
		}
	})
	t.Run("unsupported kty", func(t *testing.T) {
		if _, err := (jwk{Kty: "OKP"}).publicKey(); err == nil {
			t.Fatal("unsupported key type accepted")
		}
	})
}
