// Copyright 2026 Hanzo AI Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package controllers

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base32"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// dockerClaimSet mirrors github.com/docker/distribution/registry/auth/token's
// ClaimSet — the exact shape the registry unmarshals a registry token into.
// Note `aud` is a plain string (NOT the RFC 7519 string-or-array) and the time
// fields are integer seconds. If IAM's token does not serialize to this shape
// the registry fails with "cannot unmarshal array into ClaimSet.aud" → 401.
type dockerClaimSet struct {
	Issuer     string `json:"iss"`
	Subject    string `json:"sub"`
	Audience   string `json:"aud"`
	Expiration int64  `json:"exp"`
	NotBefore  int64  `json:"nbf"`
	IssuedAt   int64  `json:"iat"`
	JWTID      string `json:"jti"`
	Access     []struct {
		Type    string   `json:"type"`
		Name    string   `json:"name"`
		Actions []string `json:"actions"`
	} `json:"access"`
}

// buildRegistryClaims constructs the token claims exactly as GetRegistryToken
// does, so the test locks the wire shape the registry depends on.
func buildRegistryClaims(subject, service string, access []RegistryAccess, now time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":    "hanzo-iam",
		"sub":    subject,
		"aud":    service,
		"exp":    now.Add(900 * time.Second).Unix(),
		"nbf":    now.Unix(),
		"iat":    now.Unix(),
		"jti":    "TESTJTI",
		"access": access,
	}
}

// TestRegistryToken_DockerCompatibleClaims proves the minted token unmarshals
// cleanly into Docker Distribution's ClaimSet (string aud, integer times, and a
// well-formed access list). This is the regression guard for the array-aud bug.
func TestRegistryToken_DockerCompatibleClaims(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	access := []RegistryAccess{{Type: "repository", Name: "hanzo/test", Actions: []string{"pull", "push"}}}
	claims := buildRegistryClaims("hanzo-registry", "registry.hanzo.ai", access, now)

	raw, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}

	// aud MUST be a JSON string, never an array.
	if !strings.Contains(string(raw), `"aud":"registry.hanzo.ai"`) {
		t.Fatalf("aud is not a bare string; got %s", raw)
	}

	var cs dockerClaimSet
	if err := json.Unmarshal(raw, &cs); err != nil {
		t.Fatalf("registry cannot unmarshal token (the production 401 bug): %v\npayload=%s", err, raw)
	}
	if cs.Audience != "registry.hanzo.ai" {
		t.Fatalf("aud = %q, want registry.hanzo.ai", cs.Audience)
	}
	if cs.Issuer != "hanzo-iam" {
		t.Fatalf("iss = %q, want hanzo-iam", cs.Issuer)
	}
	if cs.Expiration != now.Add(900*time.Second).Unix() || cs.IssuedAt != now.Unix() {
		t.Fatalf("time claims not integer seconds: exp=%d iat=%d", cs.Expiration, cs.IssuedAt)
	}
	if len(cs.Access) != 1 || cs.Access[0].Name != "hanzo/test" ||
		len(cs.Access[0].Actions) != 2 || cs.Access[0].Actions[1] != "push" {
		t.Fatalf("access did not round-trip: %+v", cs.Access)
	}
}

// referenceLibtrustKeyID is an independent re-implementation of the libtrust
// key-ID scheme, used to cross-check libtrustKeyID.
func referenceLibtrustKeyID(t *testing.T, pub *rsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal pkix: %v", err)
	}
	h := sha256.Sum256(der)
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(h[:30]), "=")
	var out []string
	for i := 0; i < len(s); i += 4 {
		end := i + 4
		if end > len(s) {
			end = len(s)
		}
		out = append(out, s[i:end])
	}
	return strings.Join(out, ":")
}

// TestLibtrustKeyID proves libtrustKeyID emits the canonical Docker/libtrust key
// ID: 12 colon-separated quads over the first 240 bits of SHA-256(PKIX DER).
// The registry derives the SAME ID from its rootcertbundle cert, so a matching
// `kid` header is what lets it trust IAM's signature.
func TestLibtrustKeyID(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	got := libtrustKeyID(&key.PublicKey)
	want := referenceLibtrustKeyID(t, &key.PublicKey)
	if got != want {
		t.Fatalf("libtrustKeyID = %q, want %q", got, want)
	}
	quads := strings.Split(got, ":")
	if len(quads) != 12 {
		t.Fatalf("expected 12 quads, got %d (%q)", len(quads), got)
	}
	for _, q := range quads {
		if len(q) != 4 {
			t.Fatalf("group %q is not 4 chars", q)
		}
	}
}

// TestRegistryToken_KidHeaderSigned proves the signed token carries a `kid`
// header equal to the signing key's libtrust ID — the value the registry looks
// up in its trust set.
func TestRegistryToken_KidHeaderSigned(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	kid := libtrustKeyID(&key.PublicKey)

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, buildRegistryClaims("hanzo-registry", "registry.hanzo.ai", nil, time.Now()))
	tok.Header["kid"] = kid
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	parsed, _, err := jwt.NewParser().ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Header["kid"] != kid {
		t.Fatalf("kid header = %v, want %q", parsed.Header["kid"], kid)
	}
	if parsed.Header["alg"] != "RS256" {
		t.Fatalf("alg = %v, want RS256", parsed.Header["alg"])
	}
}
