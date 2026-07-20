// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package iam

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

// TestParseJwtTokenCarriesOrgs proves the SDK half of the multi-org contract:
// a verified token's `orgs` membership-set claim decodes onto Claims.Orgs, so a
// consumer (cloud clients/team getUserWorkspaces, the gateway org-switch) reads
// every org the subject may act in straight off the credential — home org
// first — with no IAM round-trip.
func TestParseJwtTokenCarriesOrgs(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "iam-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	minted := Claims{
		User: User{Owner: "maxpower", Name: "davelorenzini"},
		Orgs: []OrgRef{
			{Org: "maxpower", Role: "admin"},
			{Org: "acme", Role: "member"},
		},
		TokenType: "access-token",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodRS256, minted).SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Endpoint stays empty so verification uses the Certificate PEM directly
	// (no JWKS fetch) — the self-hosted configuration path.
	c := &Client{AuthConfig: AuthConfig{Certificate: certPEM}}
	claims, err := c.ParseJwtToken(signed)
	if err != nil {
		t.Fatalf("ParseJwtToken: %v", err)
	}

	if claims.Owner != "maxpower" {
		t.Errorf("owner = %q, want maxpower", claims.Owner)
	}
	if len(claims.Orgs) != 2 {
		t.Fatalf("orgs = %+v, want 2 entries", claims.Orgs)
	}
	if claims.Orgs[0] != (OrgRef{Org: "maxpower", Role: "admin"}) {
		t.Errorf("orgs[0] = %+v, want the home org first with its role", claims.Orgs[0])
	}
	if claims.Orgs[1] != (OrgRef{Org: "acme", Role: "member"}) {
		t.Errorf("orgs[1] = %+v, want the invited team org", claims.Orgs[1])
	}

	// A token WITHOUT the claim (minted before it shipped) must parse with an
	// empty set — readers fall back to the single owner org.
	legacy := minted
	legacy.Orgs = nil
	signedLegacy, err := jwt.NewWithClaims(jwt.SigningMethodRS256, legacy).SignedString(key)
	if err != nil {
		t.Fatalf("sign legacy: %v", err)
	}
	parsed, err := c.ParseJwtToken(signedLegacy)
	if err != nil {
		t.Fatalf("ParseJwtToken legacy: %v", err)
	}
	if len(parsed.Orgs) != 0 {
		t.Errorf("legacy orgs = %+v, want empty (fallback to owner)", parsed.Orgs)
	}
}
