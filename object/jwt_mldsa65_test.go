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

package object

import (
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/luxfi/crypto/mldsa"
)

func TestSigningMethodMLDSA65_Alg(t *testing.T) {
	if SigningMethodMLDSA65.Alg() != "MLDSA65" {
		t.Fatalf("expected alg MLDSA65, got %s", SigningMethodMLDSA65.Alg())
	}
}

func TestSigningMethodMLDSA65_Registered(t *testing.T) {
	m := jwt.GetSigningMethod("MLDSA65")
	if m == nil {
		t.Fatal("MLDSA65 signing method not registered with jwt library")
	}
	if m.Alg() != "MLDSA65" {
		t.Fatalf("registered method has wrong alg: %s", m.Alg())
	}
}

func TestSigningMethodMLDSA65_SignVerify(t *testing.T) {
	sk, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	claims := jwt.RegisteredClaims{
		Issuer:  "test-issuer",
		Subject: "test-subject",
	}

	token := jwt.NewWithClaims(SigningMethodMLDSA65, claims)
	token.Header["kid"] = "test-key"

	tokenString, err := token.SignedString(sk)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if tokenString == "" {
		t.Fatal("empty token string")
	}

	// Parse and verify.
	parsed, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*signingMethodMLDSA65); !ok {
			t.Fatalf("unexpected signing method: %v", token.Header["alg"])
		}
		return sk.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("token not valid")
	}

	rc, ok := parsed.Claims.(*jwt.RegisteredClaims)
	if !ok {
		t.Fatal("claims type assertion failed")
	}
	if rc.Issuer != "test-issuer" {
		t.Fatalf("expected issuer test-issuer, got %s", rc.Issuer)
	}
	if rc.Subject != "test-subject" {
		t.Fatalf("expected subject test-subject, got %s", rc.Subject)
	}
}

func TestSigningMethodMLDSA65_WrongKey(t *testing.T) {
	sk1, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	sk2, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)

	token := jwt.NewWithClaims(SigningMethodMLDSA65, jwt.RegisteredClaims{Issuer: "x"})
	tokenString, err := token.SignedString(sk1)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify with wrong key -- must fail.
	_, err = jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (interface{}, error) {
		return sk2.PublicKey, nil
	})
	if err == nil {
		t.Fatal("expected verification failure with wrong key")
	}
}

func TestSigningMethodMLDSA65_InvalidKeyType(t *testing.T) {
	// Sign with wrong key type.
	token := jwt.NewWithClaims(SigningMethodMLDSA65, jwt.RegisteredClaims{})
	_, err := token.SignedString("not-a-key")
	if err == nil {
		t.Fatal("expected error for invalid key type")
	}

	// Verify with wrong key type.
	err = SigningMethodMLDSA65.Verify("data", []byte("sig"), "not-a-key")
	if err == nil {
		t.Fatal("expected error for invalid key type on verify")
	}
}

func TestGenerateMLDSA65Keys(t *testing.T) {
	cert, priv, err := generateMLDSA65Keys()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if cert == "" || priv == "" {
		t.Fatal("empty cert or private key")
	}

	// Parse roundtrip.
	sk, err := parseMLDSA65PrivateKey(priv)
	if err != nil {
		t.Fatalf("parse private: %v", err)
	}
	pk, err := parseMLDSA65PublicKey(cert)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}

	// Sign with parsed private key, verify with parsed public key.
	msg := []byte("roundtrip-test")
	sig, err := sk.Sign(nil, msg, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !pk.VerifySignature(msg, sig) {
		t.Fatal("verification failed after key roundtrip")
	}
}

func TestMLDSA65JWK(t *testing.T) {
	sk, _ := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	jwk := mldsa65JWK("test-kid", sk.PublicKey)

	if jwk.Kty != "MLDSA" {
		t.Fatalf("expected kty MLDSA, got %s", jwk.Kty)
	}
	if jwk.Alg != "MLDSA65" {
		t.Fatalf("expected alg MLDSA65, got %s", jwk.Alg)
	}
	if jwk.Kid != "test-kid" {
		t.Fatalf("expected kid test-kid, got %s", jwk.Kid)
	}
	if jwk.Use != "sig" {
		t.Fatalf("expected use sig, got %s", jwk.Use)
	}
	if jwk.X == "" {
		t.Fatal("empty x field")
	}

	// Must serialize to valid JSON.
	b, err := json.Marshal(jwk)
	if err != nil {
		t.Fatalf("json marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json unmarshal: %v", err)
	}
	if m["kty"] != "MLDSA" {
		t.Fatal("kty not in JSON output")
	}
}

func TestParseCertPrivateKey_MLDSA65(t *testing.T) {
	certPEM, privPEM, err := generateMLDSA65Keys()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	cert := &Cert{
		Name:       "test-mldsa65",
		PrivateKey: privPEM,
	}

	key, err := parseCertPrivateKey(cert, algMLDSA65)
	if err != nil {
		t.Fatalf("parseCertPrivateKey: %v", err)
	}

	sk, ok := key.(*mldsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *mldsa.PrivateKey, got %T", key)
	}

	// Verify the key works by signing and verifying.
	pk, err := parseMLDSA65PublicKey(certPEM)
	if err != nil {
		t.Fatalf("parse public: %v", err)
	}

	msg := []byte("cache-test")
	sig, err := sk.Sign(nil, msg, nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if !pk.VerifySignature(msg, sig) {
		t.Fatal("verification failed")
	}
}

func TestExtractPEMPayload(t *testing.T) {
	input := "-----BEGIN MLDSA65 PUBLIC KEY-----\nABCDEF==\n-----END MLDSA65 PUBLIC KEY-----\n"
	got := extractPEMPayload(input)
	if got != "ABCDEF==" {
		t.Fatalf("expected 'ABCDEF==', got '%s'", got)
	}
}

func TestCertPopulateContent_MLDSA65(t *testing.T) {
	cert := &Cert{
		Owner:           "admin",
		Name:            "test-pq-cert",
		CryptoAlgorithm: algMLDSA65,
	}

	err := cert.populateContent()
	if err != nil {
		t.Fatalf("populateContent: %v", err)
	}

	if cert.Certificate == "" {
		t.Fatal("certificate empty after populate")
	}
	if cert.PrivateKey == "" {
		t.Fatal("private key empty after populate")
	}
	if cert.Type != "pq" {
		t.Fatalf("expected type pq, got %s", cert.Type)
	}

	// Verify the generated keys parse correctly.
	_, err = parseMLDSA65PublicKey(cert.Certificate)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	_, err = parseMLDSA65PrivateKey(cert.PrivateKey)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
}
