// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"testing"
)

// rsaGenTest generates a 2048-bit RSA key (JWKS minimum) for tests.
func rsaGenTest() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// randHex returns 2n lowercase hex chars, for unique fixture values (fake IdP
// tokens and codes). It lives here because only tests need it: usernames are
// derived from the email now, not from randomness.
func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// rsaKeyToPEM encodes an RSA private key as PKCS#1 PEM (what a Cert row holds).
func rsaKeyToPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}
