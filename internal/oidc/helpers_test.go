// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
)

// rsaGenTest generates a 2048-bit RSA key (JWKS minimum) for tests.
func rsaGenTest() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// rsaKeyToPEM encodes an RSA private key as PKCS#1 PEM (what a Cert row holds).
func rsaKeyToPEM(t *testing.T, k *rsa.PrivateKey) string {
	t.Helper()
	der := x509.MarshalPKCS1PrivateKey(k)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}))
}
