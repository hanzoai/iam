// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package seed

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// ensureSigningKey fills a signing cert's PrivateKey when init_data supplies the
// cert METADATA but no key material — the normal case, because a signing key
// cannot live in the init_data.json ConfigMap (it is a secret). It generates a
// keypair matching CryptoAlgorithm and PEM-encodes the private half, so the JWKS
// endpoint publishes a key and iam can sign tokens — the same first-boot key
// provisioning the legacy Beego iam performs. It is gated to a reserved-org cert
// (the only certs the JWKS publishes), leaves a cert that already carries key
// material (PrivateKey or Certificate) or an SSL/unrecognized-alg cert untouched,
// and is safe to call every boot: the key is generated only in memory here, and
// the new-only upsert persists it just once at first creation — a re-seed
// generates a throwaway key that the existing row keeps out (stable kid+key).
func ensureSigningKey(c *schema.Cert) error {
	if c == nil || c.PrivateKey != "" || c.Certificate != "" {
		return nil // already has key material
	}
	owner := c.Owner
	if owner == "" {
		owner = "admin" // the upsert default; keep the gate consistent with it
	}
	if !store.IsSigningCertOwner(owner) {
		return nil // JWKS only publishes reserved-org certs; don't key tenant certs
	}
	if strings.EqualFold(c.Type, "SSL") {
		return nil
	}

	switch strings.ToUpper(strings.ReplaceAll(c.CryptoAlgorithm, "-", "")) {
	case "RS256", "RS512":
		bits := c.BitSize
		if bits == 0 {
			bits = 2048
		}
		key, err := rsa.GenerateKey(rand.Reader, bits)
		if err != nil {
			return err
		}
		c.PrivateKey = string(pem.EncodeToMemory(&pem.Block{
			Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key),
		}))
		c.BitSize = bits
	case "ES256", "ES384", "ES512":
		curve := map[string]elliptic.Curve{
			"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521(),
		}[strings.ToUpper(strings.ReplaceAll(c.CryptoAlgorithm, "-", ""))]
		key, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			return err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return err
		}
		c.PrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}))
	default:
		// MLDSA65 / unrecognized: leave keyless — JWKS skips it exactly as before,
		// so this never regresses a cert we cannot key here.
		return nil
	}
	return nil
}
