// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/luxfi/crypto/pq/mldsa/mldsa65"

	"github.com/hanzoai/iam/internal/schema"
)

// ML-DSA-65 (FIPS 204, NIST security level 3) as a first-class JWT signing
// method. This is the post-quantum half of the hybrid signing story: RS256
// (jwt.go) is the classical interop path every existing verifier already reads
// from the JWKS, and MLDSA65 is the forward path, active only for a Cert whose
// CryptoAlgorithm is ML-DSA. The two share the same Signer / JWKS seam, so a
// deployment migrates one Cert at a time without touching the token core.
//
// The signature scheme is pure ML-DSA-65 over the JWS signing input (no context,
// deterministic), which is exactly what the ML-DSA-65 Verify checks — so a token
// this method signs round-trips through the same package's verify path, and a
// PQ-aware relying party reads the raw public key published in the JWKS.

// algMLDSA65 is the JOSE `alg` value for ML-DSA-65 — the identifier carried in
// the JWT header and advertised in discovery + JWKS.
const algMLDSA65 = "MLDSA65"

// signingMethodMLDSA65 implements jwt.SigningMethod for ML-DSA-65.
type signingMethodMLDSA65 struct{}

// SigningMethodMLDSA65 is the shared, stateless ML-DSA-65 signing method.
var SigningMethodMLDSA65 jwt.SigningMethod = signingMethodMLDSA65{}

func init() {
	jwt.RegisterSigningMethod(algMLDSA65, func() jwt.SigningMethod { return SigningMethodMLDSA65 })
}

// Alg returns the JOSE algorithm identifier.
func (signingMethodMLDSA65) Alg() string { return algMLDSA65 }

// Sign produces a deterministic ML-DSA-65 signature over the JWS signing input.
func (signingMethodMLDSA65) Sign(signingString string, key any) ([]byte, error) {
	sk, ok := key.(*mldsa65.PrivateKey)
	if !ok {
		return nil, jwt.ErrInvalidKeyType
	}
	sig, err := mldsa65.Sign(sk, []byte(signingString), nil, false)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// Verify checks an ML-DSA-65 signature; a mismatch is a signature error, never a
// key/type panic.
func (signingMethodMLDSA65) Verify(signingString string, sig []byte, key any) error {
	pk, ok := key.(*mldsa65.PublicKey)
	if !ok {
		return jwt.ErrInvalidKeyType
	}
	if len(sig) != mldsa65.SignatureSize {
		return jwt.ErrSignatureInvalid
	}
	if !mldsa65.Verify(pk, []byte(signingString), nil, sig) {
		return jwt.ErrSignatureInvalid
	}
	return nil
}

// isMLDSACert reports whether a Cert is an ML-DSA-65 signing cert.
func isMLDSACert(cert *schema.Cert) bool {
	if cert == nil {
		return false
	}
	a := strings.ToUpper(strings.ReplaceAll(cert.CryptoAlgorithm, "-", ""))
	return a == "MLDSA65"
}

// parseMLDSA65PrivateKey decodes an ML-DSA-65 private key from a Cert's stored
// material: a PEM envelope ("MLDSA65 PRIVATE KEY") or bare base64 of the packed
// key bytes.
func parseMLDSA65PrivateKey(material string) (*mldsa65.PrivateKey, error) {
	raw, err := decodeKeyMaterial(material)
	if err != nil {
		return nil, err
	}
	sk := new(mldsa65.PrivateKey)
	if err := sk.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return sk, nil
}

// parseMLDSA65PublicKey decodes an ML-DSA-65 public key from stored material.
func parseMLDSA65PublicKey(material string) (*mldsa65.PublicKey, error) {
	raw, err := decodeKeyMaterial(material)
	if err != nil {
		return nil, err
	}
	pk := new(mldsa65.PublicKey)
	if err := pk.UnmarshalBinary(raw); err != nil {
		return nil, err
	}
	return pk, nil
}

// mldsa65PublicFromCert returns the ML-DSA-65 public key for a cert, from its
// published Certificate material when present, else derived from the private key
// (dev certs that store only the key). It never returns private material.
func mldsa65PublicFromCert(cert *schema.Cert) (*mldsa65.PublicKey, error) {
	if cert.Certificate != "" {
		if pk, err := parseMLDSA65PublicKey(cert.Certificate); err == nil {
			return pk, nil
		}
	}
	sk, err := parseMLDSA65PrivateKey(cert.PrivateKey)
	if err != nil {
		return nil, err
	}
	pub, ok := sk.Public().(*mldsa65.PublicKey)
	if !ok {
		return nil, errors.New("mldsa: derived public key has the wrong type")
	}
	return pub, nil
}

// decodeKeyMaterial extracts raw key bytes from a PEM envelope or bare base64
// (standard or url encoding), the two shapes a Cert row stores raw keys in.
func decodeKeyMaterial(material string) ([]byte, error) {
	material = strings.TrimSpace(material)
	if material == "" {
		return nil, errors.New("mldsa: empty key material")
	}
	if block, _ := pem.Decode([]byte(material)); block != nil {
		return block.Bytes, nil
	}
	if raw, err := base64.StdEncoding.DecodeString(material); err == nil {
		return raw, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(material)
	if err != nil {
		return nil, errors.New("mldsa: key material is neither PEM nor base64")
	}
	return raw, nil
}
