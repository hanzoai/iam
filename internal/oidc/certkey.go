// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"

	"github.com/luxfi/crypto/pq/mldsa/mldsa65"

	"github.com/hanzoai/iam2/internal/schema"
)

// certkey resolves the PUBLIC half of a signing Cert and encodes it as a JWK.
// It is the one place cert → public-key happens, shared by the JWKS endpoint
// (which publishes the key so relying parties can verify) and token
// verification (which checks a bearer against it). The public key is read from
// the Cert's published x509 certificate when present, else derived from the key
// pair; private material never crosses this boundary.

// certPublicKey returns a Cert's public key, its JOSE alg, and (for x509 certs)
// the base64 DER chain for the JWK `x5c`. An ML-DSA cert yields a raw ML-DSA
// public key and no chain.
func certPublicKey(cert *schema.Cert) (pub crypto.PublicKey, alg string, x5c []string, err error) {
	if cert == nil {
		return nil, "", nil, errors.New("jwks: nil cert")
	}
	if isMLDSACert(cert) {
		pk, err := mldsa65PublicFromCert(cert)
		if err != nil {
			return nil, "", nil, err
		}
		return pk, algMLDSA65, nil, nil
	}
	if cert.Certificate != "" {
		block, _ := pem.Decode([]byte(cert.Certificate))
		if block != nil {
			x509Cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, "", nil, err
			}
			a, err := classicalAlg(x509Cert.PublicKey, cert.CryptoAlgorithm)
			if err != nil {
				return nil, "", nil, err
			}
			return x509Cert.PublicKey, a, []string{base64.StdEncoding.EncodeToString(x509Cert.Raw)}, nil
		}
	}
	// Dev/test cert that stores only the private key: derive the public half.
	signer, err := parsePrivateKeyPEM(cert.PrivateKey)
	if err != nil {
		return nil, "", nil, err
	}
	a, err := classicalAlg(signer.Public(), cert.CryptoAlgorithm)
	if err != nil {
		return nil, "", nil, err
	}
	return signer.Public(), a, nil, nil
}

// certToJWK encodes a Cert's public key as a JWK map: {kty, alg, use:"sig", kid,
// key params, x5c?}. kid is the Cert name (what token headers carry), matching
// the live hanzo.id JWKS.
func certToJWK(cert *schema.Cert) (map[string]any, error) {
	pub, alg, x5c, err := certPublicKey(cert)
	if err != nil {
		return nil, err
	}
	var jwk map[string]any
	switch k := pub.(type) {
	case *rsa.PublicKey:
		jwk = rsaJWK(k)
	case *ecdsa.PublicKey:
		jwk, err = ecJWK(k)
		if err != nil {
			return nil, err
		}
	case *mldsa65.PublicKey:
		jwk = map[string]any{"kty": "MLDSA", "x": base64.RawURLEncoding.EncodeToString(k.Bytes())}
	default:
		return nil, errors.New("jwks: unsupported public key type")
	}
	jwk["use"] = "sig"
	jwk["kid"] = cert.Name
	jwk["alg"] = alg
	if len(x5c) > 0 {
		jwk["x5c"] = x5c
	}
	return jwk, nil
}

// rsaJWK encodes an RSA public key's modulus and exponent (RFC 7518 §6.3).
func rsaJWK(k *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA",
		"n":   base64.RawURLEncoding.EncodeToString(k.N.Bytes()),
		"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(k.E)).Bytes()),
	}
}

// ecJWK encodes an EC public key's curve and fixed-width coordinates (RFC 7518
// §6.2) and returns the curve's JOSE alg.
func ecJWK(k *ecdsa.PublicKey) (map[string]any, error) {
	var crv string
	var size int
	switch k.Curve.Params().BitSize {
	case 256:
		crv, size = "P-256", 32
	case 384:
		crv, size = "P-384", 48
	case 521:
		crv, size = "P-521", 66
	default:
		return nil, errors.New("jwks: unsupported EC curve")
	}
	return map[string]any{
		"kty": "EC",
		"crv": crv,
		"x":   base64.RawURLEncoding.EncodeToString(leftPad(k.X.Bytes(), size)),
		"y":   base64.RawURLEncoding.EncodeToString(leftPad(k.Y.Bytes(), size)),
	}, nil
}

// classicalAlg maps a classical public key (and the Cert's declared algorithm,
// when it agrees with the key family) to a JOSE alg. The key type is
// authoritative; the declared value only refines RSA (RS256 default, RS512 when
// pinned).
func classicalAlg(pub crypto.PublicKey, declared string) (string, error) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if strings.EqualFold(declared, "RS512") {
			return "RS512", nil
		}
		return "RS256", nil
	case *ecdsa.PublicKey:
		switch k.Curve.Params().BitSize {
		case 256:
			return "ES256", nil
		case 384:
			return "ES384", nil
		case 521:
			return "ES512", nil
		}
		return "", errors.New("jwks: unsupported EC curve")
	default:
		return "", errors.New("jwks: unsupported public key type")
	}
}

// leftPad left-zero-pads b to size bytes (EC coordinates are fixed-width).
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}
