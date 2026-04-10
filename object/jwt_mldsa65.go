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

// jwt_mldsa65.go implements a custom jwt.SigningMethod for ML-DSA-65 (FIPS 204).
//
// ML-DSA-65 provides NIST Level 3 (192-bit) post-quantum security using
// module-lattice-based digital signatures. The implementation delegates to
// github.com/luxfi/crypto/mldsa which wraps Cloudflare's circl library.
//
// Algorithm identifier: "MLDSA65"
//
// Key types:
//   - Sign:   *mldsa.PrivateKey
//   - Verify: *mldsa.PublicKey
//
// Enabled per-application via Application.TokenSigningMethod = "MLDSA65",
// or globally via conf key "jwtPqEnabled" / env var "jwtPqEnabled".

import (
	"encoding/base64"
	"errors"

	"github.com/golang-jwt/jwt/v5"
	"github.com/luxfi/crypto/mldsa"
)

const algMLDSA65 = "MLDSA65"

var (
	// SigningMethodMLDSA65 is the JWT signing method for ML-DSA-65.
	SigningMethodMLDSA65 *signingMethodMLDSA65

	errMLDSA65KeyType      = errors.New("mldsa65: invalid key type")
	errMLDSA65Verification = errors.New("mldsa65: signature verification failed")
)

func init() {
	SigningMethodMLDSA65 = &signingMethodMLDSA65{}
	jwt.RegisterSigningMethod(algMLDSA65, func() jwt.SigningMethod {
		return SigningMethodMLDSA65
	})
}

type signingMethodMLDSA65 struct{}

func (m *signingMethodMLDSA65) Alg() string { return algMLDSA65 }

// Verify checks an ML-DSA-65 signature. key must be *mldsa.PublicKey.
func (m *signingMethodMLDSA65) Verify(signingString string, sig []byte, key interface{}) error {
	pk, ok := key.(*mldsa.PublicKey)
	if !ok {
		return errMLDSA65KeyType
	}

	if !pk.VerifySignature([]byte(signingString), sig) {
		return errMLDSA65Verification
	}
	return nil
}

// Sign produces an ML-DSA-65 signature. key must be *mldsa.PrivateKey.
func (m *signingMethodMLDSA65) Sign(signingString string, key interface{}) ([]byte, error) {
	sk, ok := key.(*mldsa.PrivateKey)
	if !ok {
		return nil, errMLDSA65KeyType
	}

	sig, err := sk.Sign(nil, []byte(signingString), nil)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// generateMLDSA65Keys generates an ML-DSA-65 key pair and returns the
// public and private keys as base64-encoded PEM-like blocks.
//
// Unlike RSA/EC keys, ML-DSA keys are not wrapped in x509 certificates.
// The "certificate" field stores a PEM block with type "MLDSA65 PUBLIC KEY"
// containing the raw base64-encoded public key bytes.
// The "private key" field stores a PEM block with type "MLDSA65 PRIVATE KEY"
// containing the raw base64-encoded private key bytes.
func generateMLDSA65Keys() (certificate string, privateKey string, err error) {
	sk, err := mldsa.GenerateKey(nil, mldsa.MLDSA65)
	if err != nil {
		return "", "", err
	}

	pubB64 := base64.StdEncoding.EncodeToString(sk.PublicKey.Bytes())
	privB64 := base64.StdEncoding.EncodeToString(sk.Bytes())

	// Use PEM-like envelope so cert_cache.go and JWKS can distinguish key types.
	certificate = "-----BEGIN MLDSA65 PUBLIC KEY-----\n" + pubB64 + "\n-----END MLDSA65 PUBLIC KEY-----\n"
	privateKey = "-----BEGIN MLDSA65 PRIVATE KEY-----\n" + privB64 + "\n-----END MLDSA65 PRIVATE KEY-----\n"

	return certificate, privateKey, nil
}

// parseMLDSA65PrivateKey parses a PEM-encoded ML-DSA-65 private key.
func parseMLDSA65PrivateKey(pemData string) (*mldsa.PrivateKey, error) {
	b64 := extractPEMPayload(pemData)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return mldsa.PrivateKeyFromBytes(mldsa.MLDSA65, raw)
}

// parseMLDSA65PublicKey parses a PEM-encoded ML-DSA-65 public key.
func parseMLDSA65PublicKey(pemData string) (*mldsa.PublicKey, error) {
	b64 := extractPEMPayload(pemData)
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return mldsa.PublicKeyFromBytes(raw, mldsa.MLDSA65)
}

// extractPEMPayload strips PEM header/footer lines and returns the base64 body.
func extractPEMPayload(pemData string) string {
	var lines []string
	for _, line := range splitLines(pemData) {
		if line == "" || line[0] == '-' {
			continue
		}
		lines = append(lines, line)
	}
	result := ""
	for _, l := range lines {
		result += l
	}
	return result
}

// splitLines splits a string into lines, handling both \n and \r\n.
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}
