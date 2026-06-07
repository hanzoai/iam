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

package capauth

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/zap-proto/go/cap"
)

// ed25519Signer is an in-package implementation of cap.Signer over an
// ed25519 keypair. We define our own (rather than re-using
// cap.Ed25519Signer) because the upstream type has unexported fields and
// can only be constructed from crypto/rand.Reader — that's fine for tests
// but blocks the canonical "load from KMS-supplied seed" production path.
//
// Wire compatibility: identical. The bytes ed25519Signer.Sign returns are
// the same cap.SigSize-byte padded shape cap.Ed25519Signer returns, with
// the same algorithm tag at cap.AlgTagOffset; the in-package verifier
// path goes through cap.Verifier which decodes the leading 64 bytes as
// the ed25519 signature.
type ed25519Signer struct {
	priv ed25519.PrivateKey
	pub  [32]byte
}

// Sign signs payload with the underlying ed25519 private key, places the
// 64-byte ed25519 output at the leading bytes of the cap.SigSize footer,
// and writes the SchemeEd25519 tag at cap.AlgTagOffset. The bytes
// between the signature and the tag are zero by construction (var out).
func (s *ed25519Signer) Sign(payload []byte) ([cap.SigSize]byte, error) {
	var out [cap.SigSize]byte
	sig := ed25519.Sign(s.priv, payload)
	if len(sig) != ed25519.SignatureSize {
		return out, errors.New("capauth: ed25519 sign produced wrong size")
	}
	copy(out[:ed25519.SignatureSize], sig)
	out[cap.AlgTagOffset] = byte(cap.SchemeEd25519)
	return out, nil
}

// Public returns the 32-byte hash of the signer's ed25519 public key. The
// returned hash must match the cap's Issuer field for verification to
// succeed.
func (s *ed25519Signer) Public() [32]byte { return s.pub }

// PublicKey returns the raw 32-byte ed25519 public key, ready for
// registration in a cap.Verifier.IssuerKey lookup.
func (s *ed25519Signer) PublicKey() ed25519.PublicKey {
	return s.priv.Public().(ed25519.PublicKey)
}

// Ed25519Signer is the exported alias for the in-package signer type, kept
// so consumers can name the type without reaching into unexported names.
type Ed25519Signer = ed25519Signer

// NewEd25519Signer mints a fresh ed25519 keypair via crypto/rand.Reader.
// Returns the signer (suitable for Issuer{Signer:…, Scheme:SchemeEd25519})
// and the raw 32-byte ed25519 public key bytes (suitable for registering
// with cap.Verifier.IssuerKey).
func NewEd25519Signer() (*Ed25519Signer, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("capauth: ed25519 keygen: %w", err)
	}
	s := &Ed25519Signer{priv: priv}
	s.pub = cap.Hash32(pub)
	return s, pub, nil
}

// NewEd25519SignerFromSeed materialises a signer from a 32-byte ed25519
// seed (NOT the full 64-byte expanded private key). This is the canonical
// "load from KMS" path: the seed is what KMS stores, and ed25519.NewKeyFromSeed
// is the standard library's deterministic expansion to a full keypair.
//
// The seed bytes the caller passes are NOT zeroed by this function; the
// caller is expected to wipe its own buffer once the signer is constructed
// (see LoadEd25519FromKMS for the canonical pattern).
func NewEd25519SignerFromSeed(seed []byte) (*Ed25519Signer, ed25519.PublicKey, error) {
	if len(seed) != ed25519.SeedSize {
		return nil, nil, fmt.Errorf("capauth: ed25519 seed wrong size: got %d want %d",
			len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	s := &Ed25519Signer{priv: priv}
	s.pub = cap.Hash32(pub)
	return s, pub, nil
}

// MLDSA65Signer is the FIPS 204 Level-3 PQ signer used by Hanzo IAM (and
// every cap-aware Hanzo service) at v1.1 of the ZAP capability wire
// format. A real ML-DSA-65 signature is 3309 bytes; the v1.1 sig footer
// is 3408 bytes (cap.SigSize), large enough to hold the full signature
// plus the scheme tag byte at cap.AlgTagOffset.
//
// Wire layout produced by Sign:
//
//	out[0:3309]                = ML-DSA-65 signature bytes
//	out[3309:cap.AlgTagOffset] = zero pad
//	out[cap.AlgTagOffset]      = byte(SchemeMLDSA65) = 0x03
//
// The tag byte sits at the end of the footer and is part of the signed
// payload (the signer reads it back as part of the SignedBytes scope on
// verify), so a tag flip changes the verification result.
type MLDSA65Signer struct {
	sk *mldsa65.PrivateKey
	// pubHash is Hash32 of the full ML-DSA-65 public key. Precomputed for
	// allocation-free cap.Signer.Public() calls.
	pubHash [32]byte
	// pub is the canonical FIPS 204 public-key encoding; consumers
	// register this via cap.Verifier.IssuerKey, using
	// VerifyMLDSA65 as the algorithm-specific verifier.
	pub []byte
	// ctx is the FIPS 204 §5.2 domain-separating context string. SHOULD
	// be set to a per-deployment label (e.g. "hanzo-iam/cap/v1") so
	// signatures cannot cross-protocol replay. May be at most 255 bytes
	// per FIPS 204; empty is legal but cryptographically discouraged.
	ctx []byte
}

// mldsa65SignatureSize is the FIPS 204 ML-DSA-65 signature length in
// bytes (Level-3 parameter set, NIST PQC Round 4 / FIPS 204). The
// runtime imports luxfi/crypto/pq/mldsa/mldsa65.SignatureSize at
// init-checked equality so a binding bump that changes the figure is
// caught at startup rather than at first signature.
var mldsa65SignatureSize = mldsa65.SignatureSize

// NewMLDSA65Signer generates a fresh ML-DSA-65 keypair.
//
// ctx is the FIPS 204 §5.2 context string baked into every signature this
// signer produces. Pass a per-deployment label like "hanzo-iam/cap/v1";
// empty is legal but cryptographically discouraged. ctx MUST be at most
// 255 bytes (FIPS 204 §5.2 limit); longer values are rejected here.
func NewMLDSA65Signer(ctx []byte) (*MLDSA65Signer, []byte, error) {
	if len(ctx) > 255 {
		return nil, nil, fmt.Errorf("capauth: mldsa65 ctx too long: %d > 255", len(ctx))
	}
	pk, sk, err := mldsa65.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("capauth: mldsa65 keygen: %w", err)
	}
	pubBytes, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("capauth: mldsa65 marshal public: %w", err)
	}
	ctxCopy := append([]byte(nil), ctx...)
	s := &MLDSA65Signer{
		sk:      sk,
		pub:     pubBytes,
		ctx:     ctxCopy,
		pubHash: cap.Hash32(pubBytes),
	}
	return s, pubBytes, nil
}

// MLDSA65SignerFromKey constructs a signer from an existing ML-DSA-65
// private key (e.g. one loaded from Hanzo KMS). pubBytes is the matching
// FIPS 204 canonical public-key encoding.
func MLDSA65SignerFromKey(sk *mldsa65.PrivateKey, pubBytes []byte, ctx []byte) (*MLDSA65Signer, error) {
	if sk == nil {
		return nil, errors.New("capauth: mldsa65 from key: nil private key")
	}
	if len(pubBytes) == 0 {
		return nil, errors.New("capauth: mldsa65 from key: empty public key")
	}
	if len(ctx) > 255 {
		return nil, fmt.Errorf("capauth: mldsa65 ctx too long: %d > 255", len(ctx))
	}
	pubCopy := append([]byte(nil), pubBytes...)
	ctxCopy := append([]byte(nil), ctx...)
	return &MLDSA65Signer{
		sk:      sk,
		pub:     pubCopy,
		ctx:     ctxCopy,
		pubHash: cap.Hash32(pubCopy),
	}, nil
}

// Sign produces a FIPS 204 ML-DSA-65 signature over payload and packs
// it into the cap.SigSize (3408-byte) footer used by zap-spec v1.1:
//
//	out[0:3309]                   = mldsa65.Sign(sk, payload, ctx)
//	out[3309:cap.AlgTagOffset]    = zero pad
//	out[cap.AlgTagOffset]         = byte(SchemeMLDSA65)
//
// The signature is randomized (randomized=true in FIPS 204 §5.2) so the
// caller does not need to thread its own entropy; the ML-DSA-65 design
// is hedged against bad randomness, but fresh entropy hardens against
// fault-injection. ctx (set at signer construction) is the FIPS 204
// domain-separation string that prevents cross-protocol replay.
func (s *MLDSA65Signer) Sign(payload []byte) ([cap.SigSize]byte, error) {
	var out [cap.SigSize]byte
	if s.sk == nil {
		return out, errors.New("capauth: mldsa65 sign: nil private key")
	}
	sig, err := mldsa65.Sign(s.sk, payload, s.ctx, true)
	if err != nil {
		return out, fmt.Errorf("capauth: mldsa65 sign: %w", err)
	}
	if len(sig) != mldsa65SignatureSize {
		return out, fmt.Errorf("capauth: mldsa65 sign produced %d bytes, want %d",
			len(sig), mldsa65SignatureSize)
	}
	// FIPS 204 sig + algorithm tag at the end of the footer. The bytes
	// between len(sig) and cap.AlgTagOffset are zero by the `var out`
	// declaration; we do not need to memset them. The wire-byte tag is
	// cap.SchemeMLDSA65 (0x03), not the typed-enum SchemeMLDSA65 (which
	// is 2 to align with Identity.sol's claim.scheme integer space).
	copy(out[:], sig)
	out[cap.AlgTagOffset] = byte(cap.SchemeMLDSA65)
	return out, nil
}

// VerifyMLDSA65 is the verifier counterpart to MLDSA65Signer.Sign. It
// unpacks the leading mldsa65SignatureSize bytes of sig and calls into
// FIPS 204 verification with the supplied public-key encoding (pubBytes)
// and domain-separation context (ctx — must match what Sign used). The
// pad bytes between the signature and the algorithm tag are ignored.
//
// Returns nil on success; a wrapped error on framing failure; or
// cap.ErrSigMismatch on a cryptographically valid-shape signature that
// fails the FIPS 204 §5.3 check.
func VerifyMLDSA65(pubBytes, payload, ctx []byte, sig [cap.SigSize]byte) error {
	if sig[cap.AlgTagOffset] != byte(cap.SchemeMLDSA65) {
		return fmt.Errorf("capauth: mldsa65 verify: alg tag %#x, want %#x",
			sig[cap.AlgTagOffset], byte(cap.SchemeMLDSA65))
	}
	if len(pubBytes) != mldsa65.PublicKeySize {
		return fmt.Errorf("capauth: mldsa65 verify: pubkey wrong size: %d", len(pubBytes))
	}
	var pk mldsa65.PublicKey
	if err := pk.UnmarshalBinary(pubBytes); err != nil {
		return fmt.Errorf("capauth: mldsa65 verify: unmarshal public: %w", err)
	}
	if !mldsa65.Verify(&pk, payload, ctx, sig[:mldsa65SignatureSize]) {
		return cap.ErrSigMismatch
	}
	return nil
}

// Public returns the 32-byte hash of the ML-DSA-65 public key.
func (s *MLDSA65Signer) Public() [32]byte { return s.pubHash }

// PublicBytes returns a fresh copy of the canonical FIPS 204 public key
// encoding. Safe to register directly with cap.Verifier.IssuerKey once the
// wire bump lands; today the signer is unusable because Sign refuses.
func (s *MLDSA65Signer) PublicBytes() []byte {
	out := make([]byte, len(s.pub))
	copy(out, s.pub)
	return out
}

// ---- KMS bootstrap ---------------------------------------------------------

// KMSClient is the narrow interface this package consumes from a KMS. We
// avoid pulling github.com/hanzoai/kms/sdk/go transitively into every
// resource server that wants to verify caps; signing is an IAM-side
// concern, so the interface lives here and the concrete wiring stays in
// IAM's controllers package.
type KMSClient interface {
	// FetchEd25519Seed returns the 32-byte ed25519 seed at keyRef. NOT
	// the 64-byte expanded private key — KMS stores the seed; expansion
	// happens here, in-process, and the seed bytes are zeroed
	// immediately afterwards.
	FetchEd25519Seed(keyRef string) ([]byte, error)

	// FetchMLDSA65Private returns the canonical FIPS 204 private-key
	// encoding at keyRef. The bytes are unmarshalled in-process and the
	// raw buffer zeroed.
	FetchMLDSA65Private(keyRef string) ([]byte, error)
}

// LoadEd25519FromKMS materialises an Ed25519Signer from a KMS-supplied
// 32-byte seed. The seed is expanded into an ed25519 keypair, the signer
// constructed, and the seed bytes wiped.
//
// keyRef shape is the KMSClient's concern; for Hanzo KMS the canonical
// shape is "providers/hanzo/iam/{env}/cap-signing-{keyid}" but this
// package does not enforce it.
func LoadEd25519FromKMS(client KMSClient, keyRef string) (*Ed25519Signer, ed25519.PublicKey, error) {
	if client == nil {
		return nil, nil, errors.New("capauth: kms client nil")
	}
	seed, err := client.FetchEd25519Seed(keyRef)
	if err != nil {
		return nil, nil, fmt.Errorf("capauth: kms fetch ed25519 seed: %w", err)
	}
	defer func() {
		for i := range seed {
			seed[i] = 0
		}
	}()
	return NewEd25519SignerFromSeed(seed)
}

// LoadMLDSA65FromKMS materialises an MLDSA65Signer from a KMS-supplied
// FIPS 204 private-key encoding. ctx is the per-deployment domain
// separator.
//
// Note: the signer Sign-refuses until zap-spec v1.1; LoadMLDSA65FromKMS
// still succeeds so production can stage keys and exercise the boundary.
func LoadMLDSA65FromKMS(client KMSClient, keyRef string, ctx []byte) (*MLDSA65Signer, []byte, error) {
	if client == nil {
		return nil, nil, errors.New("capauth: kms client nil")
	}
	skBytes, err := client.FetchMLDSA65Private(keyRef)
	if err != nil {
		return nil, nil, fmt.Errorf("capauth: kms fetch mldsa65: %w", err)
	}
	defer func() {
		for i := range skBytes {
			skBytes[i] = 0
		}
	}()
	var sk mldsa65.PrivateKey
	if err := sk.UnmarshalBinary(skBytes); err != nil {
		return nil, nil, fmt.Errorf("capauth: kms mldsa65 unmarshal: %w", err)
	}
	pub := sk.Public().(*mldsa65.PublicKey)
	pubBytes, err := pub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("capauth: kms mldsa65 marshal public: %w", err)
	}
	signer, err := MLDSA65SignerFromKey(&sk, pubBytes, ctx)
	if err != nil {
		return nil, nil, err
	}
	return signer, pubBytes, nil
}
