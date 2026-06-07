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

// bootstrap.go — process-wide singletons used by the controller layer.
//
// The library types (Issuer, Verifier, Store, IssuerRegistry) are deliberately
// per-instance: tests construct them fresh, resource servers compose their
// own, and the package never owns any global state at that layer. The HTTP
// edge inside IAM is different — it has exactly one cap-signing key (loaded
// from KMS at boot) and exactly one revocation log, so the controllers need a
// well-known place to reach the singleton without threading it through every
// handler signature.
//
// The pre-existing globals in cap_auth.go (revocations + issuerRegistry) cover
// the legacy whoami flow. This file wires the *library-layer* singleton on
// top: a *Issuer with the KMS-loaded signer, an IssuerRegistry shared with
// cap_auth.go (so /v1/iam/whoami and /v1/iam/cap/issue both verify against
// the same set of public keys), and a *MemoryStore for revocations.
//
// Resource servers never call into this file — they construct their own
// Verifier from an iamclient.Registry that polls /v1/iam/cap/issuer-keys.

package capauth

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"sync"
	"time"

	"github.com/zap-proto/go/cap"
)

// ProcessIssuer is the singleton Issuer the IAM HTTP edge uses to mint caps.
// Set by InitProcessIssuer once at boot; nil before that — callers must
// gate on InitProcessIssuer having run and returned nil.
//
// We keep this exported so the controller layer can introspect (and so
// tests can swap it) without locating it through the package. The mu
// below guards write access; reads after boot are mu-free.
var (
	processMu      sync.RWMutex
	processIssuer  *Issuer
	processStore   RevocationStore
	processReg     IssuerRegistry
	processCtxID   string // identifier passed to the cap signer's context (e.g. "hanzo-iam/cap/v1")
	processPubKey  ed25519.PublicKey
	processPubHash [32]byte
)

// ErrProcessNotInitialised is returned by accessors before InitProcessIssuer
// completes. Controllers map this to a 503 — caps cannot be minted or
// verified until the boot sequence has loaded the signing key from KMS.
var ErrProcessNotInitialised = errors.New("capauth: process issuer not initialised")

// ProcessConfig drives InitProcessIssuer.
type ProcessConfig struct {
	// Seed is the 32-byte ed25519 seed loaded from KMS. The caller is
	// responsible for wiping this slice after InitProcessIssuer returns.
	Seed []byte

	// CtxID is the per-deployment label baked into log lines + future
	// PQ signer context. Today only carried for traceability.
	CtxID string
}

// InitProcessIssuer constructs the singleton Issuer + Store + Registry.
// Idempotent — repeated calls with the same seed return nil; repeated calls
// with a different seed are an error (would invalidate previously-minted
// caps in a deployment that didn't intend a key rotation).
//
// The seed bytes are consumed via NewEd25519SignerFromSeed; the caller is
// expected to zero its own buffer once this function returns.
func InitProcessIssuer(cfg ProcessConfig) error {
	if len(cfg.Seed) != ed25519.SeedSize {
		return errors.New("capauth: bootstrap seed wrong size")
	}

	signer, pub, err := NewEd25519SignerFromSeed(cfg.Seed)
	if err != nil {
		return err
	}

	processMu.Lock()
	defer processMu.Unlock()

	if processIssuer != nil {
		// Already booted. Either same key (no-op) or different (refuse).
		if bytesEqualConstantTime(processPubKey, pub) {
			return nil
		}
		return errors.New("capauth: process issuer already initialised with a different key")
	}

	store := NewMemoryStore()
	reg := NewMemoryRegistry()
	reg.Register(cap.Hash32(pub), pub)

	// Also seed the legacy cap_auth.go globals so /v1/iam/whoami's
	// verifier sees the same issuer key. The legacy and library
	// registries are independent maps; we register into both rather
	// than collapsing them, because cap_auth.go's globals are
	// goroutine-safe and exposed via legacy public surfaces that we
	// don't want to remove during the migration.
	RegisterIssuer(cap.Hash32(pub), pub)

	processIssuer = &Issuer{
		Signer: signer,
		Scheme: SchemeEd25519,
		Clock:  SystemClock{},
	}
	processStore = store
	processReg = reg
	processCtxID = cfg.CtxID
	processPubKey = pub
	processPubHash = cap.Hash32(pub)

	return nil
}

// ProcessIssuerHandle returns the singleton Issuer or
// ErrProcessNotInitialised if InitProcessIssuer hasn't run.
func ProcessIssuerHandle() (*Issuer, error) {
	processMu.RLock()
	defer processMu.RUnlock()
	if processIssuer == nil {
		return nil, ErrProcessNotInitialised
	}
	return processIssuer, nil
}

// ProcessStoreHandle returns the singleton RevocationStore.
func ProcessStoreHandle() (RevocationStore, error) {
	processMu.RLock()
	defer processMu.RUnlock()
	if processStore == nil {
		return nil, ErrProcessNotInitialised
	}
	return processStore, nil
}

// ProcessRegistryHandle returns the singleton IssuerRegistry.
func ProcessRegistryHandle() (IssuerRegistry, error) {
	processMu.RLock()
	defer processMu.RUnlock()
	if processReg == nil {
		return nil, ErrProcessNotInitialised
	}
	return processReg, nil
}

// ProcessIssuerPublicKey returns a fresh copy of the singleton's raw
// ed25519 public key. Suitable for serving on /v1/iam/cap/issuer-keys.
func ProcessIssuerPublicKey() (ed25519.PublicKey, [32]byte, error) {
	processMu.RLock()
	defer processMu.RUnlock()
	if processPubKey == nil {
		return nil, [32]byte{}, ErrProcessNotInitialised
	}
	out := make(ed25519.PublicKey, len(processPubKey))
	copy(out, processPubKey)
	return out, processPubHash, nil
}

// ResetProcessForTest wipes the singleton. Test-only — callers MUST be in
// the same package, so the symbol is not exported in a way that helps
// foreign packages. We export it because the controller-package tests
// live outside capauth and need a way to roll boot state between cases.
func ResetProcessForTest() {
	processMu.Lock()
	defer processMu.Unlock()
	processIssuer = nil
	processStore = nil
	processReg = nil
	processCtxID = ""
	processPubKey = nil
	processPubHash = [32]byte{}
	ClearIssuers()
	ClearRevocations()
}

// ProcessContextID returns the CtxID supplied to InitProcessIssuer. Empty
// string before init.
func ProcessContextID() string {
	processMu.RLock()
	defer processMu.RUnlock()
	return processCtxID
}

// IssuerKeyDescriptor is the on-the-wire shape for /v1/iam/cap/issuer-keys.
// One entry per active signing key the resource servers may encounter on
// minted caps.
type IssuerKeyDescriptor struct {
	// Scheme is the SchemeXxx value (1 = ed25519 today).
	Scheme uint8 `json:"scheme"`

	// FingerprintHex is the lowercase-hex Hash32 of the public-key bytes,
	// which is also what cap.Cap.Issuer() returns. Resource servers index
	// their registry by this hash.
	FingerprintHex string `json:"fingerprintHex"`

	// PublicKeyBase64 is the raw public-key bytes (32 for ed25519,
	// FIPS-204-canonical for ML-DSA-65) standard-base64 encoded.
	PublicKeyBase64 string `json:"publicKeyBase64"`

	// NotAfter, if non-zero, is the Unix-seconds at which this issuer key
	// is scheduled to retire — resource servers may then drop it from
	// their registry on next refresh. Zero means "no scheduled retirement".
	NotAfter int64 `json:"notAfter,omitempty"`
}

// ListIssuerKeys returns the current set of active issuer keys. v1 is the
// trivial one-entry list: the process singleton. When key rotation lands
// this returns the union of {current, prev-still-acceptable}.
//
// Exported so the controller layer can serve it on /v1/iam/cap/issuer-keys
// without reaching into private state.
func ListIssuerKeys() ([]IssuerKeyDescriptor, error) {
	processMu.RLock()
	defer processMu.RUnlock()
	if processPubKey == nil {
		return nil, ErrProcessNotInitialised
	}
	hash := processPubHash
	// hexFingerprint mirrors the hex32 helper in cap_auth.go so this
	// package keeps a single hex encoder.
	out := []IssuerKeyDescriptor{
		{
			Scheme:          uint8(SchemeEd25519),
			FingerprintHex:  Hex32(hash),
			PublicKeyBase64: stdBase64(processPubKey),
		},
	}
	return out, nil
}

// stdBase64 wraps base64.StdEncoding.EncodeToString. We accept the
// allocation here — the result rides on the /v1/iam/cap/issuer-keys
// response, which is cache-friendly, so per-call cost is amortised.
func stdBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// _ unused-suppression sentinel for the time import (kept for future expiry
// scheduling on IssuerKeyDescriptor.NotAfter).
var _ = time.Time{}
