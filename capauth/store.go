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

import "sync"

// RevocationStore tracks which caps have been revoked.
//
// The interface separates IAM's responsibility (publish a revocation,
// expose it for resource servers to consult) from any one storage
// engine. The default implementation, MemoryStore, holds an in-memory
// set and is the right answer for tests and single-process IAM
// deployments. Production IAM swaps in a store backed by the
// IAM cap-store table; resource servers swap in a store backed by the
// PubSub gossip topic and a local LRU cache.
//
// The interface is intentionally smaller than a full CRL surface: a
// revocation is irreversible (un-revoke does not exist; mint a fresh
// cap if you change your mind), so the only operations are "mark
// revoked" and "is it revoked".
type RevocationStore interface {
	// IsRevoked reports whether capID has been revoked. Must be safe
	// for concurrent use. Implementations should return false on lookup
	// errors; a transient storage failure must not cause caps to be
	// silently accepted as valid, so callers wrap this with a tighter
	// freshness budget at a higher layer.
	IsRevoked(capID [32]byte) bool

	// Revoke marks capID as revoked. Idempotent. Must be safe for
	// concurrent use.
	Revoke(capID [32]byte)
}

// MemoryStore is an in-memory RevocationStore. Safe for concurrent use.
// Test code and lab IAM deployments use this directly; production IAM
// wraps a DB-backed store in the same interface.
type MemoryStore struct {
	mu      sync.RWMutex
	revoked map[[32]byte]struct{}
}

// NewMemoryStore constructs an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{revoked: map[[32]byte]struct{}{}}
}

// IsRevoked reports whether capID has been revoked.
func (s *MemoryStore) IsRevoked(capID [32]byte) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.revoked[capID]
	return ok
}

// Revoke marks capID as revoked. Idempotent.
func (s *MemoryStore) Revoke(capID [32]byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked[capID] = struct{}{}
}

// Clear wipes the store. Test-only.
func (s *MemoryStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.revoked = map[[32]byte]struct{}{}
}

// IssuerRegistry resolves issuer-pubkey-hash to the raw public key bytes
// every verifier needs to validate a cap's signature.
//
// As with RevocationStore, the interface separates the resolution
// semantics from any one backing store. Lab and tests use MemoryRegistry;
// production wires this into the IAM key table.
type IssuerRegistry interface {
	// Lookup returns the raw public-key bytes for the issuer whose
	// 32-byte hash is hashedPub. For ed25519, the returned bytes are
	// the 32-byte raw public key. For ML-DSA-65, the returned bytes
	// are the FIPS 204 canonical public-key encoding.
	//
	// Implementations must return cap.ErrIssuerUnknown for unknown
	// hashes — the cap runtime's Verifier.Verify is sensitive to this
	// specific sentinel.
	Lookup(hashedPub [32]byte) ([]byte, error)

	// Register associates a raw pubkey with its hash. Idempotent — a
	// repeated registration of the same (hash, pub) pair is a no-op;
	// a repeated registration with a different pub bytes panics (this
	// would indicate a hash collision, which is cryptographic-grade
	// unlikely and a sign of a broken hash function).
	Register(hashedPub [32]byte, pub []byte)
}

// MemoryRegistry is an in-memory IssuerRegistry. Safe for concurrent
// use.
type MemoryRegistry struct {
	mu   sync.RWMutex
	keys map[[32]byte][]byte
}

// NewMemoryRegistry constructs an empty MemoryRegistry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{keys: map[[32]byte][]byte{}}
}

// Lookup returns the raw public-key bytes for hashedPub or
// cap.ErrIssuerUnknown.
func (r *MemoryRegistry) Lookup(hashedPub [32]byte) ([]byte, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pub, ok := r.keys[hashedPub]
	if !ok {
		return nil, errIssuerUnknown
	}
	out := make([]byte, len(pub))
	copy(out, pub)
	return out, nil
}

// Register associates hashedPub with pub. Idempotent for identical (hash, pub);
// panics on conflicting bytes (a real hash collision would be a cryptographic
// emergency).
func (r *MemoryRegistry) Register(hashedPub [32]byte, pub []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.keys[hashedPub]; ok {
		if !bytesEqualConstantTime(existing, pub) {
			panic("capauth: hash collision on IssuerRegistry.Register — different pubkeys map to the same hash")
		}
		return
	}
	cp := make([]byte, len(pub))
	copy(cp, pub)
	r.keys[hashedPub] = cp
}

// Clear wipes the registry. Test-only.
func (r *MemoryRegistry) Clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.keys = map[[32]byte][]byte{}
}
