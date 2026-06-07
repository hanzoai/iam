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
	"testing"

	"github.com/zap-proto/go/cap"
)

// randSeed produces a fresh 32-byte ed25519 seed.
func randSeed(t *testing.T) []byte {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read seed: %v", err)
	}
	return seed
}

// TestBootstrap_FreshInit asserts the singleton boots cleanly and exposes
// matching Issuer + Registry + key.
func TestBootstrap_FreshInit(t *testing.T) {
	ResetProcessForTest()
	defer ResetProcessForTest()

	seed := randSeed(t)
	if err := InitProcessIssuer(ProcessConfig{Seed: seed, CtxID: "test"}); err != nil {
		t.Fatalf("InitProcessIssuer: %v", err)
	}

	iss, err := ProcessIssuerHandle()
	if err != nil || iss == nil {
		t.Fatalf("ProcessIssuerHandle: %v iss=%v", err, iss)
	}

	store, err := ProcessStoreHandle()
	if err != nil || store == nil {
		t.Fatalf("ProcessStoreHandle: %v", err)
	}

	reg, err := ProcessRegistryHandle()
	if err != nil || reg == nil {
		t.Fatalf("ProcessRegistryHandle: %v", err)
	}

	pub, hash, err := ProcessIssuerPublicKey()
	if err != nil {
		t.Fatalf("ProcessIssuerPublicKey: %v", err)
	}
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("pub size: got %d want %d", len(pub), ed25519.PublicKeySize)
	}
	if hash != cap.Hash32(pub) {
		t.Fatalf("returned hash != Hash32(pub)")
	}

	// Registry must resolve the singleton's public key.
	got, err := reg.Lookup(hash)
	if err != nil {
		t.Fatalf("Registry.Lookup: %v", err)
	}
	if !bytesEqualConstantTime(got, pub) {
		t.Fatalf("Registry.Lookup returned different bytes")
	}

	if ProcessContextID() != "test" {
		t.Fatalf("ProcessContextID: got %q want %q", ProcessContextID(), "test")
	}
}

// TestBootstrap_IdempotentSameSeed asserts repeated init with the same seed
// is a no-op (returns nil and does not mutate state).
func TestBootstrap_IdempotentSameSeed(t *testing.T) {
	ResetProcessForTest()
	defer ResetProcessForTest()

	seed := randSeed(t)
	if err := InitProcessIssuer(ProcessConfig{Seed: seed, CtxID: "test"}); err != nil {
		t.Fatalf("first init: %v", err)
	}

	pub1, hash1, _ := ProcessIssuerPublicKey()

	// Pass a fresh copy of the seed (the first call consumed and zeroed
	// the buffer caller-side; we don't model that here but pass a copy
	// for hygiene).
	seedCopy := append([]byte(nil), seed...)
	if err := InitProcessIssuer(ProcessConfig{Seed: seedCopy, CtxID: "test"}); err != nil {
		t.Fatalf("repeated init same seed: %v", err)
	}

	pub2, hash2, _ := ProcessIssuerPublicKey()
	if !bytesEqualConstantTime(pub1, pub2) || hash1 != hash2 {
		t.Fatalf("idempotent init changed key bytes")
	}
}

// TestBootstrap_DifferentSeedRefuses asserts a second init with a different
// seed errors instead of silently rotating the key. Rotation MUST go
// through an explicit ResetProcessForTest + InitProcessIssuer pair so the
// caller observes the change.
func TestBootstrap_DifferentSeedRefuses(t *testing.T) {
	ResetProcessForTest()
	defer ResetProcessForTest()

	if err := InitProcessIssuer(ProcessConfig{Seed: randSeed(t), CtxID: "test"}); err != nil {
		t.Fatalf("first init: %v", err)
	}
	err := InitProcessIssuer(ProcessConfig{Seed: randSeed(t), CtxID: "test"})
	if err == nil {
		t.Fatalf("expected refusal on different-seed init, got nil")
	}
}

// TestBootstrap_BeforeInit asserts accessors return ErrProcessNotInitialised
// before InitProcessIssuer has run.
func TestBootstrap_BeforeInit(t *testing.T) {
	ResetProcessForTest()

	if _, err := ProcessIssuerHandle(); !errors.Is(err, ErrProcessNotInitialised) {
		t.Fatalf("expected ErrProcessNotInitialised, got %v", err)
	}
	if _, err := ProcessStoreHandle(); !errors.Is(err, ErrProcessNotInitialised) {
		t.Fatalf("expected ErrProcessNotInitialised, got %v", err)
	}
	if _, err := ProcessRegistryHandle(); !errors.Is(err, ErrProcessNotInitialised) {
		t.Fatalf("expected ErrProcessNotInitialised, got %v", err)
	}
	if _, _, err := ProcessIssuerPublicKey(); !errors.Is(err, ErrProcessNotInitialised) {
		t.Fatalf("expected ErrProcessNotInitialised, got %v", err)
	}
}

// TestBootstrap_WrongSeedSize asserts a malformed seed errors at init.
func TestBootstrap_WrongSeedSize(t *testing.T) {
	ResetProcessForTest()
	defer ResetProcessForTest()

	if err := InitProcessIssuer(ProcessConfig{Seed: make([]byte, 16), CtxID: "test"}); err == nil {
		t.Fatalf("expected error on too-short seed")
	}
}

// TestBootstrap_IssueKeyDescriptors asserts the issuer-keys list shape is
// what the resource servers expect.
func TestBootstrap_IssueKeyDescriptors(t *testing.T) {
	ResetProcessForTest()
	defer ResetProcessForTest()

	if err := InitProcessIssuer(ProcessConfig{Seed: randSeed(t), CtxID: "test"}); err != nil {
		t.Fatalf("init: %v", err)
	}

	keys, err := ListIssuerKeys()
	if err != nil {
		t.Fatalf("listIssuerKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected one key, got %d", len(keys))
	}
	k := keys[0]
	if k.Scheme != uint8(SchemeEd25519) {
		t.Fatalf("scheme: got %d want %d", k.Scheme, SchemeEd25519)
	}
	if len(k.FingerprintHex) != 64 {
		t.Fatalf("fingerprint hex length: got %d want 64", len(k.FingerprintHex))
	}
	if k.PublicKeyBase64 == "" {
		t.Fatalf("PublicKeyBase64 empty")
	}
}
