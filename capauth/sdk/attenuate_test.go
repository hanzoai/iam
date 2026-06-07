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

package sdk

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/hanzoai/iam/capauth"
	zapcap "github.com/zap-proto/go/cap"
)

// fixture bundles a real signer + parent cap so each test starts from a
// minted root.
type fixture struct {
	t           *testing.T
	rootHolder  *capauth.Ed25519Signer
	rootHolderH [32]byte
	registry    *capauth.MemoryRegistry
	parent      zapcap.Cap
	parentB64   string
	audience    [32]byte
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	issSigner, _, err := capauth.NewEd25519Signer()
	if err != nil {
		t.Fatalf("issuer signer: %v", err)
	}
	rootHolder, _, err := capauth.NewEd25519Signer()
	if err != nil {
		t.Fatalf("root holder signer: %v", err)
	}
	reg := capauth.NewMemoryRegistry()
	reg.Register(issSigner.Public(), issSigner.PublicKey())
	reg.Register(rootHolder.Public(), rootHolder.PublicKey())

	var audience [32]byte
	if _, err := rand.Read(audience[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}

	iss := &capauth.Issuer{Signer: issSigner, Scheme: capauth.SchemeEd25519, Clock: capauth.SystemClock{}}
	parent, err := iss.Issue(capauth.IssueParams{
		Kind:        zapcap.KindATSOrder,
		Target:      audience,
		Holder:      rootHolder.Public(),
		Permissions: 0b1111, // 4 bits granted
		Audience:    audience,
		ExpiresAt:   time.Now().Add(2 * time.Hour).Unix(),
		MaxDepth:    4,
	})
	if err != nil {
		t.Fatalf("Issue parent: %v", err)
	}
	return &fixture{
		t:           t,
		rootHolder:  rootHolder,
		rootHolderH: rootHolder.Public(),
		registry:    reg,
		parent:      parent,
		parentB64:   base64.StdEncoding.EncodeToString(parent.Bytes()),
		audience:    audience,
	}
}

// TestAttenuate_Narrow_OK exercises the happy path and asserts that
// running the child through a Verifier succeeds.
func TestAttenuate_Narrow_OK(t *testing.T) {
	f := newFixture(t)

	childHolder, _, err := capauth.NewEd25519Signer()
	if err != nil {
		t.Fatalf("child holder: %v", err)
	}
	f.registry.Register(childHolder.Public(), childHolder.PublicKey())

	out, err := Attenuate(AttenuateInput{
		Cap:       f.parentB64,
		Signer:    f.rootHolder,
		NewHolder: childHolder.Public(),
		Scopes:    0b0011, // subset of 0b1111
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})
	if err != nil {
		t.Fatalf("Attenuate: %v", err)
	}
	if out.Cap == "" || out.CapIDHex == "" || out.ExpiresAt == "" {
		t.Fatalf("output missing fields: %+v", out)
	}

	// Round-trip Verify against a real Verifier with the parent in chain.
	rawChild, err := base64.StdEncoding.DecodeString(out.Cap)
	if err != nil {
		t.Fatalf("decode child: %v", err)
	}
	child, err := zapcap.Wrap(rawChild)
	if err != nil {
		t.Fatalf("Wrap child: %v", err)
	}
	verifier := &capauth.LibVerifier{
		Store:    capauth.NewMemoryStore(),
		Registry: f.registry,
		Clock:    capauth.SystemClock{},
		Identity: f.audience,
	}
	if err := verifier.Verify(capauth.VerifyParams{
		Leaf:       child,
		Chain:      []zapcap.Cap{f.parent},
		RequiredOp: 0b0001,
		Target:     f.audience,
		Holder:     childHolder.Public(),
	}); err != nil {
		t.Fatalf("Verify child: %v", err)
	}
}

// TestAttenuate_RejectsWidenPerms asserts the library-layer error is
// surfaced when a caller tries to widen permissions.
func TestAttenuate_RejectsWidenPerms(t *testing.T) {
	f := newFixture(t)

	childHolder, _, _ := capauth.NewEd25519Signer()
	_, err := Attenuate(AttenuateInput{
		Cap:       f.parentB64,
		Signer:    f.rootHolder,
		NewHolder: childHolder.Public(),
		Scopes:    0b1_1111, // bit 4 not in parent
	})
	if !errors.Is(err, capauth.ErrPermsWidened) {
		t.Fatalf("expected ErrPermsWidened, got %v", err)
	}
}

// TestAttenuate_RejectsBadBase64 asserts a malformed cap string is
// rejected at the boundary.
func TestAttenuate_RejectsBadBase64(t *testing.T) {
	signer, _, _ := capauth.NewEd25519Signer()
	_, err := Attenuate(AttenuateInput{
		Cap:    "not-valid-base64!!!",
		Signer: signer,
		Scopes: 0b1,
	})
	if err == nil {
		t.Fatalf("expected base64 decode error")
	}
}

// TestAttenuate_RejectsNilSigner asserts the caller-error checks fire.
func TestAttenuate_RejectsNilSigner(t *testing.T) {
	_, err := Attenuate(AttenuateInput{
		Cap:    "validlookingbase64==",
		Signer: nil,
		Scopes: 0b1,
	})
	if err == nil {
		t.Fatalf("expected nil-signer error")
	}
}

// TestAttenuate_RejectsZeroScopes asserts we refuse the deny-all
// degenerate case (a deny-all cap is useless and likely a caller bug).
func TestAttenuate_RejectsZeroScopes(t *testing.T) {
	f := newFixture(t)
	_, err := Attenuate(AttenuateInput{
		Cap:    f.parentB64,
		Signer: f.rootHolder,
		Scopes: 0,
	})
	if err == nil {
		t.Fatalf("expected zero-scopes error")
	}
}

// TestAttenuate_RejectsWrongSigner asserts the signer-holder binding is
// checked at the SDK boundary so the caller gets a friendly message
// instead of cap.ErrChainBroken from the runtime.
func TestAttenuate_RejectsWrongSigner(t *testing.T) {
	f := newFixture(t)

	other, _, _ := capauth.NewEd25519Signer() // not the parent's holder
	_, err := Attenuate(AttenuateInput{
		Cap:       f.parentB64,
		Signer:    other,
		NewHolder: [32]byte{},
		Scopes:    0b0001,
	})
	if err == nil {
		t.Fatalf("expected wrong-signer error")
	}
}

// TestAttenuate_InheritsParentExpiry asserts that when ExpiresAt is zero
// in the input, the child inherits the parent's expiry.
func TestAttenuate_InheritsParentExpiry(t *testing.T) {
	f := newFixture(t)

	childHolder, _, _ := capauth.NewEd25519Signer()
	out, err := Attenuate(AttenuateInput{
		Cap:       f.parentB64,
		Signer:    f.rootHolder,
		NewHolder: childHolder.Public(),
		Scopes:    0b0001,
		// ExpiresAt left zero.
	})
	if err != nil {
		t.Fatalf("Attenuate: %v", err)
	}
	// Child's expiry should be parent's (or close to it — they're
	// both Unix-second precision).
	parentExp := time.Unix(int64(f.parent.ExpiresAt()), 0).UTC().Format(time.RFC3339)
	if out.ExpiresAt != parentExp {
		t.Fatalf("ExpiresAt: got %q want %q (parent's)", out.ExpiresAt, parentExp)
	}
}
