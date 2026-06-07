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
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/luxfi/crypto/pq/mldsa/mldsa65"
	"github.com/zap-proto/go/cap"
)

// mldsa65GenerateForTest is a thin wrapper around the FIPS 204 keygen
// so tests can spell their own keypairs into the fakeKMS without the
// production NewMLDSA65Signer entry point (which both generates and
// pre-marshals the public key in one call).
func mldsa65GenerateForTest() (*mldsa65.PublicKey, *mldsa65.PrivateKey, error) {
	return mldsa65.GenerateKey(rand.Reader)
}

// ---- helpers ---------------------------------------------------------------

// libTestFixture bundles the deterministic state every library-layer test
// shares: a Verifier with empty Store + Registry, an issuer signer +
// holder signer, and helpers to mint+attenuate caps.
//
// We mint a fresh signer for the issuer AND for each downstream holder
// because cap.Attenuate enforces signer.Public() == parent.Holder(), so
// "Bob the holder of the root cap" is the signer that must sign the
// "Bob delegates to Carol" attenuation.
type libTestFixture struct {
	t          *testing.T
	now        time.Time
	clock      FixedClock
	store      *MemoryStore
	registry   *MemoryRegistry
	verifier   *LibVerifier
	issSigner  *Ed25519Signer
	issIssuer  *Issuer
	resHolder  [32]byte // resource server identity baked into Verifier
	target     [32]byte // arbitrary target hash
	rootHolder *Ed25519Signer
	rootHoldH  [32]byte
}

func newLibFixture(t *testing.T) *libTestFixture {
	t.Helper()
	store := NewMemoryStore()
	registry := NewMemoryRegistry()

	issSigner, _, err := NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer (issuer): %v", err)
	}
	registry.Register(issSigner.Public(), issSigner.PublicKey())

	rootHolder, _, err := NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer (rootHolder): %v", err)
	}
	registry.Register(rootHolder.Public(), rootHolder.PublicKey())

	now := time.Unix(1_700_000_000, 0)
	clock := FixedClock{T: now}

	var resHolder, target [32]byte
	if _, err := rand.Read(resHolder[:]); err != nil {
		t.Fatalf("rand.Read resHolder: %v", err)
	}
	if _, err := rand.Read(target[:]); err != nil {
		t.Fatalf("rand.Read target: %v", err)
	}

	verifier := &LibVerifier{
		Store:    store,
		Registry: registry,
		Clock:    clock,
		Identity: resHolder,
	}

	iss := &Issuer{
		Signer: issSigner,
		Scheme: SchemeEd25519,
		Clock:  clock,
	}

	return &libTestFixture{
		t:          t,
		now:        now,
		clock:      clock,
		store:      store,
		registry:   registry,
		verifier:   verifier,
		issSigner:  issSigner,
		issIssuer:  iss,
		resHolder:  resHolder,
		target:     target,
		rootHolder: rootHolder,
		rootHoldH:  rootHolder.Public(),
	}
}

// mintRoot mints a root cap held by f.rootHolder, scoped to f.target,
// with permissions bitmask perms.
func (f *libTestFixture) mintRoot(perms uint64, audience [32]byte, expiresIn time.Duration, depth uint8) cap.Cap {
	f.t.Helper()
	exp := int64(0)
	if expiresIn != 0 {
		exp = f.now.Add(expiresIn).Unix()
	}
	c, err := f.issIssuer.Issue(IssueParams{
		Kind:        cap.KindIAMSession,
		Target:      f.target,
		Holder:      f.rootHoldH,
		Permissions: perms,
		Audience:    audience,
		ExpiresAt:   exp,
		MaxDepth:    depth,
	})
	if err != nil {
		f.t.Fatalf("mintRoot: %v", err)
	}
	return c
}

// ---- round-trip ------------------------------------------------------------

// TestLib_IssueVerify_RoundTrip is the happy path: mint a root, verify it,
// observe nil error.
func TestLib_IssueVerify_RoundTrip(t *testing.T) {
	f := newLibFixture(t)
	c := f.mintRoot(0b1, f.resHolder, 1*time.Hour, 0)
	err := f.verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0b1,
		Target:     f.target,
		Holder:     f.rootHoldH,
	})
	if err != nil {
		t.Fatalf("Verify happy path: %v", err)
	}
}

// TestLib_Verify_OpNotPermitted asserts the required-op gate works.
func TestLib_Verify_OpNotPermitted(t *testing.T) {
	f := newLibFixture(t)
	c := f.mintRoot(0b1, f.resHolder, 1*time.Hour, 0)
	err := f.verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0b10, // bit not granted
		Target:     f.target,
		Holder:     f.rootHoldH,
	})
	if !errors.Is(err, cap.ErrOpNotPermitted) {
		t.Fatalf("expected ErrOpNotPermitted, got %v", err)
	}
}

// ---- attenuation: narrowing OK --------------------------------------------

// TestLib_Attenuate_Narrow_OK derives a child cap with fewer permissions
// and a tighter expiry; verifies through the chain.
func TestLib_Attenuate_Narrow_OK(t *testing.T) {
	f := newLibFixture(t)
	parent := f.mintRoot(0b111, f.resHolder, 2*time.Hour, 4)

	// The rootHolder signs the attenuation: signer.Public() must equal
	// parent.Holder() — the cap runtime enforces this.
	childIss := &Issuer{Signer: f.rootHolder, Scheme: SchemeEd25519, Clock: f.clock}

	childHolder, _, err := NewEd25519Signer()
	if err != nil {
		t.Fatalf("childHolder keygen: %v", err)
	}
	f.registry.Register(childHolder.Public(), childHolder.PublicKey())

	child, err := childIss.Attenuate(parent, AttenuateParams{
		NewHolder:   childHolder.Public(),
		Permissions: 0b011,                              // subset of parent's 0b111
		ExpiresAt:   f.now.Add(1 * time.Hour).Unix(),    // tighter than parent's 2h
		MaxDepth:    0,                                   // inherit (parent's 4) - 1 = 3
	})
	if err != nil {
		t.Fatalf("Attenuate narrow: %v", err)
	}

	if err := f.verifier.Verify(VerifyParams{
		Leaf:       child,
		Chain:      []cap.Cap{parent},
		RequiredOp: 0b001,
		Target:     f.target,
		Holder:     childHolder.Public(),
	}); err != nil {
		t.Fatalf("Verify narrowed child: %v", err)
	}
}

// ---- attenuation: widening MUST reject ------------------------------------

// TestLib_Attenuate_Widen_Perms_Reject asserts attempts to grant the
// child a permission bit the parent does not hold are rejected at the
// helper boundary with ErrPermsWidened.
func TestLib_Attenuate_Widen_Perms_Reject(t *testing.T) {
	f := newLibFixture(t)
	parent := f.mintRoot(0b001, f.resHolder, 2*time.Hour, 4)

	childIss := &Issuer{Signer: f.rootHolder, Scheme: SchemeEd25519, Clock: f.clock}
	childHolder, _, err := NewEd25519Signer()
	if err != nil {
		t.Fatalf("childHolder keygen: %v", err)
	}

	_, err = childIss.Attenuate(parent, AttenuateParams{
		NewHolder:   childHolder.Public(),
		Permissions: 0b011, // tries to grant bit 1 that parent doesn't hold
	})
	if !errors.Is(err, ErrPermsWidened) {
		t.Fatalf("expected ErrPermsWidened, got %v", err)
	}
}

// TestLib_Attenuate_Widen_Expiry_Reject asserts attempts to set a child
// expiry strictly later than the parent's are rejected at the helper
// boundary with ErrCaveatWidened.
func TestLib_Attenuate_Widen_Expiry_Reject(t *testing.T) {
	f := newLibFixture(t)
	parent := f.mintRoot(0b1, f.resHolder, 1*time.Hour, 4)

	childIss := &Issuer{Signer: f.rootHolder, Scheme: SchemeEd25519, Clock: f.clock}
	childHolder, _, err := NewEd25519Signer()
	if err != nil {
		t.Fatalf("childHolder keygen: %v", err)
	}

	_, err = childIss.Attenuate(parent, AttenuateParams{
		NewHolder:   childHolder.Public(),
		Permissions: 0b1,
		ExpiresAt:   f.now.Add(2 * time.Hour).Unix(), // later than parent
	})
	if !errors.Is(err, ErrCaveatWidened) {
		t.Fatalf("expected ErrCaveatWidened, got %v", err)
	}
}

// TestLib_Attenuate_Widen_Audience_Reject asserts attempts to change a
// parent's CaveatAudience are rejected with ErrCaveatWidened.
func TestLib_Attenuate_Widen_Audience_Reject(t *testing.T) {
	f := newLibFixture(t)

	var aliceAud, bobAud [32]byte
	if _, err := rand.Read(aliceAud[:]); err != nil {
		t.Fatalf("rand.Read aliceAud: %v", err)
	}
	if _, err := rand.Read(bobAud[:]); err != nil {
		t.Fatalf("rand.Read bobAud: %v", err)
	}

	parent := f.mintRoot(0b1, aliceAud, 1*time.Hour, 4)

	childIss := &Issuer{Signer: f.rootHolder, Scheme: SchemeEd25519, Clock: f.clock}
	childHolder, _, err := NewEd25519Signer()
	if err != nil {
		t.Fatalf("childHolder keygen: %v", err)
	}

	_, err = childIss.Attenuate(parent, AttenuateParams{
		NewHolder:   childHolder.Public(),
		Permissions: 0b1,
		Audience:    bobAud, // ≠ parent's aliceAud
	})
	if !errors.Is(err, ErrCaveatWidened) {
		t.Fatalf("expected ErrCaveatWidened, got %v", err)
	}
}

// TestLib_Attenuate_Widen_Depth_Reject asserts attempts to set
// MaxDepth above (parent's - 1) are rejected.
func TestLib_Attenuate_Widen_Depth_Reject(t *testing.T) {
	f := newLibFixture(t)
	parent := f.mintRoot(0b1, f.resHolder, 1*time.Hour, 2) // depth 2

	childIss := &Issuer{Signer: f.rootHolder, Scheme: SchemeEd25519, Clock: f.clock}
	childHolder, _, err := NewEd25519Signer()
	if err != nil {
		t.Fatalf("childHolder keygen: %v", err)
	}

	_, err = childIss.Attenuate(parent, AttenuateParams{
		NewHolder:   childHolder.Public(),
		Permissions: 0b1,
		MaxDepth:    5, // parent permits at most parentDepth-1 = 1
	})
	if !errors.Is(err, ErrCaveatWidened) {
		t.Fatalf("expected ErrCaveatWidened, got %v", err)
	}
}

// ---- expiry ----------------------------------------------------------------

// TestLib_Verify_Expired asserts a cap whose ExpiresAt has passed under
// the verifier's Clock is rejected with cap.ErrExpired.
func TestLib_Verify_Expired(t *testing.T) {
	f := newLibFixture(t)
	c := f.mintRoot(0b1, f.resHolder, 1*time.Hour, 0) // expires in 1h

	// Advance the verifier's clock past expiry.
	f.verifier.Clock = FixedClock{T: f.now.Add(2 * time.Hour)}

	err := f.verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0b1,
		Target:     f.target,
		Holder:     f.rootHoldH,
	})
	if !errors.Is(err, cap.ErrExpired) {
		t.Fatalf("expected cap.ErrExpired, got %v", err)
	}
}

// ---- audience --------------------------------------------------------------

// TestLib_Verify_AudienceMismatch asserts a cap whose CaveatAudience
// does not name THIS verifier is rejected.
func TestLib_Verify_AudienceMismatch(t *testing.T) {
	f := newLibFixture(t)

	// Mint a cap whose audience is some other resource server.
	var otherAud [32]byte
	if _, err := rand.Read(otherAud[:]); err != nil {
		t.Fatalf("rand.Read otherAud: %v", err)
	}
	c := f.mintRoot(0b1, otherAud, 1*time.Hour, 0)

	err := f.verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0b1,
		Target:     f.target,
		Holder:     f.rootHoldH,
	})
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("expected ErrAudienceMismatch, got %v", err)
	}
}

// TestLib_Verify_AudienceMatch asserts an audience-matched cap passes
// the audience check.
func TestLib_Verify_AudienceMatch(t *testing.T) {
	f := newLibFixture(t)
	c := f.mintRoot(0b1, f.resHolder, 1*time.Hour, 0) // audience == f.resHolder

	err := f.verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0b1,
		Target:     f.target,
		Holder:     f.rootHoldH,
	})
	if err != nil {
		t.Fatalf("Verify with matching audience: %v", err)
	}
}

// ---- revocation ------------------------------------------------------------

// TestLib_Verify_Revoked asserts a cap whose ID is in the Store is
// rejected with cap.ErrRevoked.
func TestLib_Verify_Revoked(t *testing.T) {
	f := newLibFixture(t)
	c := f.mintRoot(0b1, f.resHolder, 1*time.Hour, 0)

	rev, err := f.issIssuer.Revoke(c, f.store)
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if rev.CapID != c.ID() {
		t.Fatalf("Revoke produced wrong CapID")
	}

	err = f.verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0b1,
		Target:     f.target,
		Holder:     f.rootHoldH,
	})
	if !errors.Is(err, cap.ErrRevoked) {
		t.Fatalf("expected cap.ErrRevoked, got %v", err)
	}
}

// TestLib_ApplyRevocation_Roundtrip asserts gossiped revocations
// flowing through ApplyRevocation make the local store reject the cap.
func TestLib_ApplyRevocation_Roundtrip(t *testing.T) {
	f := newLibFixture(t)
	c := f.mintRoot(0b1, f.resHolder, 1*time.Hour, 0)

	rev, err := f.issIssuer.Revoke(c, NewMemoryStore() /* ignore — we want only the wire bytes */)
	if err != nil {
		t.Fatalf("Revoke (gossiped side): %v", err)
	}
	encoded := cap.EncodeRevocation(rev)

	// Peer receives, looks up the issuer pubkey, applies.
	pub := f.issSigner.PublicKey()
	if err := ApplyRevocation(encoded, pub, f.store); err != nil {
		t.Fatalf("ApplyRevocation: %v", err)
	}

	err = f.verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0b1,
		Target:     f.target,
		Holder:     f.rootHoldH,
	})
	if !errors.Is(err, cap.ErrRevoked) {
		t.Fatalf("expected cap.ErrRevoked after gossiped revocation, got %v", err)
	}
}

// ---- chain depth ----------------------------------------------------------

// TestLib_Verify_ChainTooDeep asserts a chain longer than ChainDepthMax
// is rejected with ErrChainTooDeep, EVEN WITHOUT a MaxDepth caveat —
// the package-level ceiling is independent.
//
// We synthesize a long chain by building parent + N child caps; the
// rootHolder signs the first attenuation, each child's holder signs the
// next attenuation, etc.
func TestLib_Verify_ChainTooDeep(t *testing.T) {
	f := newLibFixture(t)
	root := f.mintRoot(0b1, f.resHolder, 24*time.Hour, 0) // no MaxDepth caveat

	chain := []cap.Cap{root}
	parent := root
	parentSigner := f.rootHolder

	for i := 0; i < ChainDepthMax; i++ {
		// At i=ChainDepthMax-1 the resulting leaf+chain is exactly
		// (ChainDepthMax+1) caps, which trips the ceiling.
		childSigner, _, err := NewEd25519Signer()
		if err != nil {
			t.Fatalf("childSigner %d: %v", i, err)
		}
		f.registry.Register(childSigner.Public(), childSigner.PublicKey())

		childIss := &Issuer{Signer: parentSigner, Scheme: SchemeEd25519, Clock: f.clock}
		child, err := childIss.Attenuate(parent, AttenuateParams{
			NewHolder:   childSigner.Public(),
			Permissions: 0b1,
		})
		if err != nil {
			t.Fatalf("Attenuate %d: %v", i, err)
		}
		chain = append([]cap.Cap{child}, chain...) // prepend: leaf first
		parent = child
		parentSigner = childSigner
	}

	leaf := chain[0]
	rest := chain[1:]

	err := f.verifier.Verify(VerifyParams{
		Leaf:       leaf,
		Chain:      rest,
		RequiredOp: 0b1,
		Target:     f.target,
		Holder:     leaf.Holder(),
	})
	if !errors.Is(err, ErrChainTooDeep) {
		t.Fatalf("expected ErrChainTooDeep, got %v", err)
	}
}

// ---- unknown caveat -------------------------------------------------------

// TestLib_Verify_UnknownCaveat asserts an unknown CaveatKind causes
// fail-closed rejection per SPEC.md §2.3 step 4.
func TestLib_Verify_UnknownCaveat(t *testing.T) {
	f := newLibFixture(t)

	// Build a cap with an out-of-spec caveat kind by reaching past the
	// helper boundary: mint via cap.Issue directly so we can stuff in a
	// non-canonical kind.
	in := cap.Issuance{
		Kind:        uint32(cap.KindIAMSession),
		Target:      f.target,
		Holder:      f.rootHoldH,
		Permissions: 0b1,
		IssuedAt:    f.now.Unix(),
		ExpiresAt:   f.now.Add(1 * time.Hour).Unix(),
		Caveats: []cap.Caveat{
			{Kind: cap.CaveatKind(0xDEAD), Value: []byte{0x01}},
		},
	}
	c, err := cap.Issue(in, f.issSigner)
	if err != nil {
		t.Fatalf("cap.Issue with weird caveat: %v", err)
	}

	err = f.verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0b1,
		Target:     f.target,
		Holder:     f.rootHoldH,
	})
	if !errors.Is(err, ErrCaveatUnknown) {
		t.Fatalf("expected ErrCaveatUnknown, got %v", err)
	}
}

// ---- ML-DSA-65 PQ round-trip ----------------------------------------------

// TestMLDSA65_Issue_Verify_RoundTrip is the PQ happy path: mint a root cap
// signed with ML-DSA-65, observe the wire-level invariants (scheme tag at
// cap.AlgTagOffset, signature occupying the leading 3309 bytes of the
// 3408-byte footer), and verify end-to-end via LibVerifier whose
// SchemeVerify hook dispatches on the tag byte and calls VerifyMLDSA65
// under the matching FIPS 204 ctx.
//
// This is the test that was guarded by the legacy ErrSchemeWireIncompat
// refusal at zap-spec v1.0 (sig96). At v1.1 (sig3408) the refusal is
// gone and PQ caps mint cleanly.
func TestMLDSA65_Issue_Verify_RoundTrip(t *testing.T) {
	ctx := []byte("hanzo-iam/cap/v1")

	signer, pubBytes, err := NewMLDSA65Signer(ctx)
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}

	// 1. Mint a root cap. No refusal at the Issue boundary anymore — the
	//    PQ signer is wire-compatible with the v1.1 footer.
	iss := &Issuer{Signer: signer, Scheme: SchemeMLDSA65, Clock: SystemClock{}}
	var target, holder [32]byte
	target[0] = 0xA1
	holder[0] = 0xB2

	c, err := iss.Issue(IssueParams{
		Kind:        cap.KindIAMSession,
		Target:      target,
		Holder:      holder,
		Permissions: 0xFF,
	})
	if err != nil {
		t.Fatalf("PQ Issue: %v", err)
	}

	// 2. Wire-level invariants: signature footer is cap.SigSize bytes
	//    wide, the algorithm tag at cap.AlgTagOffset is SchemeMLDSA65,
	//    and the leading 3309 bytes are non-trivial (a real ML-DSA-65
	//    signature is overwhelmingly unlikely to be all-zero or all-one).
	sig := c.Signature()
	if got := len(sig); got != cap.SigSize {
		t.Fatalf("Signature() length = %d, want cap.SigSize = %d", got, cap.SigSize)
	}
	if want := byte(cap.SchemeMLDSA65); sig[cap.AlgTagOffset] != want {
		t.Errorf("sig[%d] = %#x, want SchemeMLDSA65 = %#x",
			cap.AlgTagOffset, sig[cap.AlgTagOffset], want)
	}
	var allZero, allOne bool = true, true
	for i := 0; i < 3309; i++ {
		if sig[i] != 0 {
			allZero = false
		}
		if sig[i] != 0xFF {
			allOne = false
		}
	}
	if allZero || allOne {
		t.Errorf("ML-DSA-65 signature is degenerate (allZero=%v allOne=%v) — sign almost certainly failed silently",
			allZero, allOne)
	}

	// 3. End-to-end verify: build a LibVerifier with the matching ctx
	//    and an IssuerRegistry that resolves the signer's hash to its
	//    FIPS 204 pubkey encoding. The SchemeVerify hook on the
	//    LibVerifier picks up the SchemeMLDSA65 tag and dispatches to
	//    VerifyMLDSA65.
	registry := NewMemoryRegistry()
	registry.Register(signer.Public(), pubBytes)
	store := NewMemoryStore()
	verifier := &LibVerifier{
		Store:      store,
		Registry:   registry,
		Clock:      SystemClock{},
		MLDSA65Ctx: ctx,
	}
	if err := verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0x01,
		Target:     target,
		Holder:     holder,
	}); err != nil {
		t.Fatalf("LibVerifier.Verify (ML-DSA-65): %v", err)
	}

	// 4. ctx mismatch must fail (FIPS 204 §5.2 domain separation): the
	//    signer used ctx "hanzo-iam/cap/v1"; a verifier configured with
	//    a different ctx MUST reject the cap with ErrSigMismatch.
	verifierWrong := &LibVerifier{
		Store:      store,
		Registry:   registry,
		Clock:      SystemClock{},
		MLDSA65Ctx: []byte("hanzo-iam/cap/different-context"),
	}
	if err := verifierWrong.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0x01,
		Target:     target,
		Holder:     holder,
	}); !errors.Is(err, cap.ErrSigMismatch) {
		t.Fatalf("ctx-mismatched verify expected ErrSigMismatch, got %v", err)
	}
}

// TestMLDSA65_Signer_Sign_PacksSignatureAndTag drills into the Signer
// itself: a call to Sign produces a cap.SigSize-byte buffer where the
// leading 3309 bytes are a valid FIPS 204 signature under the signer's
// public key and ctx, and the final byte is the SchemeMLDSA65 tag.
func TestMLDSA65_Signer_Sign_PacksSignatureAndTag(t *testing.T) {
	ctx := []byte("hanzo-iam/cap/v1")
	signer, pubBytes, err := NewMLDSA65Signer(ctx)
	if err != nil {
		t.Fatalf("NewMLDSA65Signer: %v", err)
	}
	payload := []byte("payload-under-test")
	out, err := signer.Sign(payload)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if out[cap.AlgTagOffset] != byte(cap.SchemeMLDSA65) {
		t.Errorf("alg tag = %#x, want %#x", out[cap.AlgTagOffset], byte(cap.SchemeMLDSA65))
	}
	if err := VerifyMLDSA65(pubBytes, payload, ctx, out); err != nil {
		t.Errorf("VerifyMLDSA65 on Signer-produced bytes: %v", err)
	}
	// Flipping the tag byte must invalidate the signature shape (the
	// VerifyMLDSA65 helper refuses on tag mismatch alone).
	bad := out
	bad[cap.AlgTagOffset] = byte(cap.SchemeEd25519)
	if err := VerifyMLDSA65(pubBytes, payload, ctx, bad); err == nil {
		t.Errorf("VerifyMLDSA65 accepted wrong-tag buffer")
	}
}

// TestMLDSA65_LoadFromKMS_Roundtrip mirrors the Ed25519 KMS-loading test:
// a fakeKMS supplies an ML-DSA-65 private-key encoding, LoadMLDSA65FromKMS
// builds a signer, and an Issue/Verify round-trip closes the loop. This
// is the production wiring path Hanzo IAM uses.
func TestMLDSA65_LoadFromKMS_Roundtrip(t *testing.T) {
	// Generate a key offline and feed its marshalled bytes into the
	// fakeKMS so we can exercise LoadMLDSA65FromKMS without a real KMS.
	_, sk, err := mldsa65GenerateForTest()
	if err != nil {
		t.Fatalf("mldsa65 keygen: %v", err)
	}
	kmsBytes, err := sk.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	kms := &fakeKMS{mldsa65SkBytes: kmsBytes}

	ctx := []byte("hanzo-iam/cap/kms-test")
	signer, pubBytes, err := LoadMLDSA65FromKMS(kms, "providers/hanzo/iam/test/cap-mldsa-1", ctx)
	if err != nil {
		t.Fatalf("LoadMLDSA65FromKMS: %v", err)
	}

	registry := NewMemoryRegistry()
	registry.Register(signer.Public(), pubBytes)
	store := NewMemoryStore()
	verifier := &LibVerifier{
		Store:      store,
		Registry:   registry,
		Clock:      SystemClock{},
		MLDSA65Ctx: ctx,
	}

	iss := &Issuer{Signer: signer, Scheme: SchemeMLDSA65, Clock: SystemClock{}}
	var target, holder [32]byte
	target[0] = 1
	holder[0] = 2
	c, err := iss.Issue(IssueParams{
		Kind:        cap.KindIAMSession,
		Target:      target,
		Holder:      holder,
		Permissions: 0x01,
	})
	if err != nil {
		t.Fatalf("PQ Issue (KMS): %v", err)
	}
	if err := verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0x01,
		Target:     target,
		Holder:     holder,
	}); err != nil {
		t.Fatalf("PQ Verify (KMS-loaded signer): %v", err)
	}
}

// ---- KMS bootstrap --------------------------------------------------------

// fakeKMS implements KMSClient with in-memory bytes. Used to exercise the
// LoadEd25519FromKMS / LoadMLDSA65FromKMS paths end-to-end without a real
// KMS dependency.
type fakeKMS struct {
	ed25519Seed   []byte
	mldsa65SkBytes []byte
}

func (f *fakeKMS) FetchEd25519Seed(keyRef string) ([]byte, error) {
	out := make([]byte, len(f.ed25519Seed))
	copy(out, f.ed25519Seed)
	return out, nil
}

func (f *fakeKMS) FetchMLDSA65Private(keyRef string) ([]byte, error) {
	out := make([]byte, len(f.mldsa65SkBytes))
	copy(out, f.mldsa65SkBytes)
	return out, nil
}

// TestLib_LoadEd25519FromKMS_Roundtrip asserts a KMS-supplied seed
// produces a signer that round-trips through Issue and Verify.
func TestLib_LoadEd25519FromKMS_Roundtrip(t *testing.T) {
	// Deterministic seed.
	seed := sha256.Sum256([]byte("test-ed25519-kms-seed"))
	kms := &fakeKMS{ed25519Seed: seed[:]}

	signer, pub, err := LoadEd25519FromKMS(kms, "providers/hanzo/iam/test/cap-signing-1")
	if err != nil {
		t.Fatalf("LoadEd25519FromKMS: %v", err)
	}

	registry := NewMemoryRegistry()
	registry.Register(signer.Public(), pub)
	store := NewMemoryStore()
	verifier := &LibVerifier{Store: store, Registry: registry, Clock: SystemClock{}}

	iss := &Issuer{Signer: signer, Scheme: SchemeEd25519, Clock: SystemClock{}}

	var target, holder [32]byte
	target[0] = 1
	holder[0] = 2

	c, err := iss.Issue(IssueParams{
		Kind:        cap.KindIAMSession,
		Target:      target,
		Holder:      holder,
		Permissions: 0b1,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	if err := verifier.Verify(VerifyParams{
		Leaf:       c,
		RequiredOp: 0b1,
		Target:     target,
		Holder:     holder,
	}); err != nil {
		t.Fatalf("Verify (KMS-loaded signer): %v", err)
	}
}
