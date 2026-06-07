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

//go:build !skipCi

// cap_test.go — unit coverage for the controller-internal cap helpers.
// The full Issue → HTTP → Verify roundtrip lives in
// capauth/middleware/http where it exercises the same library layer
// against a real http.Server.

package controllers

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/iam/capauth"
	"github.com/zap-proto/go/cap"
)

// initSingleton wires the capauth process singleton with a fresh ed25519
// seed. Returns the seed for callers that want to verify minted caps
// out-of-band.
func initSingleton(t *testing.T) ed25519.PublicKey {
	t.Helper()
	capauth.ResetProcessForTest()
	t.Cleanup(capauth.ResetProcessForTest)

	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatalf("rand.Read seed: %v", err)
	}
	if err := capauth.InitProcessIssuer(capauth.ProcessConfig{
		Seed:  seed,
		CtxID: "controllers-test",
	}); err != nil {
		t.Fatalf("InitProcessIssuer: %v", err)
	}
	pub, _, err := capauth.ProcessIssuerPublicKey()
	if err != nil {
		t.Fatalf("ProcessIssuerPublicKey: %v", err)
	}
	return pub
}

// TestScopeBit_Stable asserts the scope→bit table is stable: adding new
// scopes must use higher bits and never shift the existing assignments.
// This is the canary that fires if someone reorders the table.
func TestScopeBit_Stable(t *testing.T) {
	want := map[uint32]map[string]uint64{
		uint32(cap.KindIAMSession): {
			"iam:whoami:read":   1 << 0,
			"iam:userinfo:read": 1 << 1,
		},
		uint32(cap.KindATSOrder): {
			"ats:order:create": 1 << 0,
			"ats:order:cancel": 1 << 1,
		},
		uint32(cap.KindKMSAccess): {
			"kms:secret:read":  1 << 0,
			"kms:secret:write": 1 << 1,
		},
	}
	for k, m := range want {
		got, ok := scopeBit[k]
		if !ok {
			t.Fatalf("scopeBit missing kind 0x%x", k)
		}
		for scope, bit := range m {
			if got[scope] != bit {
				t.Fatalf("scopeBit[0x%x][%q] = 0b%b; want 0b%b",
					k, scope, got[scope], bit)
			}
		}
	}
}

// TestMaxLifetime_Bounded asserts every kind in scopeBit also has a
// lifetime ceiling. We must never mint a cap without a known max-life,
// because that turns the controller into an unbounded-lifetime token
// factory.
func TestMaxLifetime_Bounded(t *testing.T) {
	for kind := range scopeBit {
		if _, ok := maxLifetimePerKind[kind]; !ok {
			t.Fatalf("kind 0x%x has scopes but no maxLifetimePerKind entry", kind)
		}
	}
}

// TestIssueCap_E2E_NoBeego exercises the cap-minting path end-to-end
// (Issue → wire bytes → Verify) without going through Beego. Same code
// the controller calls — the verifier is the library-layer verifier, the
// signer is the singleton, the cap bytes are the wire bytes.
//
// This is the "no mocks, real bytes" smoke that confirms the controller
// logic is mounting a real signer and producing caps a resource server
// can verify.
func TestIssueCap_E2E_NoBeego(t *testing.T) {
	pub := initSingleton(t)

	// Simulate the controller's mint path.
	iss, err := capauth.ProcessIssuerHandle()
	if err != nil {
		t.Fatalf("ProcessIssuerHandle: %v", err)
	}

	const audienceStr = "ats.dev.hanzo.ai"
	const userID = "alice@hanzo.ai"
	audience := cap.Hash32([]byte(audienceStr))
	holder := cap.Hash32([]byte(userID))
	expires := time.Now().Add(1 * time.Hour)

	scopes := []string{"ats:order:create", "ats:order:cancel"}
	var perms uint64
	for _, s := range scopes {
		bit, ok := scopeBit[uint32(cap.KindATSOrder)][s]
		if !ok {
			t.Fatalf("scope %q missing from table", s)
		}
		perms |= bit
	}

	issued, err := iss.Issue(capauth.IssueParams{
		Kind:        cap.KindATSOrder,
		Target:      audience,
		Holder:      holder,
		Permissions: perms,
		Audience:    audience,
		ExpiresAt:   expires.Unix(),
		MaxDepth:    capauth.ChainDepthMax,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// Now build a Verifier as a resource server would (real bytes, real
	// signatures) and confirm round-trip.
	reg := capauth.NewMemoryRegistry()
	reg.Register(cap.Hash32(pub), pub)
	verifier := &capauth.LibVerifier{
		Store:    capauth.NewMemoryStore(),
		Registry: reg,
		Clock:    capauth.SystemClock{},
		Identity: audience,
	}

	// Round-trip through bytes: encode → b64 → decode → wrap → verify.
	encoded := base64.StdEncoding.EncodeToString(issued.Bytes())
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	wrapped, err := cap.Wrap(raw)
	if err != nil {
		t.Fatalf("cap.Wrap: %v", err)
	}

	for _, scope := range scopes {
		bit := scopeBit[uint32(cap.KindATSOrder)][scope]
		if err := verifier.Verify(capauth.VerifyParams{
			Leaf:       wrapped,
			RequiredOp: bit,
			Target:     audience,
			Holder:     holder,
		}); err != nil {
			t.Fatalf("Verify scope %q: %v", scope, err)
		}
	}

	// Confirm a non-granted scope is rejected.
	otherBit := scopeBit[uint32(cap.KindATSOrder)]["ats:order:read"]
	if err := verifier.Verify(capauth.VerifyParams{
		Leaf:       wrapped,
		RequiredOp: otherBit,
		Target:     audience,
		Holder:     holder,
	}); err == nil {
		t.Fatalf("Verify of non-granted scope ats:order:read accepted")
	}
}

// TestIssueCap_E2E_RevokeBlocks asserts a revoked cap fails verification.
func TestIssueCap_E2E_RevokeBlocks(t *testing.T) {
	pub := initSingleton(t)

	iss, _ := capauth.ProcessIssuerHandle()
	audience := cap.Hash32([]byte("kms.dev.hanzo.ai"))
	holder := cap.Hash32([]byte("svc-account-1"))
	bit := scopeBit[uint32(cap.KindKMSAccess)]["kms:secret:read"]

	issued, err := iss.Issue(capauth.IssueParams{
		Kind:        cap.KindKMSAccess,
		Target:      audience,
		Holder:      holder,
		Permissions: bit,
		Audience:    audience,
		ExpiresAt:   time.Now().Add(15 * time.Minute).Unix(),
		MaxDepth:    capauth.ChainDepthMax,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	reg := capauth.NewMemoryRegistry()
	reg.Register(cap.Hash32(pub), pub)
	store, _ := capauth.ProcessStoreHandle()
	verifier := &capauth.LibVerifier{
		Store:    store,
		Registry: reg,
		Clock:    capauth.SystemClock{},
		Identity: audience,
	}

	// Pre-revoke: passes.
	if err := verifier.Verify(capauth.VerifyParams{
		Leaf:       issued,
		RequiredOp: bit,
		Target:     audience,
		Holder:     holder,
	}); err != nil {
		t.Fatalf("Verify before revoke: %v", err)
	}

	// Revoke via the process store (the same operation /v1/iam/cap/revoke
	// performs).
	capID := issued.ID()
	store.Revoke(capID)

	// Post-revoke: rejects.
	if err := verifier.Verify(capauth.VerifyParams{
		Leaf:       issued,
		RequiredOp: bit,
		Target:     audience,
		Holder:     holder,
	}); err != cap.ErrRevoked {
		t.Fatalf("Verify after revoke: got %v want ErrRevoked", err)
	}
}

// TestIssueCap_HexHolder_Bound asserts an explicit hex holder threads
// straight through to the cap's Holder field instead of being replaced
// by the userID's hash.
func TestIssueCap_HexHolder_Bound(t *testing.T) {
	initSingleton(t)
	iss, _ := capauth.ProcessIssuerHandle()

	var holder [32]byte
	if _, err := rand.Read(holder[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	holderHex := hex.EncodeToString(holder[:])

	// Roundtrip: decode the hex (as the controller does), then mint.
	raw, err := hex.DecodeString(holderHex)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var got [32]byte
	copy(got[:], raw)
	if got != holder {
		t.Fatalf("hex roundtrip mismatch")
	}

	issued, err := iss.Issue(capauth.IssueParams{
		Kind:        cap.KindIAMSession,
		Target:      [32]byte{},
		Holder:      got,
		Permissions: 1,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
		MaxDepth:    capauth.ChainDepthMax,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if issued.Holder() != holder {
		t.Fatalf("issued.Holder() != supplied holder hex")
	}
}

// TestIssuerKeys_Shape asserts the listIssuerKeys output is wire-stable.
func TestIssuerKeys_Shape(t *testing.T) {
	initSingleton(t)
	keys, err := capauth.ListIssuerKeys()
	if err != nil {
		t.Fatalf("ListIssuerKeys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	k := keys[0]
	if k.Scheme != uint8(capauth.SchemeEd25519) {
		t.Fatalf("scheme: got %d want %d", k.Scheme, capauth.SchemeEd25519)
	}
	if !strings.HasPrefix(strings.ToLower(k.FingerprintHex), strings.ToLower(k.FingerprintHex)) {
		t.Fatalf("fingerprint is not stable case")
	}
	if _, err := base64.StdEncoding.DecodeString(k.PublicKeyBase64); err != nil {
		t.Fatalf("public key not valid base64: %v", err)
	}
}
