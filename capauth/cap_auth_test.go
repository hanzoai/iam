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
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hanzoai/beego/v2/server/web/context"
	"github.com/zap-proto/go/cap"
)

// makeBeegoCtx wraps an http.Request in the Beego context shim Verify
// expects.
func makeBeegoCtx(req *http.Request) *context.Context {
	rec := httptest.NewRecorder()
	ctx := context.NewContext()
	ctx.Reset(rec, req)
	return ctx
}

// makeReq constructs a GET / request with the supplied Authorization header.
// Empty auth means no Authorization header at all.
func makeReq(auth string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/v1/iam/whoami/zap", nil)
	if auth != "" {
		req.Header.Set("Authorization", auth)
	}
	return req
}

// freshTestState wipes the in-memory revocation list and issuer registry, and
// installs a fresh ed25519 signer registered as a trusted issuer. Returns
// the signer + its public key for the test to mint caps against.
func freshTestState(t *testing.T) (*cap.Ed25519Signer, ed25519.PublicKey) {
	t.Helper()
	ClearRevocations()
	ClearIssuers()
	signer, err := cap.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	pub := signer.PublicKey()
	RegisterIssuer(signer.Public(), pub)
	return signer, pub
}

// mintTestCap builds a valid IAMSession cap with the supplied tweaks.
// expiresInSec=0 means "never expires"; positive means now+sec.
func mintTestCap(t *testing.T, signer *cap.Ed25519Signer, kind cap.CapKind,
	holder [32]byte, expiresInSec int64) cap.Cap {
	t.Helper()
	exp := int64(0)
	if expiresInSec != 0 {
		exp = time.Now().Unix() + expiresInSec
	}
	in := cap.Issuance{
		Kind:        uint32(kind),
		Target:      [32]byte{}, // IAM service identity; zero is fine for unit test
		Holder:      holder,
		Permissions: 0xFFFF_FFFF_FFFF_FFFF, // root cap, all perms
		Parent:      [32]byte{},            // root
		ExpiresAt:   exp,
	}
	c, err := cap.Issue(in, signer)
	if err != nil {
		t.Fatalf("cap.Issue: %v", err)
	}
	return c
}

// encodeAuth returns the canonical "ZAP <std-b64>" header value for the cap.
func encodeAuth(c cap.Cap) string {
	return "ZAP " + base64.StdEncoding.EncodeToString(c.Bytes())
}

// randomHolder returns a 32-byte hash to use as the holder field; in
// production this would be Hash32(user_pubkey). Random bytes suffice for
// unit tests that don't reverse-lookup the holder.
func randomHolder(t *testing.T) [32]byte {
	t.Helper()
	var h [32]byte
	if _, err := rand.Read(h[:]); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return h
}

// TestZAP_Verify_Valid issues a cap, calls Verify, and asserts holder/kind
// stashed on the context match what we minted.
func TestZAP_Verify_Valid(t *testing.T) {
	signer, _ := freshTestState(t)
	holder := randomHolder(t)
	c := mintTestCap(t, signer, cap.KindIAMSession, holder, 3600)

	ctx := makeBeegoCtx(makeReq(encodeAuth(c)))
	if err := Verify(ctx, cap.KindIAMSession); err != nil {
		t.Fatalf("Verify on valid cap returned %v", err)
	}

	gotHolder, ok := ctx.Input.GetData(CtxKeyHolderHex).(string)
	if !ok {
		t.Fatalf("CtxKeyHolderHex missing or wrong type on context")
	}
	want := Hex32(holder)
	if gotHolder != want {
		t.Fatalf("holder hex mismatch: got %q want %q", gotHolder, want)
	}

	gotKind, ok := ctx.Input.GetData(CtxKeyKind).(uint32)
	if !ok || gotKind != uint32(cap.KindIAMSession) {
		t.Fatalf("kind mismatch: got %v want %v", gotKind, uint32(cap.KindIAMSession))
	}

	gotCap, ok := ctx.Input.GetData(CtxKeyCap).(cap.Cap)
	if !ok {
		t.Fatalf("CtxKeyCap missing or wrong type on context")
	}
	if gotCap.Holder() != holder {
		t.Fatalf("ctx cap holder mismatch")
	}
}

// TestZAP_Verify_Revoked issues a cap, revokes it, asserts Verify returns
// ErrRevoked.
func TestZAP_Verify_Revoked(t *testing.T) {
	signer, _ := freshTestState(t)
	holder := randomHolder(t)
	c := mintTestCap(t, signer, cap.KindIAMSession, holder, 3600)

	Revoke(c.ID())

	ctx := makeBeegoCtx(makeReq(encodeAuth(c)))
	err := Verify(ctx, cap.KindIAMSession)
	if err != cap.ErrRevoked {
		t.Fatalf("Verify on revoked cap returned %v want %v", err, cap.ErrRevoked)
	}
}

// TestZAP_Verify_Expired issues a cap that expired one second ago and asserts
// Verify returns ErrExpired.
func TestZAP_Verify_Expired(t *testing.T) {
	signer, _ := freshTestState(t)
	holder := randomHolder(t)
	// Mint with explicit past expiry. We can't use mintTestCap's
	// expiresInSec=-1 directly because the package uses now+sec; build the
	// Issuance by hand.
	in := cap.Issuance{
		Kind:      uint32(cap.KindIAMSession),
		Holder:    holder,
		IssuedAt:  time.Now().Unix() - 10,
		ExpiresAt: time.Now().Unix() - 1, // 1 second in the past
	}
	c, err := cap.Issue(in, signer)
	if err != nil {
		t.Fatalf("cap.Issue: %v", err)
	}

	ctx := makeBeegoCtx(makeReq(encodeAuth(c)))
	if err := Verify(ctx, cap.KindIAMSession); err != cap.ErrExpired {
		t.Fatalf("Verify on expired cap returned %v want %v", err, cap.ErrExpired)
	}
}

// TestZAP_Verify_WrongKind mints a KindIAMAPIKey cap and asks the verifier
// to accept KindIAMSession — must return ErrWrongKind.
func TestZAP_Verify_WrongKind(t *testing.T) {
	signer, _ := freshTestState(t)
	holder := randomHolder(t)
	c := mintTestCap(t, signer, cap.KindIAMAPIKey, holder, 3600)

	ctx := makeBeegoCtx(makeReq(encodeAuth(c)))
	if err := Verify(ctx, cap.KindIAMSession); err != ErrWrongKind {
		t.Fatalf("Verify on wrong-kind cap returned %v want %v", err, ErrWrongKind)
	}
}

// TestZAP_Verify_NoHeader is the negative path for absent auth: Verify must
// surface ErrNoZAPHeader so the controller falls back to the Bearer path.
func TestZAP_Verify_NoHeader(t *testing.T) {
	freshTestState(t)
	ctx := makeBeegoCtx(makeReq(""))
	if err := Verify(ctx, cap.KindIAMSession); err != ErrNoZAPHeader {
		t.Fatalf("Verify with no header returned %v want %v", err, ErrNoZAPHeader)
	}
}

// TestZAP_Verify_BearerHeader makes sure a request carrying a Bearer JWT
// (not ZAP) returns ErrNoZAPHeader, not a misfire.
func TestZAP_Verify_BearerHeader(t *testing.T) {
	freshTestState(t)
	ctx := makeBeegoCtx(makeReq("Bearer eyJhbGciOiJ.fake.jwt"))
	if err := Verify(ctx, cap.KindIAMSession); err != ErrNoZAPHeader {
		t.Fatalf("Verify with Bearer header returned %v want %v", err, ErrNoZAPHeader)
	}
}

// TestZAP_Verify_BadBase64 asserts a non-base64 payload returns ErrBadBase64.
func TestZAP_Verify_BadBase64(t *testing.T) {
	freshTestState(t)
	ctx := makeBeegoCtx(makeReq("ZAP not!base64!!!@"))
	if err := Verify(ctx, cap.KindIAMSession); err != ErrBadBase64 {
		t.Fatalf("Verify with bad base64 returned %v want %v", err, ErrBadBase64)
	}
}

// TestZAP_Verify_UnknownIssuer mints a cap with a fresh signer that was
// never registered. Verify must return ErrIssuerUnknown so unknown
// signers can't slip caps through.
func TestZAP_Verify_UnknownIssuer(t *testing.T) {
	freshTestState(t)
	// Note: NOT calling RegisterIssuer for this signer.
	rogue, err := cap.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	holder := randomHolder(t)
	c := mintTestCap(t, rogue, cap.KindIAMSession, holder, 3600)

	ctx := makeBeegoCtx(makeReq(encodeAuth(c)))
	if err := Verify(ctx, cap.KindIAMSession); err != cap.ErrIssuerUnknown {
		t.Fatalf("Verify with unknown issuer returned %v want %v",
			err, cap.ErrIssuerUnknown)
	}
}

// TestZAP_Verify_TamperedSig flips one byte in the signature and asserts
// Verify rejects with ErrSigMismatch. This is the core security property:
// the cap is not a bearer string, the bytes must verify under the issuer
// key.
func TestZAP_Verify_TamperedSig(t *testing.T) {
	signer, _ := freshTestState(t)
	holder := randomHolder(t)
	c := mintTestCap(t, signer, cap.KindIAMSession, holder, 3600)

	tampered := make([]byte, len(c.Bytes()))
	copy(tampered, c.Bytes())
	// Flip a bit inside the active ed25519 signature. The cap's
	// cap.SigSize footer puts the 64-byte ed25519 signature at the
	// leading bytes; the bytes between the signature and the tag byte
	// at cap.AlgTagOffset are zero pad. We target byte (len - SigSize)
	// which is the first byte of the real signature on the wire.
	sigStart := len(tampered) - cap.SigSize
	tampered[sigStart] ^= 0x01

	hdr := "ZAP " + base64.StdEncoding.EncodeToString(tampered)
	ctx := makeBeegoCtx(makeReq(hdr))
	if err := Verify(ctx, cap.KindIAMSession); err != cap.ErrSigMismatch {
		t.Fatalf("Verify with tampered sig returned %v want %v",
			err, cap.ErrSigMismatch)
	}
}

// TestZAP_HasHeader sanity-checks the header-presence helper used by the
// dual-mode /v1/iam/whoami dispatcher.
func TestZAP_HasHeader(t *testing.T) {
	cases := []struct {
		hdr  string
		want bool
	}{
		{"", false},
		{"Bearer x.y.z", false},
		{"ZAP abc", true},
		{"ZAP ", true},          // present but empty payload; Verify will reject downstream
		{"zap lowercase", false}, // case-sensitive; clients must emit "ZAP"
		{"ZAPnotPrefixed", false},
	}
	for _, tc := range cases {
		t.Run(tc.hdr, func(t *testing.T) {
			ctx := makeBeegoCtx(makeReq(tc.hdr))
			if got := HasHeader(ctx); got != tc.want {
				t.Fatalf("HasHeader(%q) = %v want %v", tc.hdr, got, tc.want)
			}
		})
	}
}

// TestZAP_RawStdBase64 asserts the parser accepts both std (padded) and
// raw-std (unpadded) base64 encodings — some HTTP libraries strip '='.
func TestZAP_RawStdBase64(t *testing.T) {
	signer, _ := freshTestState(t)
	holder := randomHolder(t)
	c := mintTestCap(t, signer, cap.KindIAMSession, holder, 3600)

	rawHdr := "ZAP " + base64.RawStdEncoding.EncodeToString(c.Bytes())
	ctx := makeBeegoCtx(makeReq(rawHdr))
	if err := Verify(ctx, cap.KindIAMSession); err != nil {
		t.Fatalf("Verify with raw-std b64 returned %v", err)
	}
}
