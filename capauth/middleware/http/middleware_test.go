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

// middleware_test.go — end-to-end coverage of the middleware. We mint a
// real cap with a real ed25519 signer, encode it base64, set the
// Authorization header on a real http.Request, and run the middleware
// against a real Verifier. No mocks at the protocol layer.

package http

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/iam/capauth"
	zapcap "github.com/zap-proto/go/cap"
)

// e2eFixture bundles the real cryptographic state every test shares: a
// fresh ed25519 signer is registered as a trusted issuer; the Verifier is
// configured against that registry; an audience hash is fixed; we mint
// the test cap with the rootHolder signer so cap.Attenuate's parent==holder
// invariant holds (not used here but kept consistent with capauth_test.go
// shape).
type e2eFixture struct {
	t           *testing.T
	issSigner   *capauth.Ed25519Signer
	rootHolder  *capauth.Ed25519Signer
	rootHolderH [32]byte
	verifier    *capauth.LibVerifier
	audience    [32]byte
	registry    *capauth.MemoryRegistry
	store       *capauth.MemoryStore
}

func newE2E(t *testing.T) *e2eFixture {
	t.Helper()
	issSigner, _, err := capauth.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer (issuer): %v", err)
	}
	rootHolder, _, err := capauth.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer (rootHolder): %v", err)
	}
	reg := capauth.NewMemoryRegistry()
	reg.Register(issSigner.Public(), issSigner.PublicKey())
	reg.Register(rootHolder.Public(), rootHolder.PublicKey())

	var audience [32]byte
	if _, err := rand.Read(audience[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}

	store := capauth.NewMemoryStore()

	return &e2eFixture{
		t:           t,
		issSigner:   issSigner,
		rootHolder:  rootHolder,
		rootHolderH: rootHolder.Public(),
		audience:    audience,
		registry:    reg,
		store:       store,
		verifier: &capauth.LibVerifier{
			Store:    store,
			Registry: reg,
			Clock:    capauth.SystemClock{},
			Identity: audience,
		},
	}
}

// mint mints a root cap held by rootHolder, scoped to f.audience.
func (f *e2eFixture) mint(perms uint64, expiresIn time.Duration) zapcap.Cap {
	f.t.Helper()
	iss := &capauth.Issuer{
		Signer: f.issSigner,
		Scheme: capauth.SchemeEd25519,
		Clock:  capauth.SystemClock{},
	}
	c, err := iss.Issue(capauth.IssueParams{
		Kind:        zapcap.KindATSOrder,
		Target:      f.audience,
		Holder:      f.rootHolderH,
		Permissions: perms,
		Audience:    f.audience,
		ExpiresAt:   time.Now().Add(expiresIn).Unix(),
		MaxDepth:    capauth.ChainDepthMax,
	})
	if err != nil {
		f.t.Fatalf("Issue: %v", err)
	}
	return c
}

// dummyHandler echoes the verified principal hex on success. The test
// asserts both status and the echoed principal so we know the middleware
// did populate context.
func dummyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ident, ok := FromContext(r.Context())
		if !ok {
			http.Error(w, "no identity in context", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, ident.PrincipalHex)
	})
}

// TestMiddleware_HappyPath mints a cap with the required permission bit,
// sends it through a real httptest.Server, and asserts the handler ran
// and saw the identity.
func TestMiddleware_HappyPath(t *testing.T) {
	f := newE2E(t)

	requiredBit := uint64(1 << 0)
	c := f.mint(requiredBit, 1*time.Hour)

	cfg := Config{
		Verifier:          f.verifier,
		AudienceHash:      f.audience,
		RequiredScopeBits: requiredBit,
	}

	mw := Middleware(cfg)
	srv := httptest.NewServer(mw(dummyHandler()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	req.Header.Set("Authorization", "Cap "+base64.StdEncoding.EncodeToString(c.Bytes()))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d body=%s want 200", resp.StatusCode, string(body))
	}
	body, _ := io.ReadAll(resp.Body)
	if got, want := string(body), capauth.Hex32(f.rootHolderH); got != want {
		t.Fatalf("body: got %q want %q", got, want)
	}
}

// TestMiddleware_NoAuth_401 asserts an unauthenticated request is rejected
// with 401 and a Cap-scheme WWW-Authenticate header.
func TestMiddleware_NoAuth_401(t *testing.T) {
	f := newE2E(t)

	srv := httptest.NewServer(Middleware(Config{
		Verifier:          f.verifier,
		AudienceHash:      f.audience,
		RequiredScopeBits: 1 << 0,
	})(dummyHandler()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/anything")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", resp.StatusCode)
	}
	if w := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(w, "Cap ") {
		t.Fatalf("WWW-Authenticate: got %q want Cap ...", w)
	}
}

// TestMiddleware_BadBase64_401 asserts a malformed Authorization Cap
// header is rejected.
func TestMiddleware_BadBase64_401(t *testing.T) {
	f := newE2E(t)

	srv := httptest.NewServer(Middleware(Config{
		Verifier:          f.verifier,
		AudienceHash:      f.audience,
		RequiredScopeBits: 1 << 0,
	})(dummyHandler()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	req.Header.Set("Authorization", "Cap not-valid-base64!!!")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", resp.StatusCode)
	}
}

// TestMiddleware_InsufficientScope_403 asserts that an authenticated
// request lacking the required permission bit returns 403 (not 401) — the
// caller IS authenticated; they just aren't authorised for this op.
func TestMiddleware_InsufficientScope_403(t *testing.T) {
	f := newE2E(t)

	// Mint a cap with bit 0 only; require bit 1.
	c := f.mint(1<<0, 1*time.Hour)

	srv := httptest.NewServer(Middleware(Config{
		Verifier:          f.verifier,
		AudienceHash:      f.audience,
		RequiredScopeBits: 1 << 1,
	})(dummyHandler()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	req.Header.Set("Authorization", "Cap "+base64.StdEncoding.EncodeToString(c.Bytes()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d want 403", resp.StatusCode)
	}
}

// TestMiddleware_AudienceMismatch_403 mints a cap with one audience and
// configures the middleware with a different audience; expects 403.
func TestMiddleware_AudienceMismatch_403(t *testing.T) {
	f := newE2E(t)
	c := f.mint(1<<0, 1*time.Hour)

	// Configure middleware with a different audience hash.
	var otherAud [32]byte
	if _, err := rand.Read(otherAud[:]); err != nil {
		t.Fatalf("rand: %v", err)
	}
	otherVerifier := &capauth.LibVerifier{
		Store:    f.store,
		Registry: f.registry,
		Clock:    capauth.SystemClock{},
		Identity: otherAud, // mismatched
	}

	srv := httptest.NewServer(Middleware(Config{
		Verifier:          otherVerifier,
		AudienceHash:      otherAud,
		RequiredScopeBits: 1 << 0,
	})(dummyHandler()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	req.Header.Set("Authorization", "Cap "+base64.StdEncoding.EncodeToString(c.Bytes()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status: got %d want 403", resp.StatusCode)
	}
}

// TestMiddleware_Revoked_401 revokes a cap and expects 401.
func TestMiddleware_Revoked_401(t *testing.T) {
	f := newE2E(t)
	c := f.mint(1<<0, 1*time.Hour)

	srv := httptest.NewServer(Middleware(Config{
		Verifier:          f.verifier,
		AudienceHash:      f.audience,
		RequiredScopeBits: 1 << 0,
	})(dummyHandler()))
	defer srv.Close()

	// Pre-revoke: must work.
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	req.Header.Set("Authorization", "Cap "+base64.StdEncoding.EncodeToString(c.Bytes()))
	if resp, err := http.DefaultClient.Do(req); err != nil {
		t.Fatalf("pre-revoke Do: %v", err)
	} else if resp.StatusCode != http.StatusOK {
		t.Fatalf("pre-revoke status: got %d want 200", resp.StatusCode)
	} else {
		resp.Body.Close()
	}

	// Revoke via the same store the verifier looks at.
	f.store.Revoke(c.ID())

	// Post-revoke: 401.
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	req2.Header.Set("Authorization", "Cap "+base64.StdEncoding.EncodeToString(c.Bytes()))
	resp, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("post-revoke Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-revoke status: got %d want 401", resp.StatusCode)
	}
}

// TestMiddleware_Expired_401 mints a cap that's already expired and
// expects 401.
func TestMiddleware_Expired_401(t *testing.T) {
	f := newE2E(t)

	// Mint via Issuer with a back-dated clock so ExpiresAt is in the past.
	pastClock := capauth.FixedClock{T: time.Now().Add(-2 * time.Hour)}
	iss := &capauth.Issuer{
		Signer: f.issSigner,
		Scheme: capauth.SchemeEd25519,
		Clock:  pastClock,
	}
	c, err := iss.Issue(capauth.IssueParams{
		Kind:        zapcap.KindATSOrder,
		Target:      f.audience,
		Holder:      f.rootHolderH,
		Permissions: 1 << 0,
		Audience:    f.audience,
		ExpiresAt:   time.Now().Add(-1 * time.Hour).Unix(), // already expired
		MaxDepth:    capauth.ChainDepthMax,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	srv := httptest.NewServer(Middleware(Config{
		Verifier:          f.verifier,
		AudienceHash:      f.audience,
		RequiredScopeBits: 1 << 0,
	})(dummyHandler()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	req.Header.Set("Authorization", "Cap "+base64.StdEncoding.EncodeToString(c.Bytes()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", resp.StatusCode)
	}
}

// TestMiddleware_LegacyZAPPrefix_Accepted asserts that the legacy
// Authorization: ZAP <b64> prefix still works (zero-churn migration).
func TestMiddleware_LegacyZAPPrefix_Accepted(t *testing.T) {
	f := newE2E(t)
	c := f.mint(1<<0, 1*time.Hour)

	srv := httptest.NewServer(Middleware(Config{
		Verifier:          f.verifier,
		AudienceHash:      f.audience,
		RequiredScopeBits: 1 << 0,
	})(dummyHandler()))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	req.Header.Set("Authorization", "ZAP "+base64.StdEncoding.EncodeToString(c.Bytes()))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d body=%s want 200", resp.StatusCode, string(body))
	}
}

// TestMiddleware_Context_CarriesIdentity asserts both context keys are
// set after a successful verification: the *IdentityCtx via
// IdentityContextKey and the raw cap.Cap via CapContextKey.
func TestMiddleware_Context_CarriesIdentity(t *testing.T) {
	f := newE2E(t)
	c := f.mint(1<<0, 1*time.Hour)

	var sawIdent *capauth.IdentityCtx
	var sawCap zapcap.Cap

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawIdent, _ = FromContext(r.Context())
		sawCap, _ = CapFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	srv := httptest.NewServer(Middleware(Config{
		Verifier:          f.verifier,
		AudienceHash:      f.audience,
		RequiredScopeBits: 1 << 0,
	})(handler))
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/anything", nil)
	req.Header.Set("Authorization", "Cap "+base64.StdEncoding.EncodeToString(c.Bytes()))
	if _, err := http.DefaultClient.Do(req); err != nil {
		t.Fatalf("Do: %v", err)
	}

	if sawIdent == nil {
		t.Fatalf("identity not set on context")
	}
	if sawIdent.PrincipalHex != capauth.Hex32(f.rootHolderH) {
		t.Fatalf("PrincipalHex: got %q want %q",
			sawIdent.PrincipalHex, capauth.Hex32(f.rootHolderH))
	}
	if sawIdent.CapKind != uint32(zapcap.KindATSOrder) {
		t.Fatalf("CapKind: got 0x%x want 0x%x",
			sawIdent.CapKind, uint32(zapcap.KindATSOrder))
	}
	if sawIdent.ScopesBits != (1 << 0) {
		t.Fatalf("ScopesBits: got 0b%b want 0b1", sawIdent.ScopesBits)
	}
	if sawCap.Holder() != f.rootHolderH {
		t.Fatalf("CapContextKey: holder mismatch")
	}
}

// TestMiddleware_NilVerifierPanics asserts construction-time safety.
func TestMiddleware_NilVerifierPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatalf("expected panic on nil Verifier")
		}
	}()
	_ = Middleware(Config{Verifier: nil})
}

// TestMiddleware_DefaultErrorBody_JSON asserts the default error envelope
// is a JSON {"error","error_description"} pair so SDK clients can parse it.
func TestMiddleware_DefaultErrorBody_JSON(t *testing.T) {
	f := newE2E(t)
	srv := httptest.NewServer(Middleware(Config{
		Verifier:          f.verifier,
		AudienceHash:      f.audience,
		RequiredScopeBits: 1 << 0,
	})(dummyHandler()))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/anything")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"error":`) ||
		!strings.Contains(string(body), `"error_description":`) {
		t.Fatalf("body missing error envelope: %s", string(body))
	}
}

// _ unused-suppression for context import — kept live by the actual test
// flow; this is a doc anchor.
var _ = context.Background()
