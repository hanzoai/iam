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

// iamclient_test.go — end-to-end coverage of the polling registry client.
// We spin up a real httptest.Server that emits IAM-shaped responses,
// point the client at it, and assert the polling, lookup, and
// failure-isolation behaviour.

package registry

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hanzoai/iam/capauth"
	zapcap "github.com/zap-proto/go/cap"
)

// newFakeIAM returns a minimal httptest.Server that serves the
// /v1/iam/cap/issuer-keys shape against the supplied keys. Each request
// increments the counter and the latest body is the one returned.
func newFakeIAM(t *testing.T, latest *atomic.Pointer[issuerKeysResponse], calls *atomic.Int64) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/iam/cap/issuer-keys", func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body := latest.Load()
		if body == nil {
			http.Error(w, "no keys", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		_ = json.NewEncoder(w).Encode(body)
	})
	return httptest.NewServer(mux)
}

// fakeKey returns an IssuerKeyDescriptor for a freshly-minted ed25519
// signer. Tests use this to drive the fake IAM endpoint.
func fakeKey(t *testing.T) (capauth.IssuerKeyDescriptor, []byte, [32]byte) {
	t.Helper()
	signer, pub, err := capauth.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	hash := signer.Public()
	return capauth.IssuerKeyDescriptor{
		Scheme:          uint8(capauth.SchemeEd25519),
		FingerprintHex:  capauth.Hex32(hash),
		PublicKeyBase64: base64.StdEncoding.EncodeToString(pub),
	}, pub, hash
}

// TestRefresh_Populates asserts the happy path: a fresh client fetches
// the keys and Lookup returns the expected bytes.
func TestRefresh_Populates(t *testing.T) {
	var calls atomic.Int64
	var latest atomic.Pointer[issuerKeysResponse]

	srv := newFakeIAM(t, &latest, &calls)
	defer srv.Close()

	desc, pub, hash := fakeKey(t)
	latest.Store(&issuerKeysResponse{Keys: []capauth.IssuerKeyDescriptor{desc}})

	c, err := New(Config{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("calls: got %d want 1", calls.Load())
	}

	got, err := c.Lookup(hash)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if !bytesEqualConstantTime(got, pub) {
		t.Fatalf("Lookup returned different bytes")
	}
	if c.Size() != 1 {
		t.Fatalf("Size: got %d want 1", c.Size())
	}
}

// TestRefresh_FingerprintMismatch_Refuses asserts the cross-check
// defends against an IAM that lies about its public-key fingerprint.
func TestRefresh_FingerprintMismatch_Refuses(t *testing.T) {
	var calls atomic.Int64
	var latest atomic.Pointer[issuerKeysResponse]

	srv := newFakeIAM(t, &latest, &calls)
	defer srv.Close()

	desc, _, _ := fakeKey(t)
	// Corrupt the fingerprint so Hash32(pub) != advertised hash.
	desc.FingerprintHex = "00000000000000000000000000000000000000000000000000000000000000ff"
	latest.Store(&issuerKeysResponse{Keys: []capauth.IssuerKeyDescriptor{desc}})

	c, _ := New(Config{Endpoint: srv.URL})
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatalf("expected refusal on fingerprint mismatch")
	}
	if c.Size() != 0 {
		t.Fatalf("Size: got %d want 0 (refusal must not mutate table)", c.Size())
	}
}

// TestRefresh_EmptyResponseReturnsErrNoKeys exercises the empty-keys
// guard: existing local table is preserved.
func TestRefresh_EmptyResponseReturnsErrNoKeys(t *testing.T) {
	var calls atomic.Int64
	var latest atomic.Pointer[issuerKeysResponse]

	srv := newFakeIAM(t, &latest, &calls)
	defer srv.Close()

	// Pass 1: populate.
	desc, _, hash := fakeKey(t)
	latest.Store(&issuerKeysResponse{Keys: []capauth.IssuerKeyDescriptor{desc}})

	c, _ := New(Config{Endpoint: srv.URL})
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if c.Size() != 1 {
		t.Fatalf("post-first-refresh size: got %d", c.Size())
	}

	// Pass 2: IAM goes empty. Refresh should ErrNoKeys.
	latest.Store(&issuerKeysResponse{Keys: nil})
	err := c.Refresh(context.Background())
	if !errors.Is(err, ErrNoKeys) {
		t.Fatalf("Refresh: got %v want ErrNoKeys", err)
	}
	// Previous table preserved.
	if _, err := c.Lookup(hash); err != nil {
		t.Fatalf("Lookup after empty refresh: %v want nil (previous table preserved)", err)
	}
}

// TestRefresh_HTTPFailure_PreservesTable asserts that an HTTP error does
// not clear the local map.
func TestRefresh_HTTPFailure_PreservesTable(t *testing.T) {
	var calls atomic.Int64
	var latest atomic.Pointer[issuerKeysResponse]

	srv := newFakeIAM(t, &latest, &calls)

	desc, _, hash := fakeKey(t)
	latest.Store(&issuerKeysResponse{Keys: []capauth.IssuerKeyDescriptor{desc}})

	c, _ := New(Config{Endpoint: srv.URL})
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	// Close the server so subsequent Refresh fails at the transport.
	srv.Close()

	if err := c.Refresh(context.Background()); err == nil {
		t.Fatalf("expected Refresh failure after server closed")
	}
	if _, err := c.Lookup(hash); err != nil {
		t.Fatalf("Lookup after transport failure: %v (table must be preserved)", err)
	}
}

// TestLookup_Unknown asserts the cap.ErrIssuerUnknown sentinel is
// returned, because cap.Verifier dispatches on it.
func TestLookup_Unknown(t *testing.T) {
	c, _ := New(Config{Endpoint: "http://unused"})
	var hash [32]byte
	_, err := c.Lookup(hash)
	if !errors.Is(err, zapcap.ErrIssuerUnknown) {
		t.Fatalf("Lookup: got %v want ErrIssuerUnknown", err)
	}
}

// TestStart_RunsLoop kicks off the polling loop with a tight interval,
// waits for at least 2 additional poll calls (beyond the initial sync
// Refresh), and asserts Stop cleanly exits the loop.
func TestStart_RunsLoop(t *testing.T) {
	var calls atomic.Int64
	var latest atomic.Pointer[issuerKeysResponse]

	srv := newFakeIAM(t, &latest, &calls)
	defer srv.Close()

	desc, _, _ := fakeKey(t)
	latest.Store(&issuerKeysResponse{Keys: []capauth.IssuerKeyDescriptor{desc}})

	c, _ := New(Config{Endpoint: srv.URL, RefreshInterval: 20 * time.Millisecond})
	stop, err := c.Start(context.Background())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer stop()

	// initial Refresh is synchronous, then the loop fires. Wait for
	// at least 3 calls total (initial + 2 polls).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if calls.Load() >= 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if calls.Load() < 3 {
		t.Fatalf("calls after wait: %d want >= 3", calls.Load())
	}
}

// TestStart_RefreshFailureFailsBoot asserts the initial Refresh's failure
// is propagated through Start — boot-time IAM unreachability is a hard
// fail.
func TestStart_RefreshFailureFailsBoot(t *testing.T) {
	c, _ := New(Config{
		Endpoint: "http://127.0.0.1:1", // closed port
		HTTPClient: &http.Client{
			Timeout: 200 * time.Millisecond,
		},
	})
	_, err := c.Start(context.Background())
	if err == nil {
		t.Fatalf("expected Start to fail when IAM unreachable")
	}
}
