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

package kms

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// stubPeer mimics a single MPC ZAP peer. It accepts SDK POST/GET for the
// `/v1/orgs/{org}/zk/secrets` routes and keeps a per-instance in-memory
// store of ciphertexts. Lookup by encrypted path is a real MPC-server
// concern; the stub simplifies by keying on the ciphertext bytes and
// returning the single stored blob on GET (matching the SDK's own
// mock-server pattern in hanzoai/kms/sdk/go/client_test.go).
//
// This is strictly a wire-contract test — the stub never decrypts or
// inspects plaintext. It proves that IAM's KMS client can round-trip
// secrets through the SDK's quorum broadcast / quorum GET.
type stubPeer struct {
	mu    sync.Mutex
	store []json.RawMessage // all stored encryptedSecret JSON bodies
}

func newStubPeer() *stubPeer {
	return &stubPeer{}
}

func (p *stubPeer) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/zk/secrets"):
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			var es struct {
				Key   []byte `json:"key"`
				Value []byte `json:"value"`
			}
			if err := json.Unmarshal(body, &es); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			p.mu.Lock()
			p.store = append(p.store, body)
			p.mu.Unlock()
			w.WriteHeader(http.StatusOK)

		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/zk/secrets/"):
			p.mu.Lock()
			var blob json.RawMessage
			if len(p.store) > 0 {
				blob = p.store[len(p.store)-1]
			}
			p.mu.Unlock()
			if blob == nil {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write(blob)

		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
}

func TestLoadConfig_EmptyNodes_ReturnsNil(t *testing.T) {
	t.Setenv("BASE_KMS_NODES", "")
	t.Setenv("BASE_KMS_ORG_SLUG", "ignored")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: unexpected err: %v", err)
	}
	if cfg != nil {
		t.Fatalf("expected nil config when BASE_KMS_NODES is empty, got %+v", cfg)
	}
}

func TestLoadConfig_RequiresOrgSlug(t *testing.T) {
	t.Setenv("BASE_KMS_NODES", "https://n0:9999")
	t.Setenv("BASE_KMS_ORG_SLUG", "")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error when BASE_KMS_ORG_SLUG is missing")
	}
}

func TestLoadConfig_DefaultThreshold(t *testing.T) {
	t.Setenv("BASE_KMS_NODES", "https://n0:9999,https://n1:9999,https://n2:9999")
	t.Setenv("BASE_KMS_ORG_SLUG", "hanzo")
	t.Setenv("BASE_KMS_THRESHOLD", "")
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(cfg.Nodes))
	}
	if cfg.Threshold != 2 {
		t.Fatalf("expected default threshold 2 (of 3), got %d", cfg.Threshold)
	}
	if cfg.OrgSlug != "hanzo" {
		t.Fatalf("expected org hanzo, got %q", cfg.OrgSlug)
	}
}

func TestLoadConfig_ExplicitThresholdOutOfRange(t *testing.T) {
	t.Setenv("BASE_KMS_NODES", "https://n0:9999")
	t.Setenv("BASE_KMS_ORG_SLUG", "x")
	t.Setenv("BASE_KMS_THRESHOLD", "2")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected error when threshold exceeds node count")
	}
}

// TestInitWithConfig_SetGetRoundTrip proves the wire is connected:
// config parsed from env -> sdk.NewClient -> Unlock -> Set -> Get.
// The stub peers never see plaintext; decryption happens client-side.
func TestInitWithConfig_SetGetRoundTrip(t *testing.T) {
	peers := []*stubPeer{newStubPeer(), newStubPeer(), newStubPeer()}
	servers := make([]*httptest.Server, len(peers))
	urls := make([]string, len(peers))
	for i, p := range peers {
		servers[i] = httptest.NewServer(p.handler())
		urls[i] = servers[i].URL
		defer servers[i].Close()
	}

	cfg := Config{
		Nodes:      urls,
		OrgSlug:    "iam-roundtrip-test",
		Threshold:  2,
		Passphrase: "test-passphrase-7f3c",
	}

	client, err := InitWithConfig(cfg)
	if err != nil {
		t.Fatalf("InitWithConfig: %v", err)
	}
	if !client.Ready() {
		t.Fatal("expected client to be ready after Init with passphrase")
	}
	if client.Org() != "iam-roundtrip-test" {
		t.Fatalf("org mismatch: %q", client.Org())
	}

	// Set a secret — the SDK encrypts client-side and broadcasts the
	// ciphertext to all nodes. It needs threshold (2) ACKs.
	if err := client.Set("IAM_DATABASE_URL", "postgres://user:hunter2@host/db"); err != nil {
		t.Fatalf("Set: %v", err)
	}

	// Verify the stored blob at the first peer is NOT plaintext.
	if len(peers[0].store) == 0 {
		t.Fatal("peer 0 received no ciphertext")
	}
	for _, raw := range peers[0].store {
		if strings.Contains(string(raw), "hunter2") {
			t.Fatal("stored blob leaked plaintext password — client-side encryption failed")
		}
	}

	// Round-trip Get through the SDK — decrypts client-side.
	got, err := client.Get("IAM_DATABASE_URL")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got != "postgres://user:hunter2@host/db" {
		t.Fatalf("Get returned wrong value: %q", got)
	}

	// Global() should now return the initialised client.
	if Global() != client {
		t.Fatal("Global() did not return the initialised client")
	}
}

func TestGet_LockedClient_Errors(t *testing.T) {
	srv := httptest.NewServer(newStubPeer().handler())
	defer srv.Close()

	client, err := InitWithConfig(Config{
		Nodes:     []string{srv.URL},
		OrgSlug:   "locked-org",
		Threshold: 1,
		// No passphrase — client stays locked.
	})
	if err != nil {
		t.Fatalf("InitWithConfig: %v", err)
	}
	if client.Ready() {
		t.Fatal("client should be locked without passphrase")
	}
	if _, err := client.Get("anything"); err == nil {
		t.Fatal("expected Get to error on locked client")
	}
}
