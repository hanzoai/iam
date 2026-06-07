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

// integration_test.go — IAM → polling registry → middleware end-to-end.
//
// We stand up TWO real HTTP servers:
//   1. A fake IAM that emits /v1/iam/cap/issuer-keys against a real signer
//      that we also use to mint the test cap.
//   2. A resource server that wraps dummyHandler with the cap middleware,
//      configured to refresh its IssuerRegistry from server (1).
//
// We mint a real cap with the signer at (1), wait for the resource server
// to refresh its registry, and assert the cap rounds-trips through (2).
//
// This is the "no mocks at the protocol layer" smoke. Every byte that
// flows is the same wire format production runs.

package http

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/hanzoai/iam/capauth"
	"github.com/hanzoai/iam/capauth/registry"
	zapcap "github.com/zap-proto/go/cap"
)

// TestIntegration_IAM_to_Middleware_RoundTrip is the full pipeline test.
func TestIntegration_IAM_to_Middleware_RoundTrip(t *testing.T) {
	// --- 1. Set up the issuer signer + audience. -------------------------
	issSigner, issPub, err := capauth.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer (issuer): %v", err)
	}
	holderSigner, _, err := capauth.NewEd25519Signer()
	if err != nil {
		t.Fatalf("NewEd25519Signer (holder): %v", err)
	}

	audience := zapcap.Hash32([]byte("ats.dev.hanzo.ai"))

	// --- 2. Stand up the fake IAM /v1/iam/cap/issuer-keys endpoint. ------
	iamMux := http.NewServeMux()
	iamMux.HandleFunc("/v1/iam/cap/issuer-keys", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		body := map[string]any{
			"keys": []capauth.IssuerKeyDescriptor{
				{
					Scheme:          uint8(capauth.SchemeEd25519),
					FingerprintHex:  capauth.Hex32(issSigner.Public()),
					PublicKeyBase64: base64.StdEncoding.EncodeToString(issPub),
				},
			},
			"cache_control_sec": 300,
		}
		_ = json.NewEncoder(w).Encode(body)
	})
	iamSrv := httptest.NewServer(iamMux)
	defer iamSrv.Close()

	// --- 3. Build the resource-server-side polling registry. -------------
	regClient, err := registry.New(registry.Config{
		Endpoint:        iamSrv.URL,
		RefreshInterval: 50 * time.Millisecond, // doesn't matter for one-shot
	})
	if err != nil {
		t.Fatalf("registry.New: %v", err)
	}
	if err := regClient.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if regClient.Size() != 1 {
		t.Fatalf("registry size after refresh: %d want 1", regClient.Size())
	}

	// --- 4. Compose the resource-server Verifier + middleware. -----------
	verifier := &capauth.LibVerifier{
		Store:    capauth.NewMemoryStore(),
		Registry: regClient,
		Clock:    capauth.SystemClock{},
		Identity: audience,
	}
	const requiredBit = uint64(1 << 0)

	resMux := http.NewServeMux()
	resMux.HandleFunc("/v1/ats/order/create", func(w http.ResponseWriter, r *http.Request) {
		ident, ok := FromContext(r.Context())
		if !ok {
			http.Error(w, "no identity", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, ident.PrincipalHex)
	})
	cfg := Config{
		Verifier:          verifier,
		AudienceHash:      audience,
		RequiredScopeBits: requiredBit,
	}
	resSrv := httptest.NewServer(Middleware(cfg)(resMux))
	defer resSrv.Close()

	// --- 5. Mint a real cap with the issuer signer at IAM. ---------------
	iss := &capauth.Issuer{
		Signer: issSigner,
		Scheme: capauth.SchemeEd25519,
		Clock:  capauth.SystemClock{},
	}
	c, err := iss.Issue(capauth.IssueParams{
		Kind:        zapcap.KindATSOrder,
		Target:      audience,
		Holder:      holderSigner.Public(),
		Permissions: requiredBit,
		Audience:    audience,
		ExpiresAt:   time.Now().Add(1 * time.Hour).Unix(),
		MaxDepth:    capauth.ChainDepthMax,
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	// --- 6. Round-trip through the wire. ---------------------------------
	req, _ := http.NewRequest(http.MethodGet, resSrv.URL+"/v1/ats/order/create", nil)
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
	if got, want := string(body), capauth.Hex32(holderSigner.Public()); got != want {
		t.Fatalf("body: got %q want %q", got, want)
	}
}
