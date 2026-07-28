// Copyright 2025 The Hanzo Authors. All Rights Reserved.
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

package idv

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	cidv "github.com/hanzoai/idv/provider"
)

func TestServiceVerify_Success(t *testing.T) {
	// Mock IDV provider
	idvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"transactionReference": "txn-test-svc",
			"redirectUrl":          "https://verify.example.com/test",
		})
	}))
	defer idvServer.Close()

	// Mock AML server that returns no hits
	amlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]interface{}{})
	}))
	defer amlServer.Close()

	svc := NewService(amlServer.URL)
	svc.RegisterProvider(cidv.ProviderJumio, cidv.NewJumio(cidv.JumioConfig{
		BaseURL:   idvServer.URL,
		APIToken:  "tok",
		APISecret: "sec",
	}))

	result, err := svc.Verify(context.Background(), "user-1", "org-1", cidv.ProviderJumio, &cidv.VerificationRequest{
		ApplicationID: "user-1",
		GivenName:     "John",
		FamilyName:    "Doe",
		Email:         "john@example.com",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.VerificationID != "txn-test-svc" {
		t.Fatalf("expected txn-test-svc, got %q", result.VerificationID)
	}
	if result.Status != CompositePending {
		t.Fatalf("expected pending (IDV async), got %q", result.Status)
	}
	if len(result.Checks) != 3 {
		t.Fatalf("expected 3 checks, got %d", len(result.Checks))
	}
	// IDV check should be pending
	if result.Checks[0].Type != CheckIDV || result.Checks[0].Status != CheckPending {
		t.Fatalf("expected IDV/pending, got %s/%s", result.Checks[0].Type, result.Checks[0].Status)
	}
	// Sanctions should be passed
	if result.Checks[1].Type != CheckSanctions || result.Checks[1].Status != CheckPassed {
		t.Fatalf("expected sanctions/passed, got %s/%s", result.Checks[1].Type, result.Checks[1].Status)
	}
	// PEP should be passed
	if result.Checks[2].Type != CheckPEP || result.Checks[2].Status != CheckPassed {
		t.Fatalf("expected pep/passed, got %s/%s", result.Checks[2].Type, result.Checks[2].Status)
	}
}

func TestServiceVerify_SanctionsHit(t *testing.T) {
	idvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"transactionReference": "txn-sanc",
			"redirectUrl":          "https://verify.example.com/test",
		})
	}))
	defer idvServer.Close()

	// AML server returns a sanctions hit
	amlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]map[string]string{
			{"name": "John Doe", "score": "0.95"},
		})
	}))
	defer amlServer.Close()

	svc := NewService(amlServer.URL)
	svc.RegisterProvider(cidv.ProviderJumio, cidv.NewJumio(cidv.JumioConfig{
		BaseURL:   idvServer.URL,
		APIToken:  "tok",
		APISecret: "sec",
	}))

	result, err := svc.Verify(context.Background(), "user-2", "org-1", cidv.ProviderJumio, &cidv.VerificationRequest{
		ApplicationID: "user-2",
		GivenName:     "John",
		FamilyName:    "Doe",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != CompositeRejected {
		t.Fatalf("expected rejected (sanctions hit), got %q", result.Status)
	}
	if result.Checks[1].Status != CheckFailed {
		t.Fatalf("expected sanctions/failed, got %s", result.Checks[1].Status)
	}
}

func TestServiceVerify_UnknownProvider(t *testing.T) {
	svc := NewService("")
	_, err := svc.Verify(context.Background(), "user-1", "org-1", "nonexistent", &cidv.VerificationRequest{})
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestServiceVerify_NoAMLURL(t *testing.T) {
	idvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"transactionReference": "txn-no-aml",
			"redirectUrl":          "https://verify.example.com/test",
		})
	}))
	defer idvServer.Close()

	// No AML URL — the screens cannot run. Fail-closed means we do NOT approve; it does
	// NOT mean we reject. A rejection asserts the AML lists matched this person, and
	// they were never queried. This test previously asserted CompositeRejected, which
	// encoded exactly that conflation.
	svc := NewService("")
	svc.RegisterProvider(cidv.ProviderJumio, cidv.NewJumio(cidv.JumioConfig{
		BaseURL:   idvServer.URL,
		APIToken:  "tok",
		APISecret: "sec",
	}))

	result, err := svc.Verify(context.Background(), "user-1", "org-1", cidv.ProviderJumio, &cidv.VerificationRequest{
		ApplicationID: "user-1",
		GivenName:     "Test",
		FamilyName:    "User",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != CompositeError {
		t.Fatalf("expected error (AML unconfigured is our failure, not an adverse finding), got %q", result.Status)
	}
	if result.Status == CompositeApproved {
		t.Fatal("must never approve without a real AML answer")
	}
	if result.Checks[1].Status != CheckError {
		t.Fatalf("expected sanctions/error, got %s", result.Checks[1].Status)
	}
	if result.Checks[1].Detail != "aml_url_not_configured" {
		t.Fatalf("expected aml_url_not_configured, got %q", result.Checks[1].Detail)
	}
	if result.Checks[2].Status != CheckError {
		t.Fatalf("expected pep/error, got %s", result.Checks[2].Status)
	}
}

// TestServiceVerify_AMLUnreachableIsErrorNotRejection: a dead AML endpoint is an
// infrastructure fact, not a fact about the subject — same rule as an unset URL.
func TestServiceVerify_AMLUnreachableIsErrorNotRejection(t *testing.T) {
	idvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"transactionReference": "txn-dead-aml",
			"redirectUrl":          "https://verify.example.com/test",
		})
	}))
	defer idvServer.Close()

	// Start then immediately stop the AML server so the address refuses connections.
	deadAML := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	deadURL := deadAML.URL
	deadAML.Close()

	svc := NewService(deadURL)
	svc.RegisterProvider(cidv.ProviderJumio, cidv.NewJumio(cidv.JumioConfig{
		BaseURL: idvServer.URL, APIToken: "tok", APISecret: "sec",
	}))

	result, err := svc.Verify(context.Background(), "user-3", "org-1", cidv.ProviderJumio, &cidv.VerificationRequest{
		ApplicationID: "user-3", GivenName: "Test", FamilyName: "User",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != CompositeError {
		t.Fatalf("expected error for unreachable AML, got %q", result.Status)
	}
	if result.Checks[1].Detail != "aml_unreachable" {
		t.Fatalf("expected aml_unreachable, got %q", result.Checks[1].Detail)
	}
}

// TestServiceVerify_AdverseOutranksError: a REAL hit must still reject even when the
// other screen could not run. A confirmed adverse finding is not softened to "unknown"
// because our infrastructure was partly down.
func TestServiceVerify_AdverseOutranksError(t *testing.T) {
	idvServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"transactionReference": "txn-mixed",
			"redirectUrl":          "https://verify.example.com/test",
		})
	}))
	defer idvServer.Close()

	// Sanctions (no type=pep) returns a hit; the PEP query returns unparseable body.
	amlServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		if bytes.Contains(body, []byte(`"type":"pep"`)) {
			w.Write([]byte("not json"))
			return
		}
		json.NewEncoder(w).Encode([]map[string]string{{"name": "John Doe", "score": "0.99"}})
	}))
	defer amlServer.Close()

	svc := NewService(amlServer.URL)
	svc.RegisterProvider(cidv.ProviderJumio, cidv.NewJumio(cidv.JumioConfig{
		BaseURL: idvServer.URL, APIToken: "tok", APISecret: "sec",
	}))

	result, err := svc.Verify(context.Background(), "user-4", "org-1", cidv.ProviderJumio, &cidv.VerificationRequest{
		ApplicationID: "user-4", GivenName: "John", FamilyName: "Doe",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Checks[1].Status != CheckFailed {
		t.Fatalf("expected sanctions/failed (real hit), got %s", result.Checks[1].Status)
	}
	if result.Checks[2].Status != CheckError {
		t.Fatalf("expected pep/error (unparseable), got %s", result.Checks[2].Status)
	}
	if result.Status != CompositeRejected {
		t.Fatalf("a confirmed sanctions hit must reject even when PEP errored, got %q", result.Status)
	}
}

func TestServiceRegisterProvider(t *testing.T) {
	svc := NewService("")
	p := cidv.NewJumio(cidv.JumioConfig{BaseURL: "https://example.com"})
	svc.RegisterProvider("test-provider", p)

	got, ok := svc.GetProvider("test-provider")
	if !ok {
		t.Fatal("expected provider to be registered")
	}
	if got.Name() != "jumio" {
		t.Fatalf("expected jumio, got %q", got.Name())
	}

	_, ok = svc.GetProvider("nonexistent")
	if ok {
		t.Fatal("expected false for unregistered provider")
	}
}

func TestServiceCheckStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"status":             "DONE",
			"verificationStatus": "APPROVED_VERIFIED",
		})
	}))
	defer server.Close()

	svc := NewService("")
	svc.RegisterProvider(cidv.ProviderJumio, cidv.NewJumio(cidv.JumioConfig{BaseURL: server.URL}))

	result, err := svc.CheckStatus(context.Background(), cidv.ProviderJumio, "txn-001")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != cidv.StatusApproved {
		t.Fatalf("expected approved, got %q", result.Status)
	}
}

func TestServiceHandleWebhook(t *testing.T) {
	secret := "test-webhook-secret"
	svc := NewService("")
	svc.RegisterProvider(cidv.ProviderJumio, cidv.NewJumio(cidv.JumioConfig{APISecret: secret}))

	payload := []byte(`{
		"transactionReference": "txn-wh-001",
		"customerInternalReference": "user-1",
		"status": "DONE",
		"verificationStatus": "APPROVED_VERIFIED"
	}`)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	sig := hex.EncodeToString(mac.Sum(nil))

	event, err := svc.HandleWebhook(cidv.ProviderJumio, payload, map[string]string{"Callback-Sig": sig})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if event.Status != cidv.StatusApproved {
		t.Fatalf("expected approved, got %q", event.Status)
	}
	if event.VerificationID != "txn-wh-001" {
		t.Fatalf("expected txn-wh-001, got %q", event.VerificationID)
	}
}

func TestServiceHandleWebhook_UnknownProvider(t *testing.T) {
	svc := NewService("")
	_, err := svc.HandleWebhook("nonexistent", []byte(`{}`), nil)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
}

func TestVerifyHMAC(t *testing.T) {
	body := []byte("test payload")
	secret := "test-secret"

	// Compute expected HMAC
	if verifyHMAC(body, "", secret) {
		t.Fatal("empty signature should fail")
	}
	if verifyHMAC(body, "invalid", secret) {
		t.Fatal("invalid signature should fail")
	}
	if verifyHMAC(body, "", "") {
		t.Fatal("empty signature and secret should fail")
	}
}
