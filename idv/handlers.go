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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"

	stdbytes "bytes"

	cidv "github.com/hanzoai/idv/provider"
)

// VerifyIdentityRequest is the JSON body for POST /v1/idv/verify.
type VerifyIdentityRequest struct {
	UserID      string `json:"user_id"`
	Provider    string `json:"provider"`
	CallbackURL string `json:"callback_url,omitempty"`
	GivenName   string `json:"given_name,omitempty"`
	FamilyName  string `json:"family_name,omitempty"`
	DateOfBirth string `json:"date_of_birth,omitempty"`
	Email       string `json:"email,omitempty"`
	Country     string `json:"country,omitempty"`
	Workflow    string `json:"workflow,omitempty"`
}

// VerifyIdentityResponse is returned from POST /v1/idv/verify.
type VerifyIdentityResponse struct {
	VerificationID string        `json:"verification_id"`
	Status         string        `json:"status"`
	RedirectURL    string        `json:"redirect_url,omitempty"`
	Checks         []CheckResult `json:"checks"`
}

// WebhookNotification is the external event payload the BD receives.
type WebhookNotification struct {
	Event          string `json:"event"`
	UserID         string `json:"user_id"`
	VerificationID string `json:"verification_id"`
	Status         string `json:"status"`
	Provider       string `json:"provider"`
}

// Handler exposes IDV HTTP endpoints. It wraps the Service and provides
// the handler functions that are wired into the Beego router by the
// ApiController methods in controllers/idv_api.go.
type Handler struct {
	Svc           *Service
	WebhookSecret string // HMAC-SHA256 secret for verifying provider callbacks
	BDWebhookURL  string // URL to fire kyc.approved/kyc.rejected to
}

// HandleVerifyIdentity processes POST /v1/idv/verify.
func (h *Handler) HandleVerifyIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req VerifyIdentityRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.UserID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id is required"})
		return
	}
	if req.Provider == "" {
		req.Provider = cidv.ProviderJumio
	}

	orgID := r.Header.Get("X-Org-Id")

	result, err := h.Svc.Verify(r.Context(), req.UserID, orgID, req.Provider, &cidv.VerificationRequest{
		ApplicationID: req.UserID,
		GivenName:     req.GivenName,
		FamilyName:    req.FamilyName,
		DateOfBirth:   req.DateOfBirth,
		Email:         req.Email,
		Country:       req.Country,
		Workflow:      req.Workflow,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, VerifyIdentityResponse{
		VerificationID: result.VerificationID,
		Status:         result.Status,
		RedirectURL:    result.RedirectURL,
		Checks:         result.Checks,
	})
}

// HandleWebhook processes POST /v1/idv/verify/webhook.
// Provider callbacks hit this endpoint; we verify the signature, update
// user KYC status, and fire a downstream webhook to the BD.
func (h *Handler) HandleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "cannot read body"})
		return
	}

	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		providerName = cidv.ProviderJumio
	}

	// Reject webhooks when secret is not configured — never fail open.
	if h.WebhookSecret == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "webhook verification not configured"})
		return
	}
	sig := r.Header.Get("X-Webhook-Signature")
	if sig == "" {
		sig = r.Header.Get("X-SHA2-Signature") // Onfido
	}
	if sig == "" {
		sig = r.Header.Get("Plaid-Verification") // Plaid
	}
	if !verifyHMAC(body, sig, h.WebhookSecret) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid webhook signature"})
		return
	}

	headers := make(map[string]string)
	for k := range r.Header {
		headers[k] = r.Header.Get(k)
	}

	event, err := h.Svc.HandleWebhook(providerName, body, headers)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	// Determine which downstream event to fire.
	var webhookEvent string
	switch event.Status {
	case cidv.StatusApproved:
		webhookEvent = "kyc.approved"
	case cidv.StatusDeclined:
		webhookEvent = "kyc.rejected"
	default:
		// Still pending — acknowledge but don't fire downstream.
		writeJSON(w, http.StatusOK, map[string]string{"status": "acknowledged"})
		return
	}

	// Fire to BD webhook (best-effort, non-blocking in production;
	// here we do it inline for simplicity).
	if h.BDWebhookURL != "" {
		notification := WebhookNotification{
			Event:          webhookEvent,
			UserID:         event.ApplicationID,
			VerificationID: event.VerificationID,
			Status:         string(event.Status),
			Provider:       event.Provider,
		}
		notifBody, _ := json.Marshal(notification)
		go func() {
			req, err := http.NewRequest(http.MethodPost, h.BDWebhookURL, stdbytes.NewReader(notifBody))
			if err != nil {
				log.Printf("idv: failed to build BD webhook request: %v", err)
				return
			}
			req.Header.Set("Content-Type", "application/json")
			if h.WebhookSecret != "" {
				mac := hmac.New(sha256.New, []byte(h.WebhookSecret))
				mac.Write(notifBody)
				req.Header.Set("X-Webhook-Signature", hex.EncodeToString(mac.Sum(nil)))
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				log.Printf("idv: BD webhook delivery failed: %v", err)
				return
			}
			resp.Body.Close()
			if resp.StatusCode >= 400 {
				log.Printf("idv: BD webhook returned status %d", resp.StatusCode)
			}
		}()
	}

	writeJSON(w, http.StatusOK, map[string]string{
		"status":          "processed",
		"event":           webhookEvent,
		"verification_id": event.VerificationID,
	})
}

// HandleGetStatus processes GET /v1/idv/verify/{id}.
func (h *Handler) HandleGetStatus(w http.ResponseWriter, r *http.Request) {
	verificationID := r.PathValue("id")
	if verificationID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "verification id required"})
		return
	}

	providerName := r.URL.Query().Get("provider")
	if providerName == "" {
		providerName = cidv.ProviderJumio
	}

	result, err := h.Svc.CheckStatus(r.Context(), providerName, verificationID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, result)
}

// HandleUploadDocuments processes POST /v1/idv/verify/{id}/documents.
// Accepts multipart form data with supplementary document uploads.
func (h *Handler) HandleUploadDocuments(w http.ResponseWriter, r *http.Request) {
	verificationID := r.PathValue("id")
	if verificationID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "verification id required"})
		return
	}

	if err := r.ParseMultipartForm(32 << 20); err != nil { // 32 MB max
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid multipart form"})
		return
	}

	// Document upload is provider-specific. For now, acknowledge receipt.
	// The compliance service handles document attachment via its own flow.
	writeJSON(w, http.StatusOK, map[string]string{
		"status":          "received",
		"verification_id": verificationID,
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func verifyHMAC(body []byte, signature, secret string) bool {
	if signature == "" || secret == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}
