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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	cidv "github.com/hanzoai/idv/provider"
)

// CheckType enumerates the per-check types in a composite result.
const (
	CheckIDV       = "idv"
	CheckSanctions = "sanctions"
	CheckPEP       = "pep"
)

// CheckStatus enumerates per-check outcomes.
const (
	CheckPassed  = "passed"
	CheckFailed  = "failed"
	CheckPending = "pending"
	CheckError   = "error"
)

// CompositeStatus enumerates the overall verification outcome.
const (
	CompositeApproved = "approved"
	CompositeRejected = "rejected"
	CompositePending  = "pending"
	CompositeError    = "error"
)

// CheckResult is a single sub-check in the composite verification.
type CheckResult struct {
	Type   string `json:"type"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// VerifyResult is the composite outcome of IDV + sanctions + PEP.
type VerifyResult struct {
	VerificationID string        `json:"verification_id"`
	Status         string        `json:"status"`
	Provider       string        `json:"provider"`
	RedirectURL    string        `json:"redirect_url,omitempty"`
	Checks         []CheckResult `json:"checks"`
	CreatedAt      time.Time     `json:"created_at"`
}

// Service orchestrates IDV, sanctions, and PEP checks.
type Service struct {
	mu        sync.RWMutex
	providers map[string]cidv.Provider
	amlURL    string
	amlClient *http.Client
}

// NewService creates an IDV orchestration service.
func NewService(amlURL string) *Service {
	return &Service{
		providers: make(map[string]cidv.Provider),
		amlURL:    amlURL,
		amlClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// RegisterProvider adds a named IDV provider.
func (s *Service) RegisterProvider(name string, p cidv.Provider) {
	s.mu.Lock()
	s.providers[name] = p
	s.mu.Unlock()
}

// GetProvider returns a registered provider by name.
func (s *Service) GetProvider(name string) (cidv.Provider, bool) {
	s.mu.RLock()
	p, ok := s.providers[name]
	s.mu.RUnlock()
	return p, ok
}

// Verify runs the composite verification: IDV + sanctions screen + PEP check.
func (s *Service) Verify(ctx context.Context, userID, org, providerName string, req *cidv.VerificationRequest) (*VerifyResult, error) {
	s.mu.RLock()
	provider, ok := s.providers[providerName]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("IDV provider %q not registered", providerName)
	}

	result := &VerifyResult{
		Provider:  providerName,
		Status:    CompositePending,
		CreatedAt: time.Now().UTC(),
	}

	// 1. Initiate IDV
	idvResp, err := provider.InitiateVerification(ctx, req)
	if err != nil {
		result.Checks = append(result.Checks, CheckResult{
			Type: CheckIDV, Status: CheckError, Detail: err.Error(),
		})
		result.Status = CompositeError
		return result, nil
	}
	result.VerificationID = idvResp.VerificationID
	result.RedirectURL = idvResp.RedirectURL
	result.Checks = append(result.Checks, CheckResult{
		Type: CheckIDV, Status: CheckPending,
	})

	// 2. Sanctions screen (non-blocking; idv may be async via redirect)
	sanctionsStatus, sanctionsDetail := s.screen(ctx, CheckSanctions, req.GivenName+" "+req.FamilyName, req.DateOfBirth)
	result.Checks = append(result.Checks, CheckResult{
		Type: CheckSanctions, Status: sanctionsStatus, Detail: sanctionsDetail,
	})

	// 3. PEP screen
	pepStatus, pepDetail := s.screen(ctx, CheckPEP, req.GivenName+" "+req.FamilyName, req.DateOfBirth)
	result.Checks = append(result.Checks, CheckResult{
		Type: CheckPEP, Status: pepStatus, Detail: pepDetail,
	})

	// Evaluate composite: IDV is async (pending), but sanctions/PEP are sync.
	//
	// A REJECTION IS A STATEMENT ABOUT A PERSON; AN ERROR IS A STATEMENT ABOUT US.
	// Only a substantive adverse finding — the AML list actually returned a hit —
	// rejects. An infrastructure failure (endpoint unconfigured, unreachable,
	// unparseable) is CompositeError: we do not know, and recording "rejected" would
	// attribute a sanctions/PEP match to someone the list never matched. Both are
	// still fail-closed — neither approves — but they are not the same fact and must
	// not share a status.
	//
	// Adverse outranks error: a confirmed hit on one screen is not softened into
	// "unknown" because the other screen was unreachable.
	switch {
	case sanctionsStatus == CheckFailed || pepStatus == CheckFailed:
		result.Status = CompositeRejected
	case sanctionsStatus == CheckError || pepStatus == CheckError:
		result.Status = CompositeError
	}

	return result, nil
}

// HandleWebhook processes a provider webhook and returns the updated status.
func (s *Service) HandleWebhook(providerName string, body []byte, headers map[string]string) (*cidv.WebhookEvent, error) {
	s.mu.RLock()
	provider, ok := s.providers[providerName]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("IDV provider %q not registered", providerName)
	}
	return provider.ParseWebhook(body, headers)
}

// CheckStatus queries a provider for the current status of a verification.
func (s *Service) CheckStatus(ctx context.Context, providerName, verificationID string) (*cidv.VerificationStatusResult, error) {
	s.mu.RLock()
	provider, ok := s.providers[providerName]
	s.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("IDV provider %q not registered", providerName)
	}
	return provider.CheckStatus(ctx, verificationID)
}

// screenLabel is the human name of a screen, used only in the hit detail.
var screenLabel = map[string]string{CheckSanctions: "sanctions", CheckPEP: "PEP"}

// screen runs ONE AML query — sanctions or PEP, distinguished by kind — against the
// shared search endpoint (PEP entries are tagged inside the sanctions lists, so both
// read the same route; PEP adds type=pep).
//
// It returns a CheckResult status, not a bool, because there are THREE outcomes and a
// bool can only carry two. Collapsing them is what let an unset amlURL be recorded as
// a sanctions match:
//
//	CheckPassed — the list was queried and returned nothing.
//	CheckFailed — the list was queried and RETURNED A HIT. A fact about the subject.
//	CheckError  — the list could not be queried at all. A fact about our infrastructure.
//
// Every non-hit failure path is CheckError. The caller keeps all three distinct.
func (s *Service) screen(ctx context.Context, kind, name, dob string) (status, detail string) {
	if s.amlURL == "" {
		return CheckError, "aml_url_not_configured"
	}

	query := map[string]string{"name": name, "dob": dob}
	if kind == CheckPEP {
		query["type"] = "pep"
	}
	payload, _ := json.Marshal(query)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.amlURL+"/v1/aml/sanctions/search", bytes.NewReader(payload))
	if err != nil {
		return CheckError, "request_build_failed"
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.amlClient.Do(req)
	if err != nil {
		// Fail closed on network error — never approve without a real answer.
		return CheckError, "aml_unreachable"
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var hits []json.RawMessage
	if err := json.Unmarshal(body, &hits); err != nil {
		return CheckError, "aml_parse_error"
	}

	if len(hits) > 0 {
		return CheckFailed, fmt.Sprintf("%d %s hits", len(hits), screenLabel[kind])
	}
	return CheckPassed, "clear"
}
