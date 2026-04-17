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
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Accreditation methods (SEC Rule 501 of Regulation D).
const (
	AccreditationIncome       = "income"        // >$200K/yr individual, >$300K/yr joint
	AccreditationNetWorth     = "net_worth"      // >$1M excluding primary residence
	AccreditationProfessional = "professional"   // Series 7, 65, or 82 license
	AccreditationEntity       = "entity"         // >$5M in assets
)

// AccreditationStatus enumerates accreditation outcomes.
const (
	AccreditationPending  = "pending"
	AccreditationApproved = "approved"
	AccreditationRejected = "rejected"
	AccreditationExpired  = "expired"
)

// AccreditationRequest is the JSON body for POST /v1/idv/accreditation.
type AccreditationRequest struct {
	UserID string `json:"user_id"`
	Method string `json:"method"` // income, net_worth, professional, entity

	// Income method
	AnnualIncome     float64 `json:"annual_income,omitempty"`
	JointIncome      float64 `json:"joint_income,omitempty"`
	IncomeYears      int     `json:"income_years,omitempty"` // consecutive years

	// Net worth method
	NetWorth         float64 `json:"net_worth,omitempty"`

	// Professional method
	LicenseType      string `json:"license_type,omitempty"`  // series_7, series_65, series_82
	LicenseNumber    string `json:"license_number,omitempty"`

	// Entity method
	EntityName       string  `json:"entity_name,omitempty"`
	EntityAssets     float64 `json:"entity_assets,omitempty"`
}

// AccreditationResult is the outcome of accredited investor verification.
type AccreditationResult struct {
	UserID    string    `json:"user_id"`
	Method    string    `json:"method"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	Detail    string    `json:"detail,omitempty"`
}

// VerifyAccreditation evaluates whether a user qualifies as an accredited investor.
func (s *Service) VerifyAccreditation(userID, method string, req *AccreditationRequest) (*AccreditationResult, error) {
	result := &AccreditationResult{
		UserID:    userID,
		Method:    method,
		Status:    AccreditationPending,
		ExpiresAt: time.Now().UTC().AddDate(1, 0, 0), // 1 year from now
	}

	switch method {
	case AccreditationIncome:
		if req.AnnualIncome >= 200000 && req.IncomeYears >= 2 {
			result.Status = AccreditationApproved
			result.Detail = fmt.Sprintf("individual income $%.0f/yr for %d years", req.AnnualIncome, req.IncomeYears)
		} else if req.JointIncome >= 300000 && req.IncomeYears >= 2 {
			result.Status = AccreditationApproved
			result.Detail = fmt.Sprintf("joint income $%.0f/yr for %d years", req.JointIncome, req.IncomeYears)
		} else {
			result.Status = AccreditationRejected
			result.Detail = "income threshold not met"
		}

	case AccreditationNetWorth:
		if req.NetWorth >= 1000000 {
			result.Status = AccreditationApproved
			result.Detail = fmt.Sprintf("net worth $%.0f (excluding primary residence)", req.NetWorth)
		} else {
			result.Status = AccreditationRejected
			result.Detail = "net worth threshold not met"
		}

	case AccreditationProfessional:
		validLicenses := map[string]bool{
			"series_7":  true,
			"series_65": true,
			"series_82": true,
		}
		if validLicenses[req.LicenseType] && req.LicenseNumber != "" {
			result.Status = AccreditationApproved
			result.Detail = fmt.Sprintf("professional license: %s #%s", req.LicenseType, req.LicenseNumber)
		} else {
			result.Status = AccreditationRejected
			result.Detail = "valid professional license required (Series 7, 65, or 82)"
		}

	case AccreditationEntity:
		if req.EntityAssets >= 5000000 {
			result.Status = AccreditationApproved
			result.Detail = fmt.Sprintf("entity %q with $%.0f in assets", req.EntityName, req.EntityAssets)
		} else {
			result.Status = AccreditationRejected
			result.Detail = "entity asset threshold not met ($5M required)"
		}

	default:
		return nil, fmt.Errorf("unknown accreditation method: %q", method)
	}

	return result, nil
}

// HandleVerifyAccreditation processes POST /v1/idv/accreditation.
func (h *Handler) HandleVerifyAccreditation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}

	var req AccreditationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid request body"})
		return
	}
	if req.UserID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "user_id is required"})
		return
	}
	if req.Method == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "method is required"})
		return
	}

	result, err := h.Svc.VerifyAccreditation(req.UserID, req.Method, &req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	writeJSON(w, http.StatusOK, result)
}
