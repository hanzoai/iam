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
	"testing"
	"time"
)

func TestAccreditation_Income_Individual(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("user-1", AccreditationIncome, &AccreditationRequest{
		UserID:       "user-1",
		Method:       AccreditationIncome,
		AnnualIncome: 250000,
		IncomeYears:  3,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationApproved {
		t.Fatalf("expected approved, got %q", result.Status)
	}
	if result.ExpiresAt.Before(time.Now().Add(364 * 24 * time.Hour)) {
		t.Fatal("expiry should be ~1 year from now")
	}
}

func TestAccreditation_Income_Joint(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("user-2", AccreditationIncome, &AccreditationRequest{
		UserID:      "user-2",
		Method:      AccreditationIncome,
		JointIncome: 350000,
		IncomeYears: 2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationApproved {
		t.Fatalf("expected approved, got %q", result.Status)
	}
}

func TestAccreditation_Income_Rejected(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("user-3", AccreditationIncome, &AccreditationRequest{
		UserID:       "user-3",
		Method:       AccreditationIncome,
		AnnualIncome: 150000,
		IncomeYears:  2,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationRejected {
		t.Fatalf("expected rejected, got %q", result.Status)
	}
}

func TestAccreditation_Income_InsufficientYears(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("user-4", AccreditationIncome, &AccreditationRequest{
		UserID:       "user-4",
		Method:       AccreditationIncome,
		AnnualIncome: 250000,
		IncomeYears:  1,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationRejected {
		t.Fatalf("expected rejected (insufficient years), got %q", result.Status)
	}
}

func TestAccreditation_NetWorth_Approved(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("user-5", AccreditationNetWorth, &AccreditationRequest{
		UserID:   "user-5",
		Method:   AccreditationNetWorth,
		NetWorth: 2000000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationApproved {
		t.Fatalf("expected approved, got %q", result.Status)
	}
}

func TestAccreditation_NetWorth_Rejected(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("user-6", AccreditationNetWorth, &AccreditationRequest{
		UserID:   "user-6",
		Method:   AccreditationNetWorth,
		NetWorth: 500000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationRejected {
		t.Fatalf("expected rejected, got %q", result.Status)
	}
}

func TestAccreditation_Professional_Series7(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("user-7", AccreditationProfessional, &AccreditationRequest{
		UserID:        "user-7",
		Method:        AccreditationProfessional,
		LicenseType:   "series_7",
		LicenseNumber: "12345",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationApproved {
		t.Fatalf("expected approved, got %q", result.Status)
	}
}

func TestAccreditation_Professional_InvalidLicense(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("user-8", AccreditationProfessional, &AccreditationRequest{
		UserID:        "user-8",
		Method:        AccreditationProfessional,
		LicenseType:   "series_99",
		LicenseNumber: "12345",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationRejected {
		t.Fatalf("expected rejected, got %q", result.Status)
	}
}

func TestAccreditation_Professional_NoNumber(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("user-9", AccreditationProfessional, &AccreditationRequest{
		UserID:      "user-9",
		Method:      AccreditationProfessional,
		LicenseType: "series_65",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationRejected {
		t.Fatalf("expected rejected (no license number), got %q", result.Status)
	}
}

func TestAccreditation_Entity_Approved(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("entity-1", AccreditationEntity, &AccreditationRequest{
		UserID:       "entity-1",
		Method:       AccreditationEntity,
		EntityName:   "Acme Corp",
		EntityAssets: 10000000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationApproved {
		t.Fatalf("expected approved, got %q", result.Status)
	}
}

func TestAccreditation_Entity_Rejected(t *testing.T) {
	svc := NewService("")
	result, err := svc.VerifyAccreditation("entity-2", AccreditationEntity, &AccreditationRequest{
		UserID:       "entity-2",
		Method:       AccreditationEntity,
		EntityName:   "Small LLC",
		EntityAssets: 1000000,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Status != AccreditationRejected {
		t.Fatalf("expected rejected, got %q", result.Status)
	}
}

func TestAccreditation_UnknownMethod(t *testing.T) {
	svc := NewService("")
	_, err := svc.VerifyAccreditation("user-10", "unknown_method", &AccreditationRequest{
		UserID: "user-10",
		Method: "unknown_method",
	})
	if err == nil {
		t.Fatal("expected error for unknown method")
	}
}
