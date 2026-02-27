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

package object

import (
	"testing"
	"time"
)

func TestWelcomeCreditConstants(t *testing.T) {
	if WelcomeCreditAmount != 0 {
		t.Errorf("WelcomeCreditAmount = %v, want 0 (credit granted by Commerce on payment method add)", WelcomeCreditAmount)
	}
	if WelcomeCreditCurrency != "USD" {
		t.Errorf("WelcomeCreditCurrency = %q, want \"USD\"", WelcomeCreditCurrency)
	}
	if WelcomeCreditTag != "welcome-credit" {
		t.Errorf("WelcomeCreditTag = %q, want \"welcome-credit\"", WelcomeCreditTag)
	}
	if WelcomeCreditDays != 30 {
		t.Errorf("WelcomeCreditDays = %d, want 30", WelcomeCreditDays)
	}
}

func TestWelcomeCreditNilUser(t *testing.T) {
	err := GrantWelcomeCredit(nil, "en")
	if err == nil {
		t.Fatal("expected error for nil user, got nil")
	}
	if err.Error() != "user is nil" {
		t.Errorf("unexpected error message: %s", err.Error())
	}
}

func TestWelcomeCreditZeroAmountReturnsNil(t *testing.T) {
	user := &User{Owner: "test-org", Name: "test-user"}
	err := GrantWelcomeCredit(user, "en")
	if err != nil {
		t.Errorf("expected nil error for zero credit amount, got: %v", err)
	}
}

func TestWelcomeCreditExpiryCalculation(t *testing.T) {
	now := time.Now()
	expires := now.AddDate(0, 0, WelcomeCreditDays)
	diff := expires.Sub(now)

	// 30 days should be between 29 and 31 days (accounting for DST edge cases)
	if diff.Hours() < 29*24 || diff.Hours() > 31*24 {
		t.Errorf("expiry duration %v is not approximately 30 days", diff)
	}
}
