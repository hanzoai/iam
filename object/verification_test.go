// Copyright 2024 The Hanzo Authors. All Rights Reserved.
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
	"os"
	"testing"
)

func TestGetVerificationCode_UserPinned(t *testing.T) {
	user := &User{VerificationCode: "123456"}
	code := getVerificationCode(user, nil)
	if code != "123456" {
		t.Errorf("expected per-user pinned OTP 123456, got %s", code)
	}
}

func TestGetVerificationCode_NoPinned_Random(t *testing.T) {
	user := &User{VerificationCode: ""}
	code := getVerificationCode(user, nil)
	if len(code) != 6 {
		t.Errorf("expected 6-digit random code, got %q (len %d)", code, len(code))
	}
	for _, c := range code {
		if c < '0' || c > '9' {
			t.Errorf("expected numeric code, got %q", code)
			break
		}
	}
}

func TestGetVerificationCode_NilUser(t *testing.T) {
	code := getVerificationCode(nil, nil)
	if len(code) != 6 {
		t.Errorf("expected 6-digit random code, got %q (len %d)", code, len(code))
	}
}

func TestGetVerificationCode_OrgMasterIgnored(t *testing.T) {
	// Org-level master code must NOT be used — only per-user pinned OTP
	user := &User{VerificationCode: ""}
	org := &Organization{MasterVerificationCode: "999999"}
	code := getVerificationCode(user, org)
	if code == "999999" {
		t.Errorf("org MasterVerificationCode must NOT be used, but got %s", code)
	}
	if len(code) != 6 {
		t.Errorf("expected 6-digit random code, got %q", code)
	}
}

func TestIsDemoPhone(t *testing.T) {
	// isDemoPhone only works when ENV is NOT production
	os.Setenv("ENV", "dev")
	defer os.Unsetenv("ENV")

	tests := []struct {
		phone    string
		expected string
	}{
		{"+19999999999", "999999"},
		{"+11111111111", "111111"},
		{"+15555555555", "555555"},
		{"+12223334444", ""},            // mixed digits
		{"+1234", ""},                   // too short
		{"9999999", "999999"},           // 7 digits, all same
		{"+1 (999) 999-9999", "999999"}, // formatted
	}

	for _, tc := range tests {
		got := isDemoPhone(tc.phone)
		if got != tc.expected {
			t.Errorf("isDemoPhone(%q) = %q, want %q", tc.phone, got, tc.expected)
		}
	}
}

func TestIsDemoPhone_ProductionDisabled(t *testing.T) {
	os.Setenv("ENV", "production")
	defer os.Unsetenv("ENV")

	got := isDemoPhone("+19999999999")
	if got != "" {
		t.Errorf("isDemoPhone should return empty in production, got %q", got)
	}
}
