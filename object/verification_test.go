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

// TestIsDemoPhone removed: demo-phone fallback (e.g. +19999999999 → 999999)
// was replaced by per-user pinnedOTP in CheckVerificationCode. The old
// isDemoPhone helper no longer exists; these tests referenced a deleted
// symbol and prevented the object package test binary from compiling.
