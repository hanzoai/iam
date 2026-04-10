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
	org := &Organization{MasterVerificationCode: "999999"}

	code := getVerificationCode(user, org)
	if code != "123456" {
		t.Errorf("expected per-user code 123456, got %s", code)
	}
}

func TestGetVerificationCode_OrgMaster(t *testing.T) {
	user := &User{VerificationCode: ""}
	org := &Organization{MasterVerificationCode: "999999"}

	code := getVerificationCode(user, org)
	if code != "999999" {
		t.Errorf("expected org master code 999999, got %s", code)
	}
}

func TestGetVerificationCode_NilUser_OrgMaster(t *testing.T) {
	org := &Organization{MasterVerificationCode: "888888"}

	code := getVerificationCode(nil, org)
	if code != "888888" {
		t.Errorf("expected org master code 888888, got %s", code)
	}
}

func TestGetVerificationCode_Random(t *testing.T) {
	user := &User{VerificationCode: ""}
	org := &Organization{MasterVerificationCode: ""}

	code := getVerificationCode(user, org)
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

func TestGetVerificationCode_NilUserNilOrg(t *testing.T) {
	code := getVerificationCode(nil, nil)
	if len(code) != 6 {
		t.Errorf("expected 6-digit random code, got %q (len %d)", code, len(code))
	}
}

func TestGetVerificationCode_UserPinnedOverridesOrg(t *testing.T) {
	user := &User{VerificationCode: "111111"}
	org := &Organization{MasterVerificationCode: "222222"}

	code := getVerificationCode(user, org)
	if code != "111111" {
		t.Errorf("per-user code should override org master: expected 111111, got %s", code)
	}
}

func TestPinnedOTP(t *testing.T) {
	// Per-user pinned OTP: set on User.VerificationCode, returned by getVerificationCode
	user := &User{VerificationCode: "123456"}
	code := getVerificationCode(user, nil)
	if code != "123456" {
		t.Errorf("pinned OTP: expected 123456, got %s", code)
	}
}

func TestPinnedOTP_Empty(t *testing.T) {
	// No pinned OTP: should generate a random code
	user := &User{VerificationCode: ""}
	code := getVerificationCode(user, nil)
	if len(code) != 6 {
		t.Errorf("random OTP should be 6 digits, got %q (len=%d)", code, len(code))
	}
}
