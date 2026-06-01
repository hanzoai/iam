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

package util

import "testing"

// TestNormalizeE164 pins the storage contract: every (phone, country)
// pair that ends up persisted on `User.Phone` MUST normalize to the
// same E.164 string regardless of which surface fed it in.
func TestNormalizeE164(t *testing.T) {
	cases := []struct {
		name        string
		phone       string
		countryCode string
		want        string
		wantErr     bool
	}{
		// The order-loss collision: bare national digits + US country
		// code MUST produce the same string the SPA sends as E.164.
		{"us_national_plus_country", "6178888888", "US", "+16178888888", false},
		{"us_e164_passthrough", "+16178888888", "US", "+16178888888", false},
		{"us_e164_no_country", "+16178888888", "", "+16178888888", false},

		// Format variants — libphonenumber strips noise.
		{"us_with_dashes", "617-888-8888", "US", "+16178888888", false},
		{"us_with_parens_space", "(617) 888-8888", "US", "+16178888888", false},
		{"us_with_plus1_no_country", "+1 617 888 8888", "", "+16178888888", false},

		// Empty passthrough — optional field.
		{"empty", "", "", "", false},
		{"empty_with_country", "", "US", "", false},

		// Non-parseable. These MUST fail so AddUser/UpdateUser reject
		// the write. Bare digits with no country code is the classic
		// mobile-FE bug we're guarding against.
		{"national_no_country", "6178888888", "", "", true},
		{"obvious_garbage", "not-a-phone", "US", "", true},
		{"too_short", "123", "US", "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeE164(tc.phone, tc.countryCode)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("NormalizeE164(%q,%q) want error, got nil (result=%q)",
						tc.phone, tc.countryCode, got)
				}
				if got != "" {
					t.Fatalf("NormalizeE164(%q,%q) on error want empty result, got %q",
						tc.phone, tc.countryCode, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeE164(%q,%q) unexpected error: %v",
					tc.phone, tc.countryCode, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeE164(%q,%q) = %q, want %q",
					tc.phone, tc.countryCode, got, tc.want)
			}
		})
	}
}

// TestNormalizeE164Idempotent asserts that re-normalizing an already-
// canonical E.164 string is a stable no-op. The migration relies on
// this — re-running it must not mutate already-migrated rows.
func TestNormalizeE164Idempotent(t *testing.T) {
	inputs := []string{
		"+16178888888",
		"+447911123456",
		"+819012345678",
	}
	for _, in := range inputs {
		once, err := NormalizeE164(in, "")
		if err != nil {
			t.Fatalf("first normalize %q: %v", in, err)
		}
		twice, err := NormalizeE164(once, "")
		if err != nil {
			t.Fatalf("second normalize %q: %v", once, err)
		}
		if once != twice {
			t.Errorf("NormalizeE164 not idempotent for %q: once=%q twice=%q", in, once, twice)
		}
		if once != in {
			t.Errorf("NormalizeE164 mutated already-canonical input %q → %q", in, once)
		}
	}
}

// TestGetE164NumberCompat keeps the legacy two-value variant honest.
func TestGetE164NumberCompat(t *testing.T) {
	got, ok := GetE164Number("6178888888", "US")
	if !ok || got != "+16178888888" {
		t.Errorf("GetE164Number(6178888888, US) = (%q,%v), want (+16178888888,true)", got, ok)
	}

	got, ok = GetE164Number("not-a-phone", "US")
	if ok || got != "" {
		t.Errorf("GetE164Number(garbage) = (%q,%v), want (\"\",false)", got, ok)
	}
}
