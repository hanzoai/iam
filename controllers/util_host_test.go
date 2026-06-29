// Copyright 2026 The Hanzo IAM Authors. All Rights Reserved.
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

package controllers

import "testing"

// TestEffectiveHost: a forged X-Forwarded-Host for a host IAM does not serve is
// ignored in favour of the real connection Host; a served forwarded host is
// honored; with no allowlist (dev) everything is trusted.
func TestEffectiveHost(t *testing.T) {
	served := func(h string) bool { return h == "hanzo.id" || h == "iam.hanzo.ai" }
	cases := []struct{ real, fwd, want string }{
		{"iam.hanzo.ai", "", "iam.hanzo.ai"},                    // no fwd -> real host
		{"iam.hanzo.ai", "hanzo.id", "hanzo.id"},                // served fwd -> trusted
		{"iam.hanzo.ai", "evil.com", "iam.hanzo.ai"},            // foreign fwd -> ignored
		{"iam.hanzo.ai", "hanzo.id , x.com", "hanzo.id"},        // CSV first, served
		{"iam.hanzo.ai", "evil.com , hanzo.id", "iam.hanzo.ai"}, // CSV first not served -> real
	}
	for _, tc := range cases {
		if got := effectiveHost(tc.real, tc.fwd, served); got != tc.want {
			t.Errorf("effectiveHost(%q, %q) = %q, want %q", tc.real, tc.fwd, got, tc.want)
		}
	}
	// No allowlist configured (local dev) -> behavior unchanged: trust the header.
	always := func(string) bool { return true }
	if got := effectiveHost("real-host", "anything.example", always); got != "anything.example" {
		t.Errorf("dev passthrough = %q, want anything.example", got)
	}
}
