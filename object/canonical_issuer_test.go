// Copyright 2024 The Hanzo IAM Authors. All Rights Reserved.
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

import "testing"

// prodFront mirrors the prod originFrontend CSV (hanzo.id is first).
var prodFront = []string{
	"https://hanzo.id", "https://lux.id", "https://zoo.id", "https://zoolabs.id",
	"https://pars.id", "https://osage.id", "https://id.ad.nexus", "https://id.bootno.de",
}

// TestResolveCanonicalIssuer asserts every host of a brand maps to that brand's
// ONE login origin — the drift fix (iam.hanzo.ai -> https://hanzo.id) — while
// other brands keep their own issuer (no cross-brand leak).
func TestResolveCanonicalIssuer(t *testing.T) {
	cases := []struct {
		host string
		want string
	}{
		// hanzo brand — the drift fix: API/login hosts all fold to hanzo.id.
		{"iam.hanzo.ai", "https://hanzo.id"},
		{"hanzo.id", "https://hanzo.id"},
		{"hanzo.ai", "https://hanzo.id"},
		{"id.hanzo.ai", "https://hanzo.id"},
		{"auth.hanzo.ai", "https://hanzo.id"},
		{"iam.hanzo.ai:443", "https://hanzo.id"},
		// white-label preserved — never collapses to hanzo.
		{"lux.id", "https://lux.id"},
		{"id.lux.network", "https://lux.id"},
		{"zoo.id", "https://zoo.id"},
		{"id.zoo.network", "https://zoo.id"},
		{"pars.id", "https://pars.id"},
		{"id.ad.nexus", "https://id.ad.nexus"},
	}
	for _, tc := range cases {
		if got := resolveCanonicalIssuer(tc.host, prodFront, "https://"+originHostname(tc.host)); got != tc.want {
			t.Errorf("resolveCanonicalIssuer(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

// TestResolveCanonicalIssuerUnknownBrand: an unconfigured brand falls back to the
// host-derived backend origin (no incorrect fold into hanzo).
func TestResolveCanonicalIssuerUnknownBrand(t *testing.T) {
	got := resolveCanonicalIssuer("iam.example.com", prodFront, "https://iam.example.com")
	if got != "https://iam.example.com" {
		t.Errorf("unknown brand = %q, want host-derived https://iam.example.com", got)
	}
	// Empty front list -> always host-derived fallback.
	if got := resolveCanonicalIssuer("iam.hanzo.ai", nil, "https://iam.hanzo.ai"); got != "https://iam.hanzo.ai" {
		t.Errorf("empty frontList = %q, want fallback", got)
	}
}

// TestBrandLabel pins the brand-label reduction that groups a brand's hosts.
func TestBrandLabel(t *testing.T) {
	cases := map[string]string{
		"iam.hanzo.ai":     "hanzo",
		"hanzo.id":         "hanzo",
		"hanzo.ai":         "hanzo",
		"id.hanzo.ai":      "hanzo",
		"https://hanzo.id": "hanzo",
		"id.lux.network":   "lux",
		"lux.id":           "lux",
		"id.zoo.network":   "zoo",
		"auth.pars.ai":     "pars",
		"iam.hanzo.ai:443": "hanzo",
	}
	for host, want := range cases {
		if got := brandLabel(host); got != want {
			t.Errorf("brandLabel(%q) = %q, want %q", host, got, want)
		}
	}
}
