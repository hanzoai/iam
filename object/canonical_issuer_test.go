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

// prodFront / prodOrigin mirror the LIVE prod originFrontend / origin CSVs
// (hanzo.id is first in both) — see the iam-conf ConfigMap. The brand-fold
// allowlist is derived from BOTH, so the tests must use the real backend
// (API) hosts (iam.hanzo.ai, id.lux.network, ...) too.
var prodFront = []string{
	"https://hanzo.id", "https://lux.id", "https://zoo.id", "https://zoolabs.id",
	"https://www.zoolabs.id", "https://pars.id", "https://osage.id",
	"https://www.osage.id", "https://id.ad.nexus", "https://id.bootno.de",
}

var prodOrigin = []string{
	"https://hanzo.id", "https://hanzo.ai", "https://lux.id", "https://zoo.id",
	"https://zoolabs.id", "https://www.zoolabs.id", "https://pars.id",
	"https://osage.id", "https://www.osage.id", "https://id.ad.nexus",
	"https://id.bootno.de", "https://id.hanzo.ai", "https://id.lux.network",
	"https://id.zoo.network", "https://id.pars.network", "https://iam.hanzo.ai",
	"https://auth.hanzo.ai", "https://auth.zoo.ngo", "https://auth.pars.ai",
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
		if got := resolveCanonicalIssuer(tc.host, prodFront, prodOrigin, "https://"+originHostname(tc.host)); got != tc.want {
			t.Errorf("resolveCanonicalIssuer(%q) = %q, want %q", tc.host, got, tc.want)
		}
	}
}

// TestResolveCanonicalIssuerUnknownBrand: an UNSERVED host must NEVER yield a
// host-derived (attacker-influenceable) issuer — it falls back to the configured
// primary login origin. With an empty front list there is nothing to fall back
// to, so the host-derived backend is the only (and unavoidable) option.
func TestResolveCanonicalIssuerUnknownBrand(t *testing.T) {
	got := resolveCanonicalIssuer("iam.example.com", prodFront, prodOrigin, "https://iam.example.com")
	if got != "https://hanzo.id" {
		t.Errorf("unknown brand = %q, want safe default https://hanzo.id (never host-derived)", got)
	}
	// Empty front list -> host-derived fallback (no configured default exists).
	if got := resolveCanonicalIssuer("iam.hanzo.ai", nil, nil, "https://iam.hanzo.ai"); got != "https://iam.hanzo.ai" {
		t.Errorf("empty frontList = %q, want fallback", got)
	}
}

// TestResolveCanonicalIssuerHostCollisions locks the defense against host
// look-alikes that share a brand's first label but are NOT served by IAM (the
// brandLabel collision class). None may fold into a real brand issuer; each gets
// the safe configured default. Un-exploitable today only because ingress strips
// X-Forwarded-Host and the gateway pins iss — this makes it robust regardless.
func TestResolveCanonicalIssuerHostCollisions(t *testing.T) {
	const safe = "https://hanzo.id" // frontList[0], the configured primary
	for _, host := range []string{
		"hanzo.evil.com",        // brand label "hanzo", registrable evil.com
		"hanzo.id.attacker.com", // registrable attacker.com (NOT hanzo.id)
		"iam.hanzo.evil",        // strip iam. -> hanzo.evil, registrable hanzo.evil
		"xn--hanzo-7b7c.id",     // punycode homoglyph, registrable xn--hanzo-7b7c.id
		"lux.hanzo.ai",          // cross-brand label on a real (served) hanzo.ai domain
	} {
		got := resolveCanonicalIssuer(host, prodFront, prodOrigin, "https://"+originHostname(host))
		if got != safe {
			t.Errorf("collision host %q folded to %q, want safe default %q", host, got, safe)
		}
	}
}

func TestRegistrableDomain(t *testing.T) {
	cases := map[string]string{
		"iam.hanzo.ai":          "hanzo.ai",
		"hanzo.id":              "hanzo.id",
		"id.lux.network":        "lux.network",
		"https://auth.pars.ai":  "pars.ai",
		"hanzo.id.attacker.com": "attacker.com",
		"localhost":             "localhost",
		"iam.hanzo.ai:443":      "hanzo.ai",
	}
	for host, want := range cases {
		if got := registrableDomain(host); got != want {
			t.Errorf("registrableDomain(%q) = %q, want %q", host, got, want)
		}
	}
}

// TestIsServedHostAllowlist pins the X-Forwarded-Host / host-trust allowlist.
func TestIsServedHostAllowlist(t *testing.T) {
	served := append(append([]string{}, prodFront...), prodOrigin...)
	for _, rd := range []string{"hanzo.ai", "hanzo.id", "lux.network", "zoo.ngo", "pars.ai", "ad.nexus"} {
		if !isServedRegistrable(rd, served) {
			t.Errorf("isServedRegistrable(%q) = false, want true", rd)
		}
	}
	for _, rd := range []string{"evil.com", "attacker.com", "hanzo.evil", ""} {
		if isServedRegistrable(rd, served) {
			t.Errorf("isServedRegistrable(%q) = true, want false", rd)
		}
	}
	// brandServesRegistrable binds a brand label to its configured domains.
	if !brandServesRegistrable("hanzo", "hanzo.ai", served) {
		t.Error("brandServesRegistrable(hanzo, hanzo.ai) = false, want true")
	}
	if brandServesRegistrable("lux", "hanzo.ai", served) {
		t.Error("brandServesRegistrable(lux, hanzo.ai) = true, want false (cross-brand)")
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
