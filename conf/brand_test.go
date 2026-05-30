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

package conf

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSuperadminRuleFor_DefaultBrand_FailSafe verifies the fallback
// default contains NO auto-promotion entries. Production deploys MUST
// mount their own brand.json explicitly; a missing/malformed mount
// MUST NOT auto-grant global admin to any domain (was C-4 red team finding).
func TestSuperadminRuleFor_DefaultBrand_FailSafe(t *testing.T) {
	ReloadBrand()
	t.Setenv("IAM_BRAND_FILE", "/nonexistent/brand.json")

	for _, email := range []string{
		"z@hanzo.ai",
		"a@zoo.ngo",
		"b@lux.network",
		"c@pars.network",
	} {
		if _, ok := SuperadminRuleFor(email); ok {
			t.Errorf("FAIL-SAFE BROKEN: %s matched under default (empty) brand", email)
		}
	}
}

// TestSuperadminRuleFor_CustomBrand exercises white-label override: a
// caller mounts /etc/brand/brand.json with their own domain list, and
// the engine respects it (no hanzo-leak).
func TestSuperadminRuleFor_CustomBrand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "brand.json")
	body := `{
	  "name": "Acme",
	  "domain": "acme.example",
	  "superadminDomains": [
	    {"domain": "acme.example", "org": "admin", "globalAdmin": true},
	    {"domain": "vendor.example", "org": "vendor", "globalAdmin": false}
	  ]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ReloadBrand()
	t.Setenv("IAM_BRAND_FILE", path)

	// Custom brand domain → admin org + global admin.
	r1, ok := SuperadminRuleFor("ceo@acme.example")
	if !ok || !r1.GlobalAdmin || r1.Org != AdminOrg {
		t.Fatalf("expected acme.example=global admin, got ok=%v rule=%+v", ok, r1)
	}
	// Vendor → vendor org, NOT global admin.
	r2, ok := SuperadminRuleFor("user@vendor.example")
	if !ok || r2.GlobalAdmin || r2.Org != "vendor" {
		t.Fatalf("expected vendor.example=vendor-org no-global, got ok=%v rule=%+v", ok, r2)
	}
	// hanzo.ai is NOT in the custom brand — should not match.
	if _, ok := SuperadminRuleFor("z@hanzo.ai"); ok {
		t.Fatal("hanzo.ai must NOT match a non-hanzo brand")
	}
}

// TestSuperadminRuleFor_CaseInsensitive covers RFC 5321 §2.4 domain
// case-insensitivity. Tests with a populated custom brand to exercise
// the case-insensitive match path (default is now empty per C-4 fix).
func TestSuperadminRuleFor_CaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "brand.json")
	body := `{
	  "name": "Hanzo",
	  "domain": "hanzo.ai",
	  "superadminDomains": [
	    {"domain": "hanzo.ai", "org": "admin", "globalAdmin": true}
	  ]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ReloadBrand()
	t.Setenv("IAM_BRAND_FILE", path)

	for _, email := range []string{"Z@HANZO.AI", "z@Hanzo.Ai", "z@hanzo.AI"} {
		if _, ok := SuperadminRuleFor(email); !ok {
			t.Errorf("case-insensitive match failed for %q", email)
		}
	}
}

// TestSuperadminRuleFor_Unmatched verifies that unknown domains return
// (zero, false).
func TestSuperadminRuleFor_Unmatched(t *testing.T) {
	ReloadBrand()
	t.Setenv("IAM_BRAND_FILE", "/nonexistent/brand.json")

	for _, email := range []string{
		"",
		"no-at-sign",
		"trailing@",
		"alice@example.com",
		"bob@subdomain.hanzo.ai", // subdomain — exact match only
	} {
		if _, ok := SuperadminRuleFor(email); ok {
			t.Errorf("unexpected match for %q", email)
		}
	}
}
