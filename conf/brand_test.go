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

// TestSuperadminRuleFor_DefaultBrand verifies the fallback defaults
// when no brand.json file is present.
func TestSuperadminRuleFor_DefaultBrand(t *testing.T) {
	ReloadBrand()
	t.Setenv("IAM_BRAND_FILE", "/nonexistent/brand.json")

	rule, ok := SuperadminRuleFor("z@hanzo.ai")
	if !ok {
		t.Fatal("expected match for @hanzo.ai under default brand")
	}
	if !rule.SuperAdmin {
		t.Fatalf("expected SuperAdmin=true, got %+v", rule)
	}
	if rule.Org != AdminOrg {
		t.Fatalf("expected Org=AdminOrg (%s), got %s", AdminOrg, rule.Org)
	}
}

// TestSuperadminRuleFor_ParsNoSuperAdmin checks the pars override:
// it must NOT confer global admin, only org membership in "pars".
func TestSuperadminRuleFor_ParsNoSuperAdmin(t *testing.T) {
	ReloadBrand()
	t.Setenv("IAM_BRAND_FILE", "/nonexistent/brand.json")

	rule, ok := SuperadminRuleFor("carol@pars.network")
	if !ok {
		t.Fatal("expected match for @pars.network")
	}
	if rule.SuperAdmin {
		t.Fatalf("@pars.network must NOT be global admin: %+v", rule)
	}
	if rule.Org != "pars" {
		t.Fatalf("expected Org=pars, got %s", rule.Org)
	}
}

// TestSuperadminRuleFor_CustomBrand exercises white-label override: a
// caller mounts /etc/brand/brand.json with their own domain list, and
// the engine respects it (no hanzo-leak).
func TestSuperadminRuleFor_CustomBrand(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "brand.json")
	body := `{
	  "name": "Liquid",
	  "domain": "liquid.example",
	  "superadminDomains": [
	    {"domain": "liquid.example", "org": "admin", "superAdmin": true},
	    {"domain": "vendor.example", "org": "vendor", "superAdmin": false}
	  ]
	}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ReloadBrand()
	t.Setenv("IAM_BRAND_FILE", path)

	// Custom brand domain → admin org + global admin.
	r1, ok := SuperadminRuleFor("ceo@liquid.example")
	if !ok || !r1.SuperAdmin || r1.Org != AdminOrg {
		t.Fatalf("expected liquid.example=global admin, got ok=%v rule=%+v", ok, r1)
	}
	// Vendor → vendor org, NOT global admin.
	r2, ok := SuperadminRuleFor("user@vendor.example")
	if !ok || r2.SuperAdmin || r2.Org != "vendor" {
		t.Fatalf("expected vendor.example=vendor-org no-global, got ok=%v rule=%+v", ok, r2)
	}
	// hanzo.ai is NOT in the custom brand — should not match.
	if _, ok := SuperadminRuleFor("z@hanzo.ai"); ok {
		t.Fatal("hanzo.ai must NOT match a non-hanzo brand")
	}
}

// TestSuperadminRuleFor_CaseInsensitive covers RFC 5321 §2.4 domain
// case-insensitivity.
func TestSuperadminRuleFor_CaseInsensitive(t *testing.T) {
	ReloadBrand()
	t.Setenv("IAM_BRAND_FILE", "/nonexistent/brand.json")

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
