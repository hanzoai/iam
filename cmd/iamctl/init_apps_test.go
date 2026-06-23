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

package main

import "testing"

// TestBrandSpecs_StableAndUnique guards the single source of truth: every
// brand has a complete spec, and orgs + clientIds are unique (a dup would
// silently shadow a brand's login).
func TestBrandSpecs_StableAndUnique(t *testing.T) {
	if len(brandSpecs) < 3 {
		t.Fatalf("expected at least the 3 desktop brands, got %d", len(brandSpecs))
	}
	seenOrg := map[string]bool{}
	seenCID := map[string]bool{}
	for _, b := range brandSpecs {
		if b.Org == "" || b.AppName == "" || b.ClientID == "" || b.RedirectURI == "" {
			t.Fatalf("incomplete brandSpec: %+v", b)
		}
		if seenOrg[b.Org] {
			t.Fatalf("duplicate org: %s", b.Org)
		}
		if seenCID[b.ClientID] {
			t.Fatalf("duplicate clientId: %s", b.ClientID)
		}
		seenOrg[b.Org] = true
		seenCID[b.ClientID] = true
	}
}

// TestBuildApp_CanonicalFields locks the OAuth client shape: stable clientId,
// the native deep-link redirect, password + code signin, and (critically)
// an EMPTY providers slice — wire-providers owns GitHub/Google attachment.
func TestBuildApp_CanonicalFields(t *testing.T) {
	b := brandSpec{
		Org: "hanzo", DisplayName: "Hanzo", AppName: "app-hanzo",
		ClientID: "hanzo-app-client-id", RedirectURI: "hanzo://oauth/hanzo",
		Homepage: "https://hanzo.ai",
	}
	a := buildApp(b)

	if a.ClientId != "hanzo-app-client-id" {
		t.Errorf("clientId = %q, want hanzo-app-client-id", a.ClientId)
	}
	if a.Owner != "admin" || a.Organization != "hanzo" {
		t.Errorf("owner/org = %q/%q, want admin/hanzo", a.Owner, a.Organization)
	}
	if len(a.RedirectUris) != 1 || a.RedirectUris[0] != "hanzo://oauth/hanzo" {
		t.Errorf("redirectUris = %v, want [hanzo://oauth/hanzo]", a.RedirectUris)
	}
	if !a.EnablePassword || !a.EnableCodeSignin {
		t.Errorf("want password + code signin enabled, got pw=%v code=%v", a.EnablePassword, a.EnableCodeSignin)
	}
	if len(a.Providers) != 0 {
		t.Errorf("providers must be empty (wire-providers attaches them), got %d", len(a.Providers))
	}

	wantGrants := map[string]bool{"authorization_code": true, "refresh_token": true}
	for _, g := range a.GrantTypes {
		delete(wantGrants, g)
	}
	if len(wantGrants) != 0 {
		t.Errorf("missing grant types: %v", wantGrants)
	}
}

// TestSigninMethods_IncludeVerificationCode: the verification-code method is
// exactly what makes the email/phone "switch" appear on the login page.
func TestSigninMethods_IncludeVerificationCode(t *testing.T) {
	var hasPassword, hasCode bool
	for _, m := range signinMethodsForBrand() {
		switch m.Name {
		case "Password":
			hasPassword = true
		case "Verification code":
			hasCode = true
		}
	}
	if !hasPassword || !hasCode {
		t.Fatalf("signin methods must include Password + Verification code, got %+v", signinMethodsForBrand())
	}
}

// TestHasApp exercises the idempotency check that prevents duplicate creates.
func TestHasApp(t *testing.T) {
	apps := []app{{Owner: "admin", Name: "app-hanzo", Organization: "hanzo"}}
	if !hasApp(apps, "app-hanzo") {
		t.Error("hasApp should find app-hanzo")
	}
	if hasApp(apps, "app-zoo") {
		t.Error("hasApp should not report app-zoo present")
	}
	if hasApp(nil, "app-hanzo") {
		t.Error("hasApp on empty list should be false")
	}
}

// TestBuildOrg_Minimal verifies the org carries the admin-compatible password
// hashing so seeded brand users authenticate.
func TestBuildOrg_Minimal(t *testing.T) {
	o := buildOrg(brandSpecs[0])
	if o.Owner != "admin" {
		t.Errorf("org owner = %q, want admin", o.Owner)
	}
	if o.PasswordType != "argon2id" {
		t.Errorf("passwordType = %q, want argon2id", o.PasswordType)
	}
	if o.Name != brandSpecs[0].Org {
		t.Errorf("org name = %q, want %q", o.Name, brandSpecs[0].Org)
	}
}
