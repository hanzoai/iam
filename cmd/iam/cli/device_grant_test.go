// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.

package cli

import (
	"encoding/json"
	"testing"
)

const deviceCodeGrant = "urn:ietf:params:oauth:grant-type:device_code"

// TestBrandGrantTypes_IncludesDeviceCode pins the single source of truth: every
// brand desktop/CLI app must advertise the device grant or CLI login fails the
// IsGrantTypeValid gate.
func TestBrandGrantTypes_IncludesDeviceCode(t *testing.T) {
	if !containsStr(brandGrantTypes, "authorization_code") || !containsStr(brandGrantTypes, "refresh_token") {
		t.Fatalf("brandGrantTypes missing the browser grants: %v", brandGrantTypes)
	}
	if !containsStr(brandGrantTypes, deviceCodeGrant) {
		t.Fatalf("brandGrantTypes must include device_code: %v", brandGrantTypes)
	}
}

// TestBuildApp_IncludesDeviceCode verifies the create path seeds device_code,
// and that buildApp copies the canonical slice (never aliases the shared var).
func TestBuildApp_IncludesDeviceCode(t *testing.T) {
	a := buildApp(brandSpecs[0])
	if !containsStr(a.GrantTypes, deviceCodeGrant) {
		t.Fatalf("buildApp grantTypes must include device_code: %v", a.GrantTypes)
	}
	a.GrantTypes[0] = "mutated"
	if brandGrantTypes[0] == "mutated" {
		t.Fatal("buildApp must copy brandGrantTypes, not alias it")
	}
}

func TestEnsureGrantTypes_EmptyAdds(t *testing.T) {
	a := &app{}
	if added := ensureGrantTypes(a, brandGrantTypes); added != len(brandGrantTypes) {
		t.Fatalf("expected %d added, got %d", len(brandGrantTypes), added)
	}
	if len(a.GrantTypes) != len(brandGrantTypes) {
		t.Fatalf("grantTypes = %v", a.GrantTypes)
	}
}

func TestEnsureGrantTypes_Idempotent(t *testing.T) {
	a := &app{GrantTypes: append([]string(nil), brandGrantTypes...)}
	if added := ensureGrantTypes(a, brandGrantTypes); added != 0 {
		t.Fatalf("idempotency violation: second converge added %d", added)
	}
}

// TestEnsureGrantTypes_PartialPreservesOrder is the real prod state: existing
// apps have [authorization_code, refresh_token]; converge appends device_code
// at the end WITHOUT reordering (authorization_code must stay first for the UI).
func TestEnsureGrantTypes_PartialPreservesOrder(t *testing.T) {
	a := &app{GrantTypes: []string{"authorization_code", "refresh_token"}}
	added := ensureGrantTypes(a, brandGrantTypes)
	if added != 1 {
		t.Fatalf("expected 1 addition (device_code), got %d", added)
	}
	if a.GrantTypes[0] != "authorization_code" || a.GrantTypes[1] != "refresh_token" {
		t.Errorf("existing order not preserved: %v", a.GrantTypes)
	}
	if a.GrantTypes[len(a.GrantTypes)-1] != deviceCodeGrant {
		t.Errorf("device_code must be appended last: %v", a.GrantTypes)
	}
}

func TestFindApp(t *testing.T) {
	apps := []app{{Name: "app-hanzo"}, {Name: "app-zoo"}}
	if findApp(apps, "app-zoo") == nil {
		t.Error("findApp should locate app-zoo")
	}
	if findApp(apps, "app-lux") != nil {
		t.Error("findApp should not report app-lux present")
	}
	if findApp(nil, "app-hanzo") != nil {
		t.Error("findApp on empty list should be nil")
	}
	// Must return a pointer INTO the slice so callers can mutate for write-back.
	p := findApp(apps, "app-hanzo")
	p.GrantTypes = []string{"x"}
	if len(apps[0].GrantTypes) != 1 {
		t.Error("findApp must return a mutable pointer into the slice")
	}
}

// TestApp_UnmarshalJSON_CapturesRaw verifies the typed view decodes AND the
// complete row is captured in raw (including fields with no typed counterpart).
func TestApp_UnmarshalJSON_CapturesRaw(t *testing.T) {
	raw := `{"owner":"admin","name":"app-hanzo","organization":"hanzo",` +
		`"clientId":"hanzo-app-client-id","clientSecret":"s3cr3t",` +
		`"redirectUris":["hanzo://oauth/hanzo"],"tokenFormat":"JWT",` +
		`"grantTypes":["authorization_code","refresh_token"],` +
		`"providers":[{"name":"provider-github"}],"expireInHours":168}`

	var a app
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if a.Name != "app-hanzo" || a.Organization != "hanzo" {
		t.Fatalf("typed view wrong: %+v", a)
	}
	if len(a.GrantTypes) != 2 {
		t.Fatalf("grantTypes = %v", a.GrantTypes)
	}
	if len(a.Providers) != 1 || a.Providers[0].Name != "provider-github" {
		t.Fatalf("providers = %+v", a.Providers)
	}
	for _, k := range []string{"clientId", "clientSecret", "redirectUris", "tokenFormat", "expireInHours"} {
		if _, ok := a.raw[k]; !ok {
			t.Errorf("raw missing %q — a round-trip would drop it", k)
		}
	}
}

// TestUpdateBody_PreservesUnknownFields is THE field-wipe regression guard.
// update-application is an AllCols full-row replace, so the read-modify-write
// must hand back every field. This proves converging grant types preserves
// clientSecret, redirectUris, tokenFormat, etc. verbatim.
func TestUpdateBody_PreservesUnknownFields(t *testing.T) {
	raw := `{"owner":"admin","name":"app-hanzo","organization":"hanzo",` +
		`"clientId":"hanzo-app-client-id","clientSecret":"s3cr3t",` +
		`"redirectUris":["hanzo://oauth/hanzo"],"tokenFormat":"JWT",` +
		`"cert":"cert-hanzo","enablePassword":true,` +
		`"grantTypes":["authorization_code","refresh_token"],` +
		`"providers":[{"name":"provider-github"}]}`

	var a app
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if added := ensureGrantTypes(&a, brandGrantTypes); added != 1 {
		t.Fatalf("expected 1 grant added (device_code), got %d", added)
	}

	body := a.updateBody()

	for _, k := range []string{
		"owner", "name", "organization", "clientId", "clientSecret",
		"redirectUris", "tokenFormat", "cert", "enablePassword", "providers", "grantTypes",
	} {
		if _, ok := body[k]; !ok {
			t.Errorf("updateBody dropped %q — it would be wiped on full-row replace", k)
		}
	}

	var secret string
	if err := json.Unmarshal(body["clientSecret"], &secret); err != nil || secret != "s3cr3t" {
		t.Errorf("clientSecret = %q (err %v), want s3cr3t preserved verbatim", secret, err)
	}

	var grants []string
	if err := json.Unmarshal(body["grantTypes"], &grants); err != nil {
		t.Fatalf("grantTypes decode: %v", err)
	}
	if !containsStr(grants, deviceCodeGrant) {
		t.Errorf("grantTypes %v must include device_code after converge", grants)
	}

	// updateBody must defensively copy raw (mutating its output must not corrupt a.raw).
	delete(body, "clientId")
	if _, ok := a.raw["clientId"]; !ok {
		t.Error("updateBody must not mutate a.raw")
	}
}

// TestChooseConvergeTarget guards SF-1: the brand rename (app-<org> -> <org>-app)
// must converge the LIVE app in place, never create a silent duplicate whose
// device_code grant nothing uses.
func TestChooseConvergeTarget(t *testing.T) {
	b := brandSpec{Org: "hanzo", AppName: "hanzo-app"}

	// canonical present -> converge canonical
	if got := chooseConvergeTarget([]app{{Name: "hanzo-app"}}, b); got == nil || got.Name != "hanzo-app" {
		t.Fatalf("canonical: got %v", got)
	}
	// only legacy present -> converge legacy in place (no duplicate)
	if got := chooseConvergeTarget([]app{{Name: "app-hanzo"}}, b); got == nil || got.Name != "app-hanzo" {
		t.Fatalf("legacy: got %v", got)
	}
	// both present -> canonical wins
	if got := chooseConvergeTarget([]app{{Name: "app-hanzo"}, {Name: "hanzo-app"}}, b); got == nil || got.Name != "hanzo-app" {
		t.Fatalf("both: got %v", got)
	}
	// neither -> nil (caller creates fresh)
	if got := chooseConvergeTarget([]app{{Name: "other"}}, b); got != nil {
		t.Fatalf("neither: got %v", got)
	}
}

// TestMaskedSecret guards the updateApp safety check: a "***" clientSecret must
// be recognized so a masking regression can never be written back over the real
// secret.
func TestMaskedSecret(t *testing.T) {
	if !maskedSecret(json.RawMessage(`"***"`)) {
		t.Error(`"***" must be detected as the mask sentinel`)
	}
	if maskedSecret(json.RawMessage(`"s3cr3t"`)) {
		t.Error("a real secret must not be flagged as masked")
	}
	if maskedSecret(nil) {
		t.Error("absent clientSecret is not the mask sentinel")
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
