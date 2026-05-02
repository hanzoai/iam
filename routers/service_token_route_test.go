// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

//go:build !skipCi

package routers

import (
	"os"
	"testing"
)

// TestIsServiceTokenRoute exercises the canonical service-token allowlist.
// These routes accept Authorization: Bearer <unified-service-token> and ONLY
// that — no session, no clientId/clientSecret fallback.
//
// Anything not in the allowlist must return false so the normal
// JWT/session/clientId-secret pipeline applies. New entries to this list are
// security-sensitive — keep the allowlist minimal.
func TestIsServiceTokenRoute(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		// Operator-driven bootstrap surface.
		{"/v1/iam/sync-init-data", true},
		{"/v1/iam/admin/applications/upsert", true},
		{"/v1/iam/admin/users/upsert", true},

		// Anything else must NOT be on the service-token path.
		{"/v1/iam/login", false},
		{"/v1/iam/get-users", false},
		{"/v1/iam/admin/users", false},
		{"/v1/iam/admin/users/delete", false},
		{"/v1/iam/admin", false},
		{"/v1/iam/admin/", false},
		{"/v1/iam/admin/applications", false},
		{"/healthz", false},
		{"", false},
		// Trailing slash variants must NOT match — exact match only.
		{"/v1/iam/admin/users/upsert/", false},
		{"/v1/iam/admin/users/upsert?owner=x", false},
	}
	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			got := isServiceTokenRoute(tc.path)
			if got != tc.want {
				t.Fatalf("isServiceTokenRoute(%q) = %v; want %v", tc.path, got, tc.want)
			}
		})
	}
}

// TestIsValidUnifiedServiceToken_RequiresMatch verifies the constant-time
// token compare against the env-configured unified service token. Empty
// or mismatched inputs must return false; only an exact match returns true.
func TestIsValidUnifiedServiceToken_RequiresMatch(t *testing.T) {
	// Save and clear env for hermetic test, restore on exit.
	saved := map[string]string{}
	for _, k := range []string{"HANZO_API_KEY", "KMS_SERVICE_TOKEN", "IAM_SERVICE_TOKEN"} {
		saved[k] = os.Getenv(k)
		_ = os.Unsetenv(k)
	}
	defer func() {
		for k, v := range saved {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	// No token configured → all inputs invalid.
	if isValidUnifiedServiceToken("") {
		t.Fatal("empty input must be invalid when no token configured")
	}
	if isValidUnifiedServiceToken("anything") {
		t.Fatal("non-empty input must be invalid when no token configured")
	}

	// Configure IAM_SERVICE_TOKEN — input must match exactly.
	_ = os.Setenv("IAM_SERVICE_TOKEN", "secret-abc-123")
	if !isValidUnifiedServiceToken("secret-abc-123") {
		t.Fatal("matching token must be valid")
	}
	if isValidUnifiedServiceToken("secret-abc-124") {
		t.Fatal("near-match token must NOT be valid")
	}
	if isValidUnifiedServiceToken("") {
		t.Fatal("empty input must be invalid even with token configured")
	}

	// Switch to HANZO_API_KEY (highest precedence).
	_ = os.Unsetenv("IAM_SERVICE_TOKEN")
	_ = os.Setenv("HANZO_API_KEY", "hanzo-key-xyz")
	if !isValidUnifiedServiceToken("hanzo-key-xyz") {
		t.Fatal("HANZO_API_KEY must take effect")
	}
	if isValidUnifiedServiceToken("secret-abc-123") {
		t.Fatal("old IAM_SERVICE_TOKEN must no longer match after unset")
	}
}

// TestGetUnifiedServiceToken_PrecedenceOrder verifies that the env-var
// resolution order is HANZO_API_KEY → KMS_SERVICE_TOKEN → IAM_SERVICE_TOKEN.
// First non-empty value wins; later ones do not override.
func TestGetUnifiedServiceToken_PrecedenceOrder(t *testing.T) {
	saved := map[string]string{}
	for _, k := range []string{"HANZO_API_KEY", "KMS_SERVICE_TOKEN", "IAM_SERVICE_TOKEN"} {
		saved[k] = os.Getenv(k)
		_ = os.Unsetenv(k)
	}
	defer func() {
		for k, v := range saved {
			if v == "" {
				_ = os.Unsetenv(k)
			} else {
				_ = os.Setenv(k, v)
			}
		}
	}()

	if got := getUnifiedServiceToken(); got != "" {
		t.Fatalf("expected empty token when no env set, got %q", got)
	}

	_ = os.Setenv("IAM_SERVICE_TOKEN", "iam-token")
	if got := getUnifiedServiceToken(); got != "iam-token" {
		t.Fatalf("expected iam-token, got %q", got)
	}

	_ = os.Setenv("KMS_SERVICE_TOKEN", "kms-token")
	if got := getUnifiedServiceToken(); got != "kms-token" {
		t.Fatalf("KMS_SERVICE_TOKEN must outrank IAM_SERVICE_TOKEN; got %q", got)
	}

	_ = os.Setenv("HANZO_API_KEY", "hanzo-key")
	if got := getUnifiedServiceToken(); got != "hanzo-key" {
		t.Fatalf("HANZO_API_KEY must outrank KMS_SERVICE_TOKEN; got %q", got)
	}
}
