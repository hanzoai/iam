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

//go:build !skipCi

package object

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// The `project` claim carries the caller's org DEFAULT project. The gateway
// mints X-Project-Id from it (empty ⟹ default scope ⟹ header omitted, see
// iamauth.MintedProject), so it must ride in every JWT format when set and be
// OMITTED — not emitted as "" — when the org has no default project. These tests
// pin both halves of that contract, mirroring org_claim_test.go for `owner`.

// projectClaimSurfaces renders the given claims through every JWT token format
// exactly as a client sees them on the wire (getClaimsCustom already returns the
// wire map; the struct formats go through jsonClaims).
func projectClaimSurfaces(t *testing.T, claims Claims) map[string]map[string]interface{} {
	t.Helper()
	return map[string]map[string]interface{}{
		"JWT (default)": jsonClaims(t, getClaimsWithoutThirdIdp(claims)),
		"JWT-Empty":     jsonClaims(t, getShortClaims(claims)),
		"JWT-Standard":  jsonClaims(t, getStandardClaims(claims)),
		"JWT-Custom":    getClaimsCustom(claims, []string{"email"}, nil),
	}
}

// TestJwtFormatsCarryProject asserts every JWT token format serializes the
// `project` claim when the org has a default project.
func TestJwtFormatsCarryProject(t *testing.T) {
	claims := Claims{
		User:             testUser(),
		TokenType:        "access-token",
		Scope:            "openid profile email",
		Project:          "research",
		RegisteredClaims: jwt.RegisteredClaims{Subject: "hanzo/alice"},
	}

	for surface, m := range projectClaimSurfaces(t, claims) {
		got, ok := m["project"]
		if !ok || got != "research" {
			t.Errorf("%s: project claim = %v (present=%v), want %q", surface, got, ok, "research")
		}
	}
}

// TestJwtFormatsOmitEmptyProject asserts the claim is OMITTED (absent, not an
// empty string) when the org has no default project — the gateway's
// absent-⟹-default contract depends on absence, so an empty "project": "" would
// break the minimal-canonical form.
func TestJwtFormatsOmitEmptyProject(t *testing.T) {
	claims := Claims{
		User:             testUser(),
		TokenType:        "access-token",
		Scope:            "openid profile email",
		Project:          "",
		RegisteredClaims: jwt.RegisteredClaims{Subject: "hanzo/alice"},
	}

	for surface, m := range projectClaimSurfaces(t, claims) {
		if got, ok := m["project"]; ok {
			t.Errorf("%s: project claim present = %v, want omitted", surface, got)
		}
	}
}
