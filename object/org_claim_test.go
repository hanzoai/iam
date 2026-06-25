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
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

// The org (tenant) claim is the keystone of multi-tenant isolation: the gateway
// derives X-Org-Id from the JWT `owner` claim (2026-03-27 header convention) and
// migrated OIDC clients read `owner`/`organization` to scope tenancy. If the
// claim is missing, every consumer silently falls back to a "default" org and
// tenant isolation breaks. These tests pin the claim into BOTH the OIDC userinfo
// response and every JWT token format.

// jsonClaims marshals a value the way the JWT/userinfo serializer does, then
// re-parses it as a generic map — i.e. exactly what a client sees on the wire.
func jsonClaims(t *testing.T, v interface{}) map[string]interface{} {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return m
}

func assertOrg(t *testing.T, surface string, m map[string]interface{}, wantOrg string) {
	t.Helper()
	if got, ok := m["owner"]; !ok || got != wantOrg {
		t.Errorf("%s: owner claim = %v (present=%v), want %q", surface, got, ok, wantOrg)
	}
	if got, ok := m["organization"]; !ok || got != wantOrg {
		t.Errorf("%s: organization claim = %v (present=%v), want %q", surface, got, ok, wantOrg)
	}
}

func testUser() *User {
	return &User{
		Owner:       "hanzo",
		Name:        "alice",
		Id:          "hanzo/alice",
		DisplayName: "Alice",
		Email:       "alice@hanzo.ai",
		Groups:      []string{"hanzo/eng"},
	}
}

// TestUserinfoCarriesOrg asserts the OIDC userinfo response includes the org
// claim regardless of requested scopes (it must not depend on "profile").
func TestUserinfoCarriesOrg(t *testing.T) {
	user := testUser()
	// "email" scope only — deliberately excludes "profile" so we never touch
	// the DB via ExtendUserWithRolesAndPermissions; owner must still be present.
	info, err := GetUserInfo(user, "openid email", "client-app", "iam.hanzo.ai")
	if err != nil {
		t.Fatalf("GetUserInfo: %v", err)
	}
	m := jsonClaims(t, info)
	assertOrg(t, "userinfo", m, "hanzo")
}

// TestJwtFormatsCarryOrg asserts every JWT token format serializes the org
// claim. JWT/JWT-Empty/JWT-Standard carry it via the embedded user's `owner`
// field; JWT-Custom emits only selected fields, so the builder injects `owner`
// and `organization` unconditionally.
func TestJwtFormatsCarryOrg(t *testing.T) {
	claims := Claims{
		User:             testUser(),
		TokenType:        "access-token",
		Scope:            "openid profile email",
		RegisteredClaims: jwt.RegisteredClaims{Subject: "hanzo/alice"},
	}

	assertOrg(t, "JWT (default)", jsonClaims(t, getClaimsWithoutThirdIdp(claims)), "hanzo")
	assertOrg(t, "JWT-Empty", jsonClaims(t, getShortClaims(claims)), "hanzo")
	assertOrg(t, "JWT-Standard", jsonClaims(t, getStandardClaims(claims)), "hanzo")

	// JWT-Custom with an app config that selects NOTHING org-related — owner and
	// organization must still be present.
	custom := getClaimsCustom(claims, []string{"email"}, nil)
	assertOrg(t, "JWT-Custom", custom, "hanzo")
}
