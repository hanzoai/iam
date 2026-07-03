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

// A bearer token rides in the `Authorization` request header, and api.hanzo.ai
// rejects oversized headers with HTTP 431 ("Too big request header"). The
// default "JWT" access token must therefore stay bounded and must never carry
// credential material — while still carrying the authorization grant
// (isAdmin/roles/permissions/groups) and billing tier that commerce reads.

// heavyUser is a worst-case user: everything that used to bloat (and leak into)
// the default token is populated. Authorization + tier must survive; secrets and
// profile bloat (incl. the UI-preferences Properties blob) must not.
func heavyUser() *User {
	return &User{
		Owner:         "hanzo",
		Name:          "alice",
		Id:            "hanzo/alice",
		Type:          "normal-user",
		DisplayName:   "Alice",
		Email:         "alice@hanzo.ai",
		EmailVerified: true,
		IsAdmin:       true,
		// Credential material — MUST NOT appear in a token.
		Password:      "$argon2id$v=19$...redacted...",
		PasswordSalt:  "818bcaa2b2679e1c0af6",
		PasswordType:  "argon2id",
		TotpSecret:    "JBSWY3DPEHPK3PXP",
		RecoveryCodes: []string{"aaaa-bbbb", "cccc-dddd"},
		// Profile bloat — MUST NOT appear.
		Avatar:    "https://cdn.hanzo.ai/img/default-avatar.png",
		Address:   []string{"1 Infinite Loop", "Cupertino"},
		Education: "PhD",
		// Authorization grant — MUST survive (commerce FlexRoles + IAM re-parse).
		Roles:       []*Role{{Owner: "hanzo", Name: "o11y-admin"}, {Owner: "hanzo", Name: "billing-admin"}},
		Permissions: []*Permission{{Owner: "hanzo", Name: "read-all"}},
		Groups:      []string{"hanzo/eng"},
		// Properties: only the billing `tier` survives; the UI blob is dropped.
		Properties: map[string]string{
			"tier":              "pro",
			"hanzo.preferences": `{"favorites":["chat","billing","models","vector"],"theme":"dark"}`,
		},
	}
}

func TestDefaultJwtKeepsAuthzDropsSecretsAndBloat(t *testing.T) {
	claims := Claims{
		User:             heavyUser(),
		TokenType:        "access-token",
		Scope:            "openid profile email",
		RegisteredClaims: jwt.RegisteredClaims{Subject: "hanzo/alice"},
	}

	m := jsonClaims(t, getClaimsWithoutThirdIdp(claims))

	// Identity + org survive.
	for _, k := range []string{"owner", "organization", "name", "id", "email", "email_verified"} {
		if _, ok := m[k]; !ok {
			t.Errorf("identity claim %q missing", k)
		}
	}
	if m["owner"] != "hanzo" || m["organization"] != "hanzo" {
		t.Errorf("org claim = owner=%v organization=%v, want hanzo", m["owner"], m["organization"])
	}

	// Authorization grant survives (commerce reads roles; IAM re-parses them).
	if _, ok := m["isAdmin"]; !ok {
		t.Errorf("isAdmin claim dropped")
	}
	roles, ok := m["roles"].([]interface{})
	if !ok || len(roles) != 2 {
		t.Fatalf("roles claim = %v, want 2 role objects", m["roles"])
	}
	if r0, _ := roles[0].(map[string]interface{}); r0["name"] != "o11y-admin" {
		t.Errorf("roles[0].name = %v, want o11y-admin", r0["name"])
	}
	if _, ok := m["permissions"]; !ok {
		t.Errorf("permissions claim dropped")
	}
	if _, ok := m["groups"]; !ok {
		t.Errorf("groups claim dropped")
	}

	// Properties are filtered to the billing allowlist: tier stays, blob goes.
	props, ok := m["properties"].(map[string]interface{})
	if !ok {
		t.Fatalf("properties claim = %v, want {tier}", m["properties"])
	}
	if props["tier"] != "pro" {
		t.Errorf("properties.tier = %v, want pro", props["tier"])
	}
	if _, leaked := props["hanzo.preferences"]; leaked {
		t.Errorf("properties leaked UI-preferences blob: %v", props)
	}

	// Credential material and profile bloat are gone.
	for _, k := range []string{
		"password", "passwordSalt", "passwordType", "totpSecret", "recoveryCodes",
		"hash", "preHash", "avatar", "permanentAvatar", "address", "education",
		"managedAccounts",
	} {
		if v, ok := m[k]; ok {
			t.Errorf("forbidden claim %q leaked: %v", k, v)
		}
	}

	// Bounded: a worst-case user still serializes compactly.
	b, _ := json.Marshal(getClaimsWithoutThirdIdp(claims))
	if len(b) > 700 {
		t.Errorf("default JWT payload = %d bytes, want <= 700 (bounded)", len(b))
	}
	t.Logf("default JWT payload (heavy user) = %d bytes", len(b))
}
