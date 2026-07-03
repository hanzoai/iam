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
// default "JWT" access token must therefore be BOUNDED and must never carry
// credential material. These tests pin both invariants against a maximally
// heavy user (many roles/permissions/properties + populated secrets): the
// projection drops all of it and keeps only identity + org.

// heavyUser is a worst-case user: the fields that used to bloat (and leak into)
// the default token are all populated.
func heavyUser() *User {
	return &User{
		Owner:         "hanzo",
		Name:          "alice",
		Id:            "hanzo/alice",
		Type:          "normal-user",
		DisplayName:   "Alice",
		Email:         "alice@hanzo.ai",
		EmailVerified: true,
		// Credential material — MUST NOT appear in a token.
		Password:      "$argon2id$v=19$...redacted...",
		PasswordSalt:  "818bcaa2b2679e1c0af6",
		PasswordType:  "argon2id",
		TotpSecret:    "JBSWY3DPEHPK3PXP",
		RecoveryCodes: []string{"aaaa-bbbb", "cccc-dddd"},
		// Unbounded / heavyweight — the gateway-header-limit offenders.
		Avatar:      "https://cdn.hanzo.ai/img/default-avatar.png",
		Address:     []string{"1 Infinite Loop", "Cupertino"},
		Education:   "PhD",
		Properties:  map[string]string{"hanzo.preferences": `{"favorites":["chat","billing","models","vector"]}`},
		Roles:       []*Role{{Owner: "hanzo", Name: "o11y-admin"}, {Owner: "hanzo", Name: "billing-admin"}},
		Permissions: []*Permission{{Owner: "hanzo", Name: "read-all"}, {Owner: "hanzo", Name: "write-all"}},
		Groups:      []string{"hanzo/eng", "hanzo/founders"},
	}
}

// TestDefaultJwtIsSlimAndSafe asserts the default "JWT" access-token projection
// (getClaimsWithoutThirdIdp) keeps identity + org and drops every heavyweight
// and secret claim, keeping the serialized payload bounded.
func TestDefaultJwtIsSlimAndSafe(t *testing.T) {
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
			t.Errorf("default JWT: identity claim %q missing", k)
		}
	}
	if m["owner"] != "hanzo" || m["organization"] != "hanzo" {
		t.Errorf("default JWT: org claim = owner=%v organization=%v, want hanzo", m["owner"], m["organization"])
	}

	// Credential material and heavyweight/unbounded claims are gone.
	for _, k := range []string{
		"password", "passwordSalt", "passwordType", "totpSecret", "recoveryCodes",
		"properties", "roles", "permissions", "groups", "managedAccounts",
		"avatar", "permanentAvatar", "address", "education",
	} {
		if v, ok := m[k]; ok {
			t.Errorf("default JWT: forbidden claim %q leaked: %v", k, v)
		}
	}

	// Bounded size: a worst-case user still serializes compactly.
	b, _ := json.Marshal(getClaimsWithoutThirdIdp(claims))
	if len(b) > 512 {
		t.Errorf("default JWT payload = %d bytes, want <= 512 (bounded)", len(b))
	}
	t.Logf("default JWT payload (heavy user) = %d bytes", len(b))
}
