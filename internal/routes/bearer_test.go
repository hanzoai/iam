// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signed signs claims under the trusted cert, the way IAM signs every token.
func (h *harness) signed(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	claims["iat"] = time.Now().Add(-time.Minute).Unix()
	claims["exp"] = time.Now().Add(time.Hour).Unix()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = signingKid
	s, err := tok.SignedString(h.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// A bearer is an access token this IAM issued. An id_token proves a sign-in to
// the client it was issued to and is no credential to act with, and a token with
// no audience or an issuer this IAM does not mint under was not issued as one.
// Each is refused at the Guard and at the account read, for a SuperAdmin's
// subject as for anyone's.
func TestBearer_onlyAnAccessTokenActs(t *testing.T) {
	h := newHarness(t)
	for name, c := range map[string]struct {
		claims jwt.MapClaims
		want   int
	}{
		"an access token": {jwt.MapClaims{"sub": "admin/root", "tokenType": "access-token", "iss": "https://hanzo.id", "aud": "hanzo-console"}, 200},
		"an id_token":     {jwt.MapClaims{"sub": "admin/root", "tokenType": "id-token", "iss": "https://hanzo.id", "aud": "hanzo-console", "nonce": "n"}, 401},
		"no token type":   {jwt.MapClaims{"sub": "admin/root", "iss": "https://hanzo.id", "aud": "hanzo-console"}, 401},
		"no audience":     {jwt.MapClaims{"sub": "admin/root", "tokenType": "access-token", "iss": "https://hanzo.id"}, 401},
		"another issuer":  {jwt.MapClaims{"sub": "admin/root", "tokenType": "access-token", "iss": "https://issuer.example", "aud": "hanzo-console"}, 401},
	} {
		bearer := h.signed(t, c.claims)
		if code, body := h.get(t, "/v1/iam/users?owner=hanzo", bearer); code != c.want {
			t.Errorf("%s at the Guard: %d %.120s, want %d", name, code, body, c.want)
		}
		code, body := h.get(t, "/v1/iam/account", bearer)
		signedIn := code == 200 && !contains(body, `"status":"error"`)
		if signedIn != (c.want == 200) {
			t.Errorf("%s at the account read: %d %.120s", name, code, body)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
