// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam/pkg/schema"
)

// audienceOf keeps the presented token's audience so a re-scoped credential is
// accepted where the original was, and falls back to the app's own client id
// when the token carries none.
func TestAudienceOf(t *testing.T) {
	app := &schema.Application{ClientId: "self-client"}
	cases := []struct {
		name   string
		claims *Claims
		want   string
	}{
		{"keeps presented audience", &Claims{RegisteredClaims: jwt.RegisteredClaims{Audience: jwt.ClaimStrings{"resource-a"}}}, "resource-a"},
		{"empty audience falls back", &Claims{}, "self-client"},
		{"blank first audience falls back", &Claims{RegisteredClaims: jwt.RegisteredClaims{Audience: jwt.ClaimStrings{""}}}, "self-client"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := audienceOf(tc.claims, app); got != tc.want {
				t.Fatalf("audienceOf = %q, want %q", got, tc.want)
			}
		})
	}
}

// WebAuthnDisplayName shows the display name when present, else the signup name,
// and never an empty string an authenticator would render as an unnamed entry.
func TestWebAuthnDisplayName(t *testing.T) {
	cases := []struct {
		name string
		user *schema.User
		want string
	}{
		{"display name preferred", &schema.User{DisplayName: "Zach Kelling", Name: "z"}, "Zach Kelling"},
		{"falls back to name", &schema.User{Name: "z"}, "z"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := (holder{user: tc.user}).WebAuthnDisplayName(); got != tc.want {
				t.Fatalf("WebAuthnDisplayName = %q, want %q", got, tc.want)
			}
		})
	}
}
