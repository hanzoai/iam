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

// IsClientCredentialsClaim — the single client_credentials discriminator that
// backs both the by-attribute service route and the confidential-client subject
// normalization in routers/authz_filter.go. A genuine client_credentials token
// is the synthetic application-user minted by GetClientCredentialsToken
// (Type=="application", User.Name==app.Name, Provider=="", SigninMethod=="").
// Type ALONE is forgeable, so all four fields are required.

package object

import "testing"

func ccClaims(name, typ, provider, signin string) *Claims {
	return &Claims{
		User:         &User{Name: name, Type: typ},
		Provider:     provider,
		SigninMethod: signin,
	}
}

func TestIsClientCredentialsClaim(t *testing.T) {
	app := &Application{Owner: "admin", Name: "hanzo-console", Organization: "hanzo"}

	cases := []struct {
		name   string
		claims *Claims
		want   bool
	}{
		{
			// The genuine client_credentials shape.
			name:   "genuine client_credentials",
			claims: ccClaims("hanzo-console", "application", "", ""),
			want:   true,
		},
		{
			// A tenant-admin-promoted user with Type="application" but whose
			// user-name differs from the app name — the exact forgery shape.
			name:   "type=application but name mismatch (forgery)",
			claims: ccClaims("dave", "application", "", ""),
			want:   false,
		},
		{
			// A human OIDC/authorization_code JWT carries a Provider.
			name:   "has provider (authorization_code)",
			claims: ccClaims("hanzo-console", "application", "google", ""),
			want:   false,
		},
		{
			// A password-grant JWT carries a SigninMethod.
			name:   "has signinMethod (password grant)",
			claims: ccClaims("hanzo-console", "application", "", "Password"),
			want:   false,
		},
		{
			// A normal user JWT — wrong Type.
			name:   "type=normal-user",
			claims: ccClaims("hanzo-console", "normal-user", "", ""),
			want:   false,
		},
		{
			name:   "nil claims",
			claims: nil,
			want:   false,
		},
		{
			name:   "nil embedded user",
			claims: &Claims{User: nil},
			want:   false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := IsClientCredentialsClaim(tc.claims, app); got != tc.want {
				t.Fatalf("IsClientCredentialsClaim(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}

	// nil application is never a client_credentials claim.
	if IsClientCredentialsClaim(ccClaims("hanzo-console", "application", "", ""), nil) {
		t.Fatal("nil application must not resolve to a client_credentials claim")
	}
}
