// Copyright 2026 The Hanzo Authors. All Rights Reserved.

package routers

import "testing"

func TestCanonicalOAuthPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// Bare OAuth2-spec form passes through unchanged.
		{"/login/oauth/authorize", "/login/oauth/authorize"},
		{"/login/oauth/access_token", "/login/oauth/access_token"},

		// /oauth/* OIDC-discovery alias collapses to /login/oauth/*.
		{"/oauth/authorize", "/login/oauth/authorize"},
		{"/oauth/token", "/login/oauth/token"},
		{"/oauth/access_token", "/login/oauth/access_token"},
		{"/oauth/refresh", "/login/oauth/refresh"},
		{"/oauth/introspect", "/login/oauth/introspect"},
		{"/oauth/revoke", "/login/oauth/revoke"},
		{"/oauth/userinfo", "/login/oauth/userinfo"},
		{"/oauth/device", "/login/oauth/device"},
		{"/oauth/logout", "/login/oauth/logout"},
		{"/oauth/register", "/login/oauth/register"},

		// Gateway-prefixed forms collapse to /login/oauth/*.
		{"/v1/iam/oauth/authorize", "/login/oauth/authorize"},
		{"/v1/iam/oauth/access_token", "/login/oauth/access_token"},
		{"/v1/iam/login/oauth/authorize", "/login/oauth/authorize"},
		{"/v1/iam/login/oauth/access_token", "/login/oauth/access_token"},
		{"/v1/iam/login/oauth/refresh_token", "/login/oauth/refresh_token"},

		// Legacy /api/iam/... too.
		{"/api/iam/oauth/access_token", "/login/oauth/access_token"},
		{"/api/iam/login/oauth/access_token", "/login/oauth/access_token"},

		// Non-OAuth paths must be untouched.
		{"/v1/iam/login", "/v1/iam/login"},
		{"/v1/iam/get-user", "/v1/iam/get-user"},
		{"/", "/"},
		{"/health", "/health"},

		// Word-boundary safety — /oauth-foo must NOT match /oauth.
		{"/oauth-spec", "/oauth-spec"},
		{"/v1/iam/oauthx/foo", "/v1/iam/oauthx/foo"},
	}
	for _, c := range cases {
		got := canonicalOAuthPath(c.in)
		if got != c.want {
			t.Errorf("canonicalOAuthPath(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
