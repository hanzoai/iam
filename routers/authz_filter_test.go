// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0

package routers

import (
	"net/http"
	"testing"
)

// TestGetUrlPath_NormalizesV1IamOAuth verifies that both the legacy bare
// (/login/oauth/*, /oauth/*) and canonical /v1/iam/-prefixed OAuth surfaces
// collapse to the same authz resource so the anonymous policy applies. Without
// this, public OIDC clients hitting /v1/iam/login/oauth/access_token saw
// `{"status":"error","msg":"Unauthorized operation"}` because Casbin matched
// against the full prefixed path and no policy granted anonymous access.
func TestGetUrlPath_NormalizesV1IamOAuth(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		// OAuth/OIDC code+token flow → /login/oauth resource (anonymous-grantable).
		{"v1_iam_oauth_authorize", "/v1/iam/oauth/authorize", "/login/oauth"},
		{"v1_iam_oauth_token", "/v1/iam/oauth/token", "/login/oauth"},
		{"v1_iam_oauth_access_token", "/v1/iam/oauth/access_token", "/login/oauth"},
		{"v1_iam_oauth_refresh", "/v1/iam/oauth/refresh", "/login/oauth"},
		{"v1_iam_oauth_refresh_token", "/v1/iam/oauth/refresh_token", "/login/oauth"},
		{"v1_iam_oauth_introspect", "/v1/iam/oauth/introspect", "/login/oauth"},
		{"v1_iam_oauth_revoke", "/v1/iam/oauth/revoke", "/login/oauth"},
		{"v1_iam_oauth_register", "/v1/iam/oauth/register", "/login/oauth"},

		// userinfo / device / logout collapse to their existing canonical
		// /v1/iam/* policy resource keys so the discovery doc's
		// /v1/iam/oauth/* surface shares a single policy with the IAM
		// API surface.
		{"v1_iam_oauth_userinfo", "/v1/iam/oauth/userinfo", "/v1/iam/userinfo"},
		{"v1_iam_oauth_device", "/v1/iam/oauth/device", "/v1/iam/device-auth"},
		{"v1_iam_oauth_logout", "/v1/iam/oauth/logout", "/v1/iam/logout"},

		// Non-OAuth paths pass through unchanged.
		{"healthz", "/healthz", "/healthz"},
		{"v1_iam_healthz", "/v1/iam/healthz", "/v1/iam/healthz"},
		{"v1_iam_login", "/v1/iam/login", "/v1/iam/login"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := newTestCtx(http.MethodGet, tc.path, "127.0.0.1")
			got := getUrlPath(ctx)
			if got != tc.want {
				t.Fatalf("getUrlPath(%q) = %q; want %q", tc.path, got, tc.want)
			}
		})
	}
}
