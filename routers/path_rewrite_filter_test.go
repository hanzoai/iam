// Copyright 2026 The Hanzo Authors. All Rights Reserved.

package routers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beego/beego/v2/server/web/context"
)

func TestCanonicalPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// --- OAuth surface ---

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

		// Legacy /api/iam/<oauth>... — OAuth aliases win over generic /api/* rewrite.
		{"/api/iam/oauth/access_token", "/login/oauth/access_token"},
		{"/api/iam/login/oauth/access_token", "/login/oauth/access_token"},

		// --- Legacy /api/* surface (upstream-Casdoor shape) ---

		// /api/<endpoint> → /v1/iam/<endpoint>. Method-agnostic — same
		// rewrite for GET, POST, PUT, DELETE.
		{"/api/login", "/v1/iam/login"},
		{"/api/get-account", "/v1/iam/get-account"},
		{"/api/userinfo", "/v1/iam/userinfo"},
		{"/api/get-applications", "/v1/iam/get-applications"},
		{"/api/get-organizations", "/v1/iam/get-organizations"},
		{"/api/add-user", "/v1/iam/add-user"},
		{"/api/delete-token", "/v1/iam/delete-token"},
		{"/api/get-app-login", "/v1/iam/get-app-login"},
		{"/api/signup", "/v1/iam/signup"},

		// /api/iam/<non-oauth> → /v1/iam/<endpoint> (drop the /iam middle
		// segment — it's a doubled prefix from a path-preserving gateway).
		{"/api/iam/get-account", "/v1/iam/get-account"},
		{"/api/iam/login", "/v1/iam/login"},

		// Trailing path segments preserved.
		{"/api/server/myorg/myapp", "/v1/iam/server/myorg/myapp"},
		{"/api/saml/redirect/myorg/myapp", "/v1/iam/saml/redirect/myorg/myapp"},

		// --- Pass-through ---

		// Already-canonical /v1/iam/* untouched.
		{"/v1/iam/login", "/v1/iam/login"},
		{"/v1/iam/get-user", "/v1/iam/get-user"},

		// Root + health untouched.
		{"/", "/"},
		{"/health", "/health"},
		{"/healthz", "/healthz"},

		// /.well-known/* untouched (registered directly in router.go).
		{"/.well-known/openid-configuration", "/.well-known/openid-configuration"},
		{"/.well-known/jwks", "/.well-known/jwks"},

		// /cas/* and /scim/* untouched.
		{"/cas/myorg/myapp/serviceValidate", "/cas/myorg/myapp/serviceValidate"},
		{"/scim/Users", "/scim/Users"},

		// /_/iam SPA route untouched.
		{"/_/iam", "/_/iam"},
		{"/_/iam/index.html", "/_/iam/index.html"},

		// Word-boundary safety — /oauth-foo must NOT match /oauth, and
		// /api-foo must NOT match /api.
		{"/oauth-spec", "/oauth-spec"},
		{"/v1/iam/oauthx/foo", "/v1/iam/oauthx/foo"},
		{"/apidocs", "/apidocs"},
		{"/api-token", "/api-token"},
	}
	for _, c := range cases {
		got := canonicalPath(c.in)
		if got != c.want {
			t.Errorf("canonicalPath(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

// TestPathRewriteFilter_LegacyAPI_POST verifies that the filter mutates the
// request URL in-place for legacy /api/* aliases, regardless of HTTP method.
// This is the unit-level guard for the "POST /api/login returns SPA HTML"
// regression — once rewritten, StaticFilter's /v1/iam/ pass-through skips
// the SPA fallback and Beego dispatches to ApiController.Login.
func TestPathRewriteFilter_LegacyAPI_POST(t *testing.T) {
	cases := []struct {
		name, method, in, want string
	}{
		{"POST_api_login", http.MethodPost, "/api/login", "/v1/iam/login"},
		{"POST_api_signup", http.MethodPost, "/api/signup", "/v1/iam/signup"},
		{"POST_api_add_user", http.MethodPost, "/api/add-user", "/v1/iam/add-user"},
		{"GET_api_get_account", http.MethodGet, "/api/get-account", "/v1/iam/get-account"},
		{"GET_api_userinfo", http.MethodGet, "/api/userinfo", "/v1/iam/userinfo"},
		{"DELETE_api_delete_token", http.MethodDelete, "/api/delete-token", "/v1/iam/delete-token"},
		{"POST_api_iam_login", http.MethodPost, "/api/iam/login", "/v1/iam/login"},
		// OAuth on /api/iam wins via canonicalOAuthPath, not the legacy
		// rewrite — both end up at /login/oauth/*.
		{"POST_api_iam_oauth_token", http.MethodPost, "/api/iam/oauth/access_token", "/login/oauth/access_token"},
		// Already-canonical paths are no-ops.
		{"POST_v1_iam_login_noop", http.MethodPost, "/v1/iam/login", "/v1/iam/login"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.in, strings.NewReader(""))
			rec := httptest.NewRecorder()
			ctx := context.NewContext()
			ctx.Reset(rec, req)

			PathRewriteFilter(ctx)

			if got := ctx.Request.URL.Path; got != c.want {
				t.Errorf("PathRewriteFilter(%s %q) → %q; want %q", c.method, c.in, got, c.want)
			}
		})
	}
}

// TestPathRewriteFilter_StaticFilterHandoff confirms the rewritten path
// matches the prefix StaticFilter uses to skip the SPA fallback. This is
// the load-bearing invariant: rewrite → /v1/iam/* → StaticFilter pass-through
// → Beego router → handler. Encoded as a direct prefix check rather than
// invoking StaticFilter (which depends on global beego config + a web/build
// dir at runtime).
func TestPathRewriteFilter_StaticFilterHandoff(t *testing.T) {
	for _, in := range []string{
		"/api/login",
		"/api/signup",
		"/api/get-applications",
		"/api/iam/login",
	} {
		req := httptest.NewRequest(http.MethodPost, in, strings.NewReader(""))
		rec := httptest.NewRecorder()
		ctx := context.NewContext()
		ctx.Reset(rec, req)

		PathRewriteFilter(ctx)

		got := ctx.Request.URL.Path
		if !strings.HasPrefix(got, "/v1/iam/") {
			t.Errorf("rewritten %q = %q; expected /v1/iam/ prefix so StaticFilter skips SPA fallback", in, got)
		}
	}
}

// TestCanonicalOAuthPath kept for compatibility — exercises the OAuth-only
// path directly so a regression to the OAuth alias table can't hide behind
// the broader canonicalPath dispatch.
func TestCanonicalOAuthPath(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"/login/oauth/authorize", "/login/oauth/authorize"},
		{"/oauth/authorize", "/login/oauth/authorize"},
		{"/v1/iam/oauth/access_token", "/login/oauth/access_token"},
		{"/v1/iam/login/oauth/access_token", "/login/oauth/access_token"},
		{"/api/iam/oauth/access_token", "/login/oauth/access_token"},
		{"/api/iam/login/oauth/access_token", "/login/oauth/access_token"},

		// Non-OAuth: untouched by canonicalOAuthPath.
		{"/api/login", "/api/login"},
		{"/v1/iam/login", "/v1/iam/login"},
	}
	for _, c := range cases {
		got := canonicalOAuthPath(c.in)
		if got != c.want {
			t.Errorf("canonicalOAuthPath(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}
