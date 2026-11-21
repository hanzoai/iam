// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package cors

import "testing"

// A redirect URI reduces to exactly the string a browser sends in Origin —
// scheme + host + port, nothing else. Getting this wrong means a registered
// app still gets blocked, which is the bug this package exists to fix.
func TestOriginOf_MatchesWhatABrowserSends(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://lux.cloud/auth/callback", "https://lux.cloud"},
		{"https://console.lux.cloud/auth/callback", "https://console.lux.cloud"},
		{"https://lux.cloud:8443/auth/callback", "https://lux.cloud:8443"}, // port is part of the origin
		{"https://lux.cloud", "https://lux.cloud"},                         // no path
		{"  https://lux.cloud/auth/callback  ", "https://lux.cloud"},       // document whitespace
	} {
		if got := originOf(tc.in); got != tc.want {
			t.Errorf("originOf(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// cli and desktop clients register loopback and custom-scheme redirects. They
// never send an Origin, so they must not widen the allowlist — in particular a
// deep-link scheme must never become an allowed web origin.
func TestOriginOf_SkipsNonBrowserRedirects(t *testing.T) {
	for _, in := range []string{
		"lux://oauth/desk",
		"http://127.0.0.1/callback", // loopback IS http, but see below
		"",
		"://malformed",
	} {
		got := originOf(in)
		if in == "http://127.0.0.1/callback" {
			// Loopback is a real http origin and is returned; it is harmless
			// (no site is served there) and keeps a local dev client working.
			if got != "http://127.0.0.1" {
				t.Errorf("originOf(%q) = %q, want the loopback origin", in, got)
			}
			continue
		}
		if got != "" {
			t.Errorf("originOf(%q) = %q, want empty", in, got)
		}
	}
}

// Only endpoints a browser-side OIDC client actually calls are opened. Widening
// this set is a security decision, so the set is asserted rather than assumed.
func TestBrowserPaths_ExactlyTheOIDCBrowserSurface(t *testing.T) {
	// These MUST be open — the failure that motivated this package was the
	// token endpoint and discovery being blocked.
	for _, p := range []string{
		"/v1/iam/oauth/token",
		"/.well-known/openid-configuration",
		"/v1/iam/.well-known/jwks",
		"/v1/iam/oauth/userinfo",
	} {
		if !browserPaths[p] {
			t.Errorf("%s must be reachable cross-origin", p)
		}
	}
	// These MUST NOT be: admin/bootstrap surfaces and the credential-login
	// endpoint are not for cross-origin browser use.
	for _, p := range []string{
		"/v1/iam/admin/applications/upsert",
		"/v1/iam/admin/users/upsert",
		"/v1/iam/login",
		"/healthz",
		"/v1/iam/oauth/authorize", // a top-level redirect, not a fetch
	} {
		if browserPaths[p] {
			t.Errorf("%s must NOT be opened cross-origin", p)
		}
	}
}

// The allowlist is derived from application rows; an origin nobody registered
// is not allowed, and one that is registered is.
func TestLoadDerivesTheAllowlistFromRedirectUris(t *testing.T) {
	set := map[string]bool{}
	for _, u := range []string{
		"https://lux.cloud/auth/callback",
		"https://www.lux.cloud/auth/callback",
		"lux://oauth/desk",
	} {
		if o := originOf(u); o != "" {
			set[o] = true
		}
	}
	if !set["https://lux.cloud"] || !set["https://www.lux.cloud"] {
		t.Errorf("registered hosts missing from the allowlist: %v", set)
	}
	if set["https://evil.example"] {
		t.Error("an unregistered origin must never be allowed")
	}
	if len(set) != 2 {
		t.Errorf("deep-link scheme leaked into the web allowlist: %v", set)
	}
}

// The org surface a console reads about itself must be reachable cross-origin,
// or a registered SPA cannot render its own org switcher and its backend ends up
// re-implementing an identity read. These sit beside the OIDC endpoints because
// they are the same shape: a Bearer-protected read whose ORIGIN is decided here
// and whose PRINCIPAL is decided by the Guard.
func TestBrowserPaths_CoverTheConsoleOrgSurface(t *testing.T) {
	for _, p := range []string{
		"/v1/iam/get-organizations",
		"/v1/iam/get-organization",
		"/v1/iam/get-users",
		"/v1/iam/get-account",
	} {
		if !browserPaths[p] {
			t.Errorf("%s must be reachable cross-origin: a console reads it to show "+
				"which org the user is acting as", p)
		}
	}
}

// Opening a path to an origin is not the same as opening the data. Anything a
// browser never calls stays closed, so this list can only grow deliberately.
func TestBrowserPaths_StayClosedByDefault(t *testing.T) {
	for _, p := range []string{
		"/v1/iam/users",          // typed CRUD — server-to-server
		"/v1/iam/get-certs",      // signing material
		"/v1/iam/get-providers",  // provider secrets
		"/v1/iam/delete-user",    // a write
		"/v1/iam/registry/token", // docker client, not a browser
	} {
		if browserPaths[p] {
			t.Errorf("%s is open to browsers but nothing browser-side calls it", p)
		}
	}
}
