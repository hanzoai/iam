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

package object

import (
	"reflect"
	"strings"
	"testing"
)

func TestSplitOriginList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "https://hanzo.id", []string{"https://hanzo.id"}},
		{"two", "https://hanzo.id,https://lux.id", []string{"https://hanzo.id", "https://lux.id"}},
		{
			"production-prod-config",
			"https://hanzo.ai,https://hanzo.id,https://lux.id,https://zoo.id,https://pars.id,https://id.ad.nexus,https://id.bootno.de,https://id.hanzo.ai,https://id.lux.network,https://id.zoo.network,https://id.pars.network,https://iam.hanzo.ai,https://auth.hanzo.ai,https://auth.zoo.ngo,https://auth.pars.ai",
			[]string{
				"https://hanzo.ai",
				"https://hanzo.id",
				"https://lux.id",
				"https://zoo.id",
				"https://pars.id",
				"https://id.ad.nexus",
				"https://id.bootno.de",
				"https://id.hanzo.ai",
				"https://id.lux.network",
				"https://id.zoo.network",
				"https://id.pars.network",
				"https://iam.hanzo.ai",
				"https://auth.hanzo.ai",
				"https://auth.zoo.ngo",
				"https://auth.pars.ai",
			},
		},
		{"trim-spaces", "  https://a  ,  https://b  ", []string{"https://a", "https://b"}},
		{"drop-empty", "https://a,,https://b,", []string{"https://a", "https://b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SplitOriginList(tt.in)
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("SplitOriginList(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}

// TestGetOidcDiscovery_CanonicalSurface locks the published discovery shape
// to /v1/iam/oauth/* + /v1/iam/.well-known/jwks. Any future drift that
// regresses to the bare /oauth/* form or the legacy /login/oauth/* form
// is a documented contract break — external IdPs/SDKs cache the discovery
// doc and will not refetch on a 404.
//
// Origin selection covers both single-host deployments (host matches
// nothing in the CSV → fallback to first entry, both fields equal) and
// multi-host (host present in CSV → exact match used).
func TestGetOidcDiscovery_CanonicalSurface(t *testing.T) {
	d := GetOidcDiscovery("iam.hanzo.ai", "")

	// Issuer must be a single absolute URL — never a CSV. The earlier
	// "comma-concatenated origin" regression made every URL invalid for
	// any OIDC library that does string equality on iss.
	if strings.ContainsRune(d.Issuer, ',') {
		t.Fatalf("issuer must be a single origin, got CSV: %q", d.Issuer)
	}
	if !strings.HasPrefix(d.Issuer, "http://") && !strings.HasPrefix(d.Issuer, "https://") {
		t.Fatalf("issuer missing scheme: %q", d.Issuer)
	}

	wantSuffix := map[string]string{
		"AuthorizationEndpoint":       "/v1/iam/oauth/authorize",
		"TokenEndpoint":               "/v1/iam/oauth/token",
		"UserinfoEndpoint":            "/v1/iam/oauth/userinfo",
		"DeviceAuthorizationEndpoint": "/v1/iam/oauth/device",
		"RegistrationEndpoint":        "/v1/iam/oauth/register",
		"IntrospectionEndpoint":       "/v1/iam/oauth/introspect",
		"RevocationEndpoint":          "/v1/iam/oauth/revoke",
		"EndSessionEndpoint":          "/v1/iam/oauth/logout",
		"JwksUri":                     "/v1/iam/.well-known/jwks",
	}
	got := map[string]string{
		"AuthorizationEndpoint":       d.AuthorizationEndpoint,
		"TokenEndpoint":               d.TokenEndpoint,
		"UserinfoEndpoint":            d.UserinfoEndpoint,
		"DeviceAuthorizationEndpoint": d.DeviceAuthorizationEndpoint,
		"RegistrationEndpoint":        d.RegistrationEndpoint,
		"IntrospectionEndpoint":       d.IntrospectionEndpoint,
		"RevocationEndpoint":          d.RevocationEndpoint,
		"EndSessionEndpoint":          d.EndSessionEndpoint,
		"JwksUri":                     d.JwksUri,
	}
	for field, suffix := range wantSuffix {
		v := got[field]
		if strings.ContainsRune(v, ',') {
			t.Errorf("%s must be a single URL, got CSV: %q", field, v)
		}
		if !strings.HasSuffix(v, suffix) {
			t.Errorf("%s = %q, want suffix %q", field, v, suffix)
		}
	}
}

// TestBuildIssuerAndJwks_AppSpecific locks the per-application URL shape
// using the pure composition helper — the same code GetOidcDiscovery
// runs before its DB-touching scope merge. Issuer + jwks_uri MUST use
// /v1/iam/.well-known/<app>/... and MUST be single URLs (no CSV).
func TestBuildIssuerAndJwks_AppSpecific(t *testing.T) {
	issuer, jwksUri := buildIssuerAndJwks("https://iam.hanzo.ai", "myapp")
	if strings.ContainsRune(issuer, ',') || strings.ContainsRune(jwksUri, ',') {
		t.Fatalf("app-specific issuer/jwks must be single URLs, got %q / %q", issuer, jwksUri)
	}
	if want := "https://iam.hanzo.ai/v1/iam/.well-known/myapp"; issuer != want {
		t.Errorf("issuer = %q, want %q", issuer, want)
	}
	if want := "https://iam.hanzo.ai/v1/iam/.well-known/myapp/jwks"; jwksUri != want {
		t.Errorf("jwks_uri = %q, want %q", jwksUri, want)
	}
}

// TestBuildIssuerAndJwks_Global covers the global (no application)
// shape — issuer is the bare origin, jwks_uri is canonical /v1/iam/.well-known/jwks.
func TestBuildIssuerAndJwks_Global(t *testing.T) {
	issuer, jwksUri := buildIssuerAndJwks("https://iam.hanzo.ai", "")
	if want := "https://iam.hanzo.ai"; issuer != want {
		t.Errorf("issuer = %q, want %q", issuer, want)
	}
	if want := "https://iam.hanzo.ai/v1/iam/.well-known/jwks"; jwksUri != want {
		t.Errorf("jwks_uri = %q, want %q", jwksUri, want)
	}
}

func TestSelectOriginForHost(t *testing.T) {
	prod := []string{
		"https://hanzo.ai",
		"https://hanzo.id",
		"https://lux.id",
		"https://zoo.id",
		"https://pars.id",
		"https://iam.hanzo.ai",
	}
	tests := []struct {
		name string
		list []string
		host string
		want string
	}{
		{"empty-list", nil, "hanzo.id", ""},
		{"exact-match", prod, "hanzo.id", "https://hanzo.id"},
		{"lux", prod, "lux.id", "https://lux.id"},
		{"zoo", prod, "zoo.id", "https://zoo.id"},
		{"pars", prod, "pars.id", "https://pars.id"},
		{"strip-port-from-host", prod, "hanzo.id:443", "https://hanzo.id"},
		{"case-insensitive", prod, "Hanzo.ID", "https://hanzo.id"},
		{"iam-domain", prod, "iam.hanzo.ai", "https://iam.hanzo.ai"},
		// No match — fall back to first entry. This is acceptable: the
		// caller is hitting a host the operator didn't put in `origin`.
		// Single-tenant deployments rely on this fallback.
		{"no-match-fallback", prod, "unknown.example", "https://hanzo.ai"},
		// Origin with explicit port: hostname comparison only.
		{"origin-with-port", []string{"http://localhost:7001"}, "localhost", "http://localhost:7001"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectOriginForHost(tt.list, tt.host)
			if got != tt.want {
				t.Fatalf("selectOriginForHost(%v, %q) = %q, want %q", tt.list, tt.host, got, tt.want)
			}
		})
	}
}
