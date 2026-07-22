// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"testing"
)

// Discovery is served at both well-known paths, host-relative, advertising only
// what iam2 implements — matching the live hanzo.id surface so a client's
// discovery step is unchanged across the backend swap.
func TestDiscovery_ShapeAtBothPaths(t *testing.T) {
	app, _ := newServer(t)

	for _, path := range []string{PathDiscovery, PathDiscoveryV1} {
		resp, body := do(t, app, formReqNoBody("GET", path))
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
		d := decode(t, body)
		if d["issuer"] != "https://hanzo.id" {
			t.Errorf("%s: issuer = %v, want https://hanzo.id", path, d["issuer"])
		}
		if d["authorization_endpoint"] != "https://hanzo.id"+PathAuthorize {
			t.Errorf("%s: authorization_endpoint = %v", path, d["authorization_endpoint"])
		}
		if d["token_endpoint"] != "https://hanzo.id"+PathToken {
			t.Errorf("%s: token_endpoint = %v", path, d["token_endpoint"])
		}
		if d["userinfo_endpoint"] != "https://hanzo.id"+PathUserInfo {
			t.Errorf("%s: userinfo_endpoint = %v", path, d["userinfo_endpoint"])
		}
		if d["jwks_uri"] != "https://hanzo.id"+PathJWKS {
			t.Errorf("%s: jwks_uri = %v", path, d["jwks_uri"])
		}
		if !containsStr(d["code_challenge_methods_supported"], "S256") {
			t.Errorf("%s: S256 not advertised", path)
		}
		if containsStr(d["code_challenge_methods_supported"], "plain") {
			t.Errorf("%s: plain must never be advertised", path)
		}
		for _, alg := range []string{"RS256", "ES256", "MLDSA65"} {
			if !containsStr(d["id_token_signing_alg_values_supported"], alg) {
				t.Errorf("%s: signing alg %s not advertised", path, alg)
			}
		}
		for _, gt := range []string{"authorization_code", "refresh_token", "client_credentials"} {
			if !containsStr(d["grant_types_supported"], gt) {
				t.Errorf("%s: grant %s not advertised", path, gt)
			}
		}
	}
}

// The issuer NEVER follows X-Forwarded-Host: it is resolved from the TRUSTED
// request host (zip.Ctx.Host(), which ignores X-Forwarded-Host) through the pinned
// issuer resolver, so a client-supplied X-Forwarded-Host cannot steer `iss`. Here
// the trusted host is hanzo.id (formReqNoBody) and no issuer map is configured, so
// the spoofed header is discarded and the issuer stays host-relative to hanzo.id.
func TestDiscovery_IssuerIgnoresForwardedHost(t *testing.T) {
	app, _ := newServer(t)
	req := formReqNoBody("GET", PathDiscovery)
	req.Header.Set("X-Forwarded-Host", "id.example.test")
	resp, body := do(t, app, req)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if got := decode(t, body)["issuer"]; got != "https://hanzo.id" {
		t.Fatalf("issuer = %v, want https://hanzo.id (X-Forwarded-Host must not steer iss)", got)
	}
}

func containsStr(v any, want string) bool {
	list, ok := v.([]any)
	if !ok {
		return false
	}
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
