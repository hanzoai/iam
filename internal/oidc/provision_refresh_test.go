// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// Provisioning moves its founder into the org they found, which re-keys their
// identity from <old>/<name> to <org>/<name>. The refresh token they signed in
// with names the old key; it must keep renewing, and the token it mints names
// the org they now live in, at the head of its `orgs`. A founder whose session died here was told their
// org was not created when it was.
func TestProvision_FounderKeepsRenewing(t *testing.T) {
	t.Setenv("IAM_SERVICE_TOKEN", "svc-secret-value")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	rt, _ := tok["refresh_token"].(string)
	if rt == "" {
		t.Fatalf("grant issued no refresh token: %v", tok)
	}

	req := httptest.NewRequest("POST", PathProvision, strings.NewReader(`{"owner":"hanzo","name":"alice","orgSlug":"acme"}`))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer svc-secret-value")
	if resp, body := do(t, app, req); resp.StatusCode != 200 {
		t.Fatalf("provision: %d %s", resp.StatusCode, body)
	}

	status, out := refresh(t, app, "pub", rt, nil)
	if status != 200 {
		t.Fatalf("refresh after the founder moved: %d %v, want 200", status, out)
	}
	at, _ := out["access_token"].(string)
	parts := strings.Split(at, ".")
	if len(parts) != 3 {
		t.Fatalf("access token is not a JWT: %q", at)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Name string `json:"name"`
		Orgs []struct {
			Org  string `json:"org"`
			Role string `json:"role"`
		} `json:"orgs"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		t.Fatal(err)
	}
	// The home org leads `orgs`; the founder lives in acme now.
	if claims.Name != "alice" || len(claims.Orgs) == 0 || claims.Orgs[0].Org != "acme" {
		t.Fatalf("renewed token names %s in %+v, want alice at home in acme", claims.Name, claims.Orgs)
	}
}
