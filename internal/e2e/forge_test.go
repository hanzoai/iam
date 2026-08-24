// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package e2e_test

// The privilege-escalation chain a tenant admin could once run — point an app at
// the platform signing cert, plant a token whose subject is admin/root, redeem its
// refresh for a bearer signed as admin/root — driven end to end through the real
// router and refused at every writable step.
//
// The refresh grant is deliberately NOT owner-pinned to the subject: a shared
// platform application legitimately signs a TENANT user's refresh with the platform
// cert (the console login every brand runs), so pinning the subject's org to the
// app's org would refuse that real flow. It does not need the pin, because the two
// preconditions a forged signature requires — an application that resolves the
// platform signing cert, and a token row whose subject is admin/root — are each
// refused to a non-super, which is what this drives. The signing app is resolved
// from the token row's own owner, and a non-super can write neither a row under the
// admin owner nor an app that names the platform cert.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"testing"
)

func sha256hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func TestForge_refusedAtEveryStep(t *testing.T) {
	e := boot(t)
	seedUser(t, e.db, "hanzo", "boss", "boss@hanzo.ai", "pw", true) // org-admin, never super
	boss := e.mint(t, "hanzo/boss")

	// Step 1 — an application that names the platform signing cert is refused, so no
	// non-super application can ever sign with the key admin/root's bearer carries.
	if st, body := e.req(t, "POST", "/v1/iam/applications", boss,
		`{"owner":"hanzo","name":"forge","organization":"hanzo","clientId":"forge","cert":"cert-hanzo"}`,
		"application/json"); st != 403 {
		t.Fatalf("step 1 (app names cert-hanzo): status=%d, want 403; body=%s", st, body)
	}

	// Step 2 — a token row whose subject is admin/root, carrying the refresh hash of
	// a secret the attacker knows, is refused.
	refresh := "known-refresh-secret"
	plant := `{"owner":"hanzo","name":"forge","application":"hanzo-console","user":"admin/root",` +
		`"refreshTokenHash":"` + sha256hex(refresh) + `","publicGrant":true,"scope":"openid"}`
	if st, body := e.req(t, "POST", "/v1/iam/tokens", boss, plant, "application/json"); st != 403 {
		t.Fatalf("step 2 (token subject admin/root): status=%d, want 403; body=%s", st, body)
	}

	// Step 3 — the refresh grant that would have signed sub=admin/root finds no row
	// to redeem: the plant never landed.
	tok := e.token(t, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refresh},
	})
	if tok["access_token"] != nil {
		t.Fatalf("a forged refresh minted a token: %v", tok)
	}
	if tok["error"] != "invalid_grant" {
		t.Fatalf("refresh error = %v, want invalid_grant", tok["error"])
	}
}

// The legitimate flow the missing pin protects: a first-party console mints a
// refresh (offline_access) and redeems it for a fresh access token whose subject is
// unchanged — proving the refresh path itself still works end to end.
func TestForge_legitimateRefreshStillWorks(t *testing.T) {
	e := boot(t)

	verifier := "e2e-verifier-0000000000000000000000000000000000000"
	code := e.login(t, verifier)
	tok := e.token(t, url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
		"client_id": {"hanzo-console"}, "client_secret": {"top-secret"},
		"redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
	refresh, _ := tok["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("offline_access minted no refresh token: %v", tok)
	}

	next := e.token(t, url.Values{
		"grant_type": {"refresh_token"}, "refresh_token": {refresh},
		"client_id": {"hanzo-console"}, "client_secret": {"top-secret"},
	})
	if s, _ := next["access_token"].(string); s == "" {
		t.Fatalf("a legitimate refresh minted no access token: %v", next)
	}
}
