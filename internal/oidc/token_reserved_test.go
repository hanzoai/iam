// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"net/url"
	"testing"
)

// INVARIANT 5 (defense in depth) — an app that SERVES a reserved system org
// (admin/built-in/app) must never obtain a token on the PUBLIC token endpoint, on
// either machine grant. Even though such a token already resolves to no authority
// (its subject "admin/<app>" has no user row, so authz grants it nothing), the
// public endpoint refuses it at the door so the property is STRUCTURAL, not a
// consequence of the principal resolver. Credentials are otherwise VALID here — the
// refusal is the reserved-Organization gate, not an auth failure.
func TestClientCredentials_reservedOrgApp_refused(t *testing.T) {
	for _, org := range []string{"admin", "built-in", "app"} {
		t.Run(org, func(t *testing.T) {
			app, db := newServer(t)
			seedAppFull(t, db, fullApp{clientID: "svc-" + org, secret: "svc-secret", org: org})

			resp, tok := postToken(t, app, url.Values{
				"grant_type":    {"client_credentials"},
				"client_id":     {"svc-" + org},
				"client_secret": {"svc-secret"}, // the CORRECT secret — refusal is the org gate
				"scope":         {"read"},
			})
			requireError(t, resp, tok, 401, "invalid_client")
			if tok["access_token"] != nil {
				t.Fatalf("a reserved-org (%s) app minted a client_credentials token: %v", org, tok)
			}
		})
	}
}

func TestPasswordGrant_reservedOrgApp_refused(t *testing.T) {
	for _, org := range []string{"admin", "built-in"} {
		t.Run(org, func(t *testing.T) {
			app, db := newServer(t)
			seedAppFull(t, db, fullApp{clientID: "console-" + org, secret: "top-secret", org: org})

			resp, tok := postToken(t, app, url.Values{
				"grant_type":    {"password"},
				"client_id":     {"console-" + org},
				"client_secret": {"top-secret"}, // the CORRECT secret — refusal is the org gate
				"username":      {"whoever"},
				"password":      {"whatever"},
			})
			requireError(t, resp, tok, 401, "invalid_client")
			if tok["access_token"] != nil {
				t.Fatalf("a reserved-org (%s) app minted a password-grant token: %v", org, tok)
			}
		})
	}
}

// Contrast/regression: a normal TENANT-serving app (Organization "hanzo") is NOT
// refused by the reserved-org gate — the machine grant still works. This proves the
// gate is precise and did not break legitimate client_credentials.
func TestClientCredentials_tenantOrgApp_stillWorks(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "svc-hanzo", secret: "svc-secret", org: "hanzo"})

	resp, tok := postToken(t, app, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"svc-hanzo"},
		"client_secret": {"svc-secret"},
		"scope":         {"read"},
	})
	if resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("tenant-org client_credentials should succeed: status=%d body=%v", resp.StatusCode, tok)
	}
}
