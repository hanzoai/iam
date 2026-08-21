// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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

// The gate on the REQUESTED organization — a different gate from the one above,
// and the one passwordGrant's F-D2 comment describes.
//
// TestPasswordGrant_reservedOrgApp_refused refuses on the APP's own org and dies
// at 401 invalid_client before any organization parameter is read, so it never
// reaches this one. Measured: with `policy.IsReservedOrg(org)` replaced by
// `false`, every test in this package still passed.
//
// The target must EXIST here, with the RIGHT password. The gate answers the same
// opaque `invalid_grant` a wrong credential gets — deliberately, so it is no
// org-existence oracle — so against a user who is not there, a missing gate and a
// working one produce the identical 400 and a test proves nothing. This is the
// request that mints a real SuperAdmin token if the gate goes: a public console
// posting organization=admin, resolving admin/<super>, on the correct password.
func TestPasswordGrant_reservedOrgRequested_refused(t *testing.T) {
	for _, org := range []string{"admin", "built-in", "app"} {
		t.Run(org, func(t *testing.T) {
			app, db := newServer(t)
			// An ordinary tenant client that may serve any org it is asked for,
			// so nothing but the reserved gate can refuse this.
			seedAppFull(t, db, fullApp{clientID: "zoo-console", secret: "top-secret", org: "zoo", shared: true})
			seedUserInOrg(t, db, org, "z", "z@hanzo.ai", "correct horse")

			resp, tok := postToken(t, app, url.Values{
				"grant_type":    {"password"},
				"client_id":     {"zoo-console"},
				"client_secret": {"top-secret"}, // correct: the refusal is the org gate
				"organization":  {org},
				"username":      {"z"},
				"password":      {"correct horse"}, // correct: likewise
			})
			requireError(t, resp, tok, 400, "invalid_grant")
			if tok["access_token"] != nil {
				t.Fatalf("organization=%s minted a token: %v", org, tok)
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
