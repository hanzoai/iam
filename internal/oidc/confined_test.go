// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/pkce"
	"github.com/hanzoai/iam/pkg/store"
)

// A row stored shared before the rule, in the admin org, signs no tenant in:
// not a brand user by the password, and not an admin-org member found through
// its roster.
func TestConfined_StoredSharedAdminAppAdmitsNoTenant(t *testing.T) {
	app, db := newServer(t)
	legacy := seedApp(t, db, appOpts{clientID: "admin-console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	legacy.Organization, legacy.IsShared = "admin", true
	if err := legacy.Put(); err != nil { // past the hook, as a row stored before it
		t.Fatalf("store the legacy row: %v", err)
	}
	seedUserInOrg(t, db, "hanzo", "alice", "alice@hanzo.ai", "pw")
	if _, err := store.EnsureMembership(tctx(), db, "hanzo/alice", "admin", store.RoleAdmin); err != nil {
		t.Fatalf("grant the admin-org membership: %v", err)
	}

	verifier := "verifier-confined-legacy-0123456789012345678901234567"
	q := url.Values{
		"clientId": {"admin-console"}, "redirectUri": {testRedirect}, "scope": {"openid"},
		"code_challenge": {pkce.Challenge(verifier)}, "code_challenge_method": {"S256"},
	}
	for _, org := range []string{"hanzo", "admin"} {
		_, body := do(t, app, jsonReq("POST", PathLogin+"?"+q.Encode(), map[string]any{
			"type": "code", "application": "admin-console",
			"organization": org, "username": "alice", "password": "pw",
		}))
		env := decode(t, body)
		if code, _ := env["data"].(string); env["status"] != "error" || code != "" {
			t.Fatalf("organization %s: a tenant signed in through a shared admin app: %s", org, body)
		}
	}
}
