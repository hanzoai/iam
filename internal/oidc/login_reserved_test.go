// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"testing"
)

// F-D2 login tail (F-D1): the reserved-org gate at the login mint tail. signup.go and
// the ROPC grant already refuse a reserved-org principal; login.go was the one door
// that omitted it. A SuperAdmin (org "admin") may sign in ONLY through an application
// that itself SERVES the admin org — never a shared / org-choice app reaching across
// tenants, which would otherwise mint a real SuperAdmin authorization code on the
// correct admin password. These prove the refuse is present AND precise.

// A SHARED app (its tenant gate accepts a user from ANY org) must NOT mint a grant for
// a reserved-org principal, even with fully valid admin credentials.
func TestLogin_reservedOrg_refusedThroughSharedApp(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "shared-portal", secret: "s3cret", org: "hanzo", shared: true, redirects: []string{testRedirect}})
	seedOrg(t, db, "admin")
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "correct horse") // the SuperAdmin

	f := map[string]string{
		"organization": "admin", "username": "root", "password": "correct horse",
		"clientId": "shared-portal", "redirectUri": testRedirect, "scope": "openid", "type": "code",
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, f))
	m := decode(t, body)
	if m["status"] != "error" {
		t.Fatalf("a shared app minted a grant for a SuperAdmin — reserved-org gate missing: %v", m)
	}
	if code, _ := m["data"].(string); code != "" {
		t.Fatalf("no code may be minted for a reserved-org principal via a shared app; got %q", code)
	}
}

// An ORG-CHOICE app (OrgChoiceMode set) also bypasses the same-org tenant gate — the
// reserved org is still refused.
func TestLogin_reservedOrg_refusedThroughOrgChoiceApp(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "choice-portal", secret: "s3cret", org: "hanzo", orgChoice: "user", redirects: []string{testRedirect}})
	seedOrg(t, db, "admin")
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "correct horse")

	f := map[string]string{
		"organization": "admin", "username": "root", "password": "correct horse",
		"clientId": "choice-portal", "redirectUri": testRedirect, "scope": "openid", "type": "code",
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, f))
	m := decode(t, body)
	if m["status"] != "error" {
		t.Fatalf("an org-choice app minted a grant for a SuperAdmin — reserved-org gate missing: %v", m)
	}
	if code, _ := m["data"].(string); code != "" {
		t.Fatalf("no code may be minted for a reserved-org principal via an org-choice app; got %q", code)
	}
}

// The DEDICATED admin-console app (Organization == "admin") MUST still sign the
// SuperAdmin in — proof the gate is precise (a reserved-org refuse, not an admin
// lockout that would break the console).
func TestLogin_reservedOrg_adminConsoleAllowed(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "admin-console", secret: "s3cret", org: "admin", redirects: []string{testRedirect}})
	seedOrg(t, db, "admin")
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "correct horse")

	f := map[string]string{
		"organization": "admin", "username": "root", "password": "correct horse",
		"clientId": "admin-console", "redirectUri": testRedirect, "scope": "openid", "type": "code",
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, f))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("the dedicated admin-console app must sign the SuperAdmin in; got %v", m)
	}
	if code, _ := m["data"].(string); code == "" {
		t.Fatal("admin-console login should mint a code for the SuperAdmin")
	}
}
