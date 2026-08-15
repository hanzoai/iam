// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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

// The dedicated admin console does not take a password either.
//
// This asserted the opposite until the reserved org became passkey-only: it was
// the proof that confinement refused the reserved org through OTHER applications
// while leaving its OWN console working. Confinement is still exactly that
// precise — it is [store.PasskeyOwed] that now closes the console too, and it
// closes it for the credential rather than for the application. What used to make
// this pair legal (a reserved-org principal at the app that serves the reserved
// org) is still legal; what is refused is the password.
//
// The precision the old assertion protected has not been lost, it has moved:
// TestAnOrdinaryAccountStillSignsInWithItsPassword is now the proof that this is a
// rule about operators and not a broken login. This becomes true again, in its
// original form, when a passkey can be asserted — the sign-in will carry one and
// the console will mint.
func TestLogin_reservedOrg_adminConsoleTakesNoPassword(t *testing.T) {
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
	if m["status"] != "error" || m["msg"] != PasskeyOnly {
		t.Fatalf("the admin console must refuse a password and say which credential is owed; got %v", m)
	}
	if code, _ := m["data"].(string); code != "" {
		t.Fatalf("the admin console minted a code for a password: %q", code)
	}
}
