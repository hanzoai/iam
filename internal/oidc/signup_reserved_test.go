// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// fullApp gives a test full control over the signup-relevant application fields the
// shared harness seedApp fixes (it hardcodes Organization "hanzo" and exposes only
// IsShared/EnableSignUp). Owner is "admin" (platform-owned, the iam convention);
// clientId == Name (the <org>-<app> convention the mint allow-lists key on).
type fullApp struct {
	clientID  string
	secret    string // "" → public (PKCE) client
	org       string // the tenant the app SERVES (Application.Organization)
	orgChoice string // OrgChoiceMode: non-empty lets a signup pick its org
	signup    bool
	shared    bool
	redirects []string
}

func seedAppFull(t *testing.T, db orm.DB, a fullApp) {
	t.Helper()
	seedRSACert(t, db, "cert-"+a.clientID)
	app := orm.New[schema.Application](db)
	app.Owner = "admin"
	app.Name = a.clientID
	app.ClientId = a.clientID
	app.ClientSecret = a.secret
	app.Organization = a.org
	app.Cert = "cert-" + a.clientID
	app.EnablePassword = true
	app.EnableSignUp = a.signup
	app.IsShared = a.shared
	app.OrgChoiceMode = a.orgChoice
	app.ExpireInHours = 1
	app.RedirectUris = a.redirects
	app.SetId("admin/" + a.clientID)
	if err := app.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app %s: %v", a.clientID, err)
	}
}

// INVARIANT 1 — No admin-org self-signup. A signup can never resolve to a reserved
// system org (admin/built-in/app); a user under "admin" is a SuperAdmin (authz
// derives Super from owner == "admin"). This must hold through EVERY app shape that
// could otherwise admit the org — a SHARED app and an ORG-CHOICE app both bypass the
// same-org tenant gate, so both are the escalation vector the reserved-org refuse closes.
func TestSignup_reservedOrg_refusedThroughSharedApp(t *testing.T) {
	for _, reserved := range []string{"admin", "built-in", "app"} {
		t.Run(reserved, func(t *testing.T) {
			app, db := newServer(t)
			// A SHARED signup app: its tenant gate admits a user into ANY org, so only the
			// reserved-org refuse stops an escalation into the reserved org.
			seedAppFull(t, db, fullApp{clientID: "shared-portal", secret: "s3cret", org: "hanzo", shared: true, signup: true})
			seedOrg(t, db, reserved) // the reserved org EXISTS — prove the refuse is not "org missing"

			status, env := signupReq(t, app, map[string]string{
				"application":  "shared-portal",
				"organization": reserved,
				"username":     "eve",
				"password":     "correct horse battery staple",
				"email":        "eve@evil.example",
			})
			if status != 400 || env["status"] != "error" {
				t.Fatalf("signup into reserved org %q: status=%d env=%v, want 400 error", reserved, status, env)
			}
			// The escalation is prevented: NO user row exists under the reserved org.
			if u, _ := store.GetUserByName(context.Background(), db, reserved, "eve"); u != nil {
				t.Fatalf("a user was created under reserved org %q — SuperAdmin/system escalation", reserved)
			}
		})
	}
}

// The same shared app that refused the reserved orgs MUST still admit a legitimate
// tenant — proof the refuse is precise (the reserved-org guard, not a broken app).
func TestSignup_sharedApp_admitsLegitimateTenant(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "shared-portal", secret: "s3cret", org: "hanzo", shared: true, signup: true})
	seedOrg(t, db, "acme")

	status, env := signupReq(t, app, map[string]string{
		"application":  "shared-portal",
		"organization": "acme",
		"username":     "alice",
		"password":     "correct horse battery staple",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("legitimate shared-app signup: status=%d env=%v, want 200 ok", status, env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "acme", "alice"); u == nil {
		t.Fatal("legitimate tenant signup created no user — the guard is over-broad")
	}
}

// The most DIRECT escalation: an app that itself SERVES the admin org (Organization
// = "admin") with signup enabled. Here the same-org tenant gate PASSES
// (organization == app.Organization == "admin"), so before the fix a signup minted a
// SuperAdmin. The reserved-org refuse closes it independent of the app's own org.
func TestSignup_adminOrgApp_cannotMintSuperAdmin(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "admin-console", secret: "s3cret", org: "admin", signup: true})
	seedOrg(t, db, "admin")

	status, env := signupReq(t, app, map[string]string{
		"application":  "admin-console",
		"organization": "admin",
		"username":     "eve",
		"password":     "correct horse battery staple",
	})
	if status != 400 || env["status"] != "error" {
		t.Fatalf("admin-org-app signup into admin: status=%d env=%v, want 400 error", status, env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "admin", "eve"); u != nil {
		t.Fatal("a SuperAdmin was minted via an admin-org signup app — invariant 1 breached")
	}
}

// An ORG-CHOICE app (OrgChoiceMode set) lets a signup name its own org, another
// route past the same-org gate — the reserved org is still refused.
func TestSignup_orgChoiceApp_reservedOrgRefused(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "choice-portal", secret: "s3cret", org: "hanzo", orgChoice: "user", signup: true})
	seedOrg(t, db, "admin")

	status, env := signupReq(t, app, map[string]string{
		"application":  "choice-portal",
		"organization": "admin",
		"username":     "eve",
		"password":     "correct horse battery staple",
	})
	if status != 400 || env["status"] != "error" {
		t.Fatalf("org-choice signup into admin: status=%d env=%v, want 400 error", status, env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "admin", "eve"); u != nil {
		t.Fatal("a SuperAdmin was minted via an org-choice signup app — invariant 1 breached")
	}
}

// No oracle (invariant 4): the reserved-org refuse and the wrong-tenant refuse return
// the BYTE-IDENTICAL message, so a prober cannot distinguish "reserved org" from
// "wrong tenant" (which would reveal that the named org is a system org).
func TestSignup_reservedOrgRefuse_noOracle(t *testing.T) {
	app, db := newServer(t)
	// A NON-shared, non-choice app serving "hanzo": a foreign tenant is refused by the
	// tenant gate; a reserved org is refused by the reserved-org gate. Same message.
	seedAppFull(t, db, fullApp{clientID: "conf", secret: "s3cret", org: "hanzo", signup: true})
	seedOrg(t, db, "admin")
	seedOrg(t, db, "acme")

	_, reservedEnv := signupReq(t, app, map[string]string{
		"application": "conf", "organization": "admin", "username": "eve", "password": "correct horse battery staple",
	})
	_, tenantEnv := signupReq(t, app, map[string]string{
		"application": "conf", "organization": "acme", "username": "eve", "password": "correct horse battery staple",
	})
	if reservedEnv["msg"] != tenantEnv["msg"] || reservedEnv["msg"] == "" {
		t.Fatalf("reserved-org refuse must be indistinguishable from wrong-tenant refuse: reserved=%q tenant=%q",
			reservedEnv["msg"], tenantEnv["msg"])
	}
}

// SIGNUP-READINESS (STEP 4) — the lux.cloud flow. A `lux-cloud` PUBLIC (PKCE) OIDC
// client, redirect https://lux.cloud/auth/callback, self-registration enabled,
// serving the `lux` org, must create a PLAIN non-admin user in `lux` (never admin):
// Owner=lux, Type=normal-user, IsAdmin=false, EmailVerified=false, password
// argon2id-hashed. This is exactly what opens lux.cloud signup.
func TestSignup_luxCloud_createsPlainNonAdminUser(t *testing.T) {
	app, db := newServer(t)
	// A PUBLIC client: no client secret (PKCE), redirect to lux.cloud, signup enabled.
	seedAppFull(t, db, fullApp{
		clientID:  "lux-cloud",
		secret:    "", // public / PKCE client
		org:       "lux",
		signup:    true,
		redirects: []string{"https://lux.cloud/auth/callback"},
	})
	seedOrg(t, db, "lux")

	const pw = "correct horse battery staple"
	status, env := signupReq(t, app, map[string]string{
		"clientId":     "lux-cloud",
		"organization": "lux",
		"username":     "pioneer",
		"password":     pw,
		"email":        "pioneer@lux.network",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("lux.cloud signup: status=%d env=%v, want 200 ok", status, env)
	}

	u, err := store.GetUserByName(context.Background(), db, "lux", "pioneer")
	if err != nil || u == nil {
		t.Fatalf("lux.cloud signup created no user: err=%v", err)
	}
	if u.Owner != "lux" {
		t.Errorf("owner = %q, want lux (a signup must land in the served tenant, never admin)", u.Owner)
	}
	if store.IsReservedOrg(u.Owner) {
		t.Errorf("lux.cloud user landed in a RESERVED org %q", u.Owner)
	}
	if u.IsAdmin {
		t.Error("lux.cloud signup produced an admin user — must be a PLAIN user")
	}
	// Now a stronger claim than it used to be: not anchored in the reserved org,
	// AND holding no membership there — a signup can mint neither.
	if super, err := store.IsSuperAdmin(context.Background(), db, u.Owner, u.Name); err != nil || super {
		t.Errorf("lux.cloud signup produced a SuperAdmin — must be a PLAIN user (super=%v err=%v)", super, err)
	}
	if u.Type != "normal-user" {
		t.Errorf("type = %q, want normal-user", u.Type)
	}
	if u.EmailVerified {
		t.Error("EmailVerified must be false on a fresh signup (not client-assertable)")
	}
	if u.PasswordType != "argon2id" || u.PasswordHash == "" || u.PasswordHash == pw {
		t.Errorf("password not argon2id-hashed: type=%q hashEmptyOrPlain=%v", u.PasswordType, u.PasswordHash == "" || u.PasswordHash == pw)
	}
}
