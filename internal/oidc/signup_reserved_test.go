// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"
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

// The lux.id flow, as hanzoai/universe declares lux-cloud: a PUBLIC (PKCE) client
// serving org lux, signup open, orgChoiceMode "create", and not shared — the seed
// states no isShared, which a new application reads as false. lux-tel and lux-app
// carry the same org and mode.
//
// Every account it registers WORKS in an org of its own. Filed in lux, as this
// application once did, every stranger was a member of one tenant — each could read
// the others' records on any surface that scopes by org. So each person lands in
// an org of their own, holds no membership in lux, and is a plain account that no
// request can make a SuperAdmin. A signup that names another standing org is
// refused: an application that is not shared serves its own org and no other.
func TestSignup_luxCloud_eachAccountFoundsItsOwnOrg(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{
		clientID:  "lux-cloud",
		secret:    "", // public / PKCE client
		org:       "lux",
		orgChoice: "create",
		signup:    true,
		redirects: []string{"https://lux.cloud/auth/callback"},
	})
	seedOrg(t, db, "lux")
	seedOrg(t, db, "acme")

	const pw = "correct horse battery staple"
	seen := map[string]bool{}
	for _, name := range []string{"pioneer", "settler"} {
		status, env := signupReq(t, app, map[string]string{
			"clientId":     "lux-cloud",
			"organization": "lux",
			"username":     name,
			"password":     pw,
			"email":        name + "@example.com",
		})
		if status != 200 || env["status"] != "ok" {
			t.Fatalf("lux.cloud signup %s: status=%d env=%v, want 200 ok", name, status, env)
		}
		data, _ := env["data"].(map[string]any)
		org, _ := data["owner"].(string)
		if org == "" || org == "lux" || seen[org] {
			t.Fatalf("%s landed in org %q; want an org of its own, not lux and not another account's", name, org)
		}
		seen[org] = true
		if policy.IsReservedOrg(org) {
			t.Fatalf("%s landed in a RESERVED org %q", name, org)
		}

		u, err := store.GetUserByName(context.Background(), db, org, name)
		if err != nil || u == nil {
			t.Fatalf("%s is not in the org its signup answered (%q): err=%v", name, org, err)
		}
		if in, _ := store.GetUserByName(context.Background(), db, "lux", name); in != nil {
			t.Fatalf("%s is still an account of org lux", name)
		}
		for _, ref := range store.MemberOrgRefs(context.Background(), db, u) {
			if ref.Org != org {
				t.Fatalf("%s's signed membership set carries %s", name, ref.Org)
			}
		}
		if super, err := store.IsSuperAdmin(context.Background(), db, u.Owner, u.Name); err != nil || super {
			t.Errorf("%s is a SuperAdmin (super=%v err=%v)", name, super, err)
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

	// acme is a customer's standing tenant. lux-cloud does not serve it, so a signup
	// naming it is refused with the same sentence as every other tenant refusal, and
	// acme gains no account.
	status, env := signupReq(t, app, map[string]string{
		"clientId":     "lux-cloud",
		"organization": "acme",
		"username":     "intruder",
		"password":     pw,
		"email":        "intruder@example.com",
	})
	if status == 200 && env["status"] == "ok" {
		t.Fatalf("a lux.cloud signup was admitted into acme: %v", env)
	}
	if msg, _ := env["msg"].(string); msg != "the user is not permitted to sign up to this application" {
		t.Fatalf("refusal message %q distinguishes this case from the other tenant refusals", msg)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "acme", "intruder"); u != nil {
		t.Fatalf("intruder now exists inside tenant acme")
	}
}
