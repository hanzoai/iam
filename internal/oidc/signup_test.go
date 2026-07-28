// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
)

// seedOrg creates an organization row (owner "admin", v1 convention) with the
// given name and optional password-complexity options.
func seedOrg(t *testing.T, db orm.DB, name string, passwordOptions ...string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner = "admin"
	o.Name = name
	o.PasswordOptions = passwordOptions
	o.SetId("admin/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
}

// signupReq drives POST /v1/iam/signup and returns the status + decoded envelope.
func signupReq(t *testing.T, app *zip.App, body map[string]string) (int, map[string]any) {
	t.Helper()
	resp, raw := do(t, app, jsonReq("POST", PathSignup, body))
	return resp.StatusCode, decode(t, raw)
}

// The happy path creates the account, returns it REDACTED (owner/name present,
// no secret), and stores the password as an argon2id hash — never plaintext.
func TestSignup_HappyPathCreatesRedactedUser(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	const pw = "correct horse battery staple"
	status, env := signupReq(t, app, map[string]string{
		"application":  "conf",
		"organization": "hanzo",
		"username":     "newbie",
		"password":     pw,
		"name":         "New Bie",
		"email":        "newbie@hanzo.ai",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("status=%d env=%v, want 200 ok", status, env)
	}
	data, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("data is not an object: %v", env["data"])
	}
	if data["owner"] != "hanzo" || data["name"] != "newbie" {
		t.Errorf("data owner/name = %v/%v, want hanzo/newbie", data["owner"], data["name"])
	}
	// The response must never carry the digest or any secret.
	for _, secret := range []string{"passwordHash", "passwordSalt", "accessSecret", "accessSecretHash"} {
		if v, present := data[secret]; present && v != "" {
			t.Errorf("signup response leaked %q = %v", secret, v)
		}
	}

	// The STORED row holds an argon2id hash (PasswordType=argon2id) that verifies the
	// password — and is NOT the plaintext. This is the no-plaintext contract.
	stored, err := store.GetUserByName(context.Background(), db, "hanzo", "newbie")
	if err != nil || stored == nil {
		t.Fatalf("stored user lookup: %v (nil=%v)", err, stored == nil)
	}
	if stored.PasswordHash == "" || stored.PasswordHash == pw {
		t.Fatalf("password stored as plaintext or empty: %q", stored.PasswordHash)
	}
	if stored.PasswordType != "argon2id" {
		t.Errorf("PasswordType = %q, want argon2id", stored.PasswordType)
	}
	if !users.VerifyPassword(stored, pw, "") {
		t.Error("stored hash does not verify the signup password")
	}
	if users.VerifyPassword(stored, "wrong", "") {
		t.Error("a wrong password verified — hashing is broken")
	}
}

// Every failure mode returns {status:"error"} on a 200 (the casibase envelope)
// and creates no user.
func TestSignup_Errors(t *testing.T) {
	newbieBody := func() map[string]string {
		return map[string]string{
			"application": "conf", "organization": "hanzo",
			"username": "newbie", "password": "correct horse battery staple",
		}
	}

	t.Run("missing required fields", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
		seedOrg(t, db, "hanzo")
		status, env := signupReq(t, app, map[string]string{"application": "conf", "organization": "hanzo"})
		if status != 200 || env["status"] != "error" {
			t.Fatalf("status=%d env=%v, want 200 error", status, env)
		}
	})

	t.Run("application does not exist", func(t *testing.T) {
		app, db := newServer(t)
		seedOrg(t, db, "hanzo")
		body := newbieBody()
		body["application"] = "ghost"
		_, env := signupReq(t, app, body)
		if env["status"] != "error" {
			t.Fatalf("want error, got %v", env)
		}
	})

	t.Run("signup disabled", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: false}) // EnableSignUp=false
		seedOrg(t, db, "hanzo")
		_, env := signupReq(t, app, newbieBody())
		if env["status"] != "error" {
			t.Fatalf("signup must be refused when disabled, got %v", env)
		}
		if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u != nil {
			t.Error("a user was created despite signup being disabled")
		}
	})

	t.Run("organization does not exist", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true}) // no org seeded
		_, env := signupReq(t, app, newbieBody())
		if env["status"] != "error" {
			t.Fatalf("want error for missing org, got %v", env)
		}
	})

	t.Run("username already taken", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
		seedOrg(t, db, "hanzo")
		seedUser(t, db, "newbie", "newbie@hanzo.ai", "pw") // already exists
		_, env := signupReq(t, app, newbieBody())
		if env["status"] != "error" || env["msg"] != "username already exists" {
			t.Fatalf("want 'username already exists', got %v", env)
		}
	})

	t.Run("username policy violated", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
		seedOrg(t, db, "hanzo")
		body := newbieBody()
		body["username"] = "1bad" // starts with a digit
		_, env := signupReq(t, app, body)
		if env["status"] != "error" {
			t.Fatalf("digit-leading username must be refused, got %v", env)
		}
	})

	// F-I2: a "/" in a username would inject a spurious owner/name separator into the
	// subject discriminator — forbidden at the door.
	t.Run("username with slash refused", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
		seedOrg(t, db, "hanzo")
		body := newbieBody()
		body["username"] = "foo/bar"
		_, env := signupReq(t, app, body)
		if env["status"] != "error" {
			t.Fatalf("username containing '/' must be refused, got %v", env)
		}
		if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "foo/bar"); u != nil {
			t.Error("a user with a '/' username was created")
		}
	})

	t.Run("password fails org complexity", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true})
		seedOrg(t, db, "hanzo", "AtLeast8") // require 8+ chars
		body := newbieBody()
		body["password"] = "short"
		_, env := signupReq(t, app, body)
		if env["status"] != "error" {
			t.Fatalf("short password must be refused under AtLeast8, got %v", env)
		}
		if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u != nil {
			t.Error("a user was created despite the password failing policy")
		}
	})
}

// ── self-serve organizations ─────────────────────────────────────────────────────

// The founder signs up and their org is minted with them. Before this, signup
// required the org to already exist, so "create a new account with a new
// organization" was impossible without an operator creating the org by hand.
func TestSignup_SelfServeOrgIsCreated(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})

	status, env := signupReq(t, app, map[string]string{
		"application":  "conf",
		"organization": "acme",
		"username":     "founder",
		"password":     "correct horse battery staple",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("self-serve signup: status=%d env=%v", status, env)
	}
	org, err := store.GetOrganizationByName(tctx(), db, "acme")
	if err != nil || org == nil {
		t.Fatalf("org acme should have been created: %v", err)
	}
	// Orgs live under "admin" — that is where org rows go and grants the ORG nothing.
	if org.Owner != "admin" {
		t.Fatalf("org owner = %q, want admin", org.Owner)
	}
	// The decisive property: authority is a property of the USER row, and authz
	// derives Super from user.Owner == "admin". The founder must belong to their OWN
	// org, so self-serve signup can never mint a SuperAdmin.
	u, err := store.GetUserByName(tctx(), db, "acme", "founder")
	if err != nil || u == nil {
		t.Fatalf("founder should exist in acme: %v", err)
	}
	if u.Owner != "acme" {
		t.Fatalf("founder owner = %q, want acme (owner 'admin' would be SuperAdmin)", u.Owner)
	}
}

// Self-serve creation is OPT-IN. An app that merely lets users choose among orgs,
// or names a single tenant, must not mint one.
func TestSignup_SelfServeOrgRefusedWithoutOptIn(t *testing.T) {
	for _, tc := range []struct{ name, mode string }{
		{"no org choice at all", ""},
		{"choice, but not create", "select"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: tc.mode})

			status, env := signupReq(t, app, map[string]string{
				"application":  "conf",
				"organization": "acme",
				"username":     "founder",
				"password":     "correct horse battery staple",
			})
			if status == 200 && env["status"] == "ok" {
				t.Fatalf("orgChoiceMode=%q must not mint an org", tc.mode)
			}
			if org, _ := store.GetOrganizationByName(tctx(), db, "acme"); org != nil {
				t.Fatal("no org may be created without the create opt-in")
			}
		})
	}
}

// THE privilege escalation to refuse: a user under "admin" is a SuperAdmin. Turning
// on self-serve creation must not open a path to minting the reserved org, and the
// refusal must hold even with the opt-in set.
func TestSignup_SelfServeCannotMintReservedOrg(t *testing.T) {
	for _, reserved := range []string{"admin", "built-in"} {
		t.Run(reserved, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})

			status, env := signupReq(t, app, map[string]string{
				"application":  "conf",
				"organization": reserved,
				"username":     "attacker",
				"password":     "correct horse battery staple",
			})
			if status == 200 && env["status"] == "ok" {
				t.Fatalf("signup into reserved org %q must be refused", reserved)
			}
			if u, _ := store.GetUserByName(tctx(), db, reserved, "attacker"); u != nil {
				t.Fatalf("no user may be created under reserved org %q", reserved)
			}
		})
	}
}

// The org name becomes the OWNER half of every (owner, name) key, so a name
// carrying the separator would be a key-injection surface.
func TestSignup_SelfServeOrgNamePolicy(t *testing.T) {
	for _, bad := range []string{"a", "1acme", "ac me", "ac/me"} {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
		status, env := signupReq(t, app, map[string]string{
			"application":  "conf",
			"organization": bad,
			"username":     "founder",
			"password":     "correct horse battery staple",
		})
		if status == 200 && env["status"] == "ok" {
			t.Fatalf("org name %q must be refused", bad)
		}
	}
}

// ── the password floor ───────────────────────────────────────────────────────
// An organization that declares NO PasswordOptions must still get a real policy.
// This is the hole that was live: store.CreateOrganization mints a self-serve org
// with an empty option set, an empty set used to mean "any non-empty password",
// and an anonymous caller registered a production account with the password "a"
// and then logged in with it.
func TestSignup_PasswordFloorAppliesWithoutOrgOptions(t *testing.T) {
	// Deliberately seeded with NO options — the self-serve org's shape.
	for _, weak := range []string{"a", "aaaaaaaa", "1234567", "short"} {
		t.Run(weak, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true})
			seedOrg(t, db, "hanzo")

			status, env := signupReq(t, app, map[string]string{
				"application": "conf", "organization": "hanzo",
				"username": "attacker", "password": weak,
			})
			if status == 200 && env["status"] == "ok" {
				t.Fatalf("password %q must be refused by the floor, got %v", weak, env)
			}
			if u, _ := store.GetUserByName(tctx(), db, "hanzo", "attacker"); u != nil {
				t.Fatalf("a user was created with the weak password %q", weak)
			}
		})
	}
}

// The floor must not cost the funnel: a strong password into an optionless org
// still succeeds. This is the case that must keep working.
func TestSignup_PasswordFloorAllowsStrongPassword(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	status, env := signupReq(t, app, map[string]string{
		"application": "conf", "organization": "hanzo",
		"username": "founder", "password": "correct horse battery staple",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("a strong password must still be accepted: status=%d env=%v", status, env)
	}
}

// The exact production attack, end to end: a self-serve signup into an org that
// does NOT exist, with the password "a". The org is minted with no options, so
// only the floor stands between an anonymous caller and the account. Neither the
// user nor a usable account may result.
func TestSignup_SelfServeOrgStillGetsPasswordFloor(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})

	status, env := signupReq(t, app, map[string]string{
		"application": "conf", "organization": "nonexistent-org-zz",
		"username": "probe-zz", "password": "a",
	})
	if status == 200 && env["status"] == "ok" {
		t.Fatalf("self-serve signup with password \"a\" must be refused, got %v", env)
	}
	if u, _ := store.GetUserByName(tctx(), db, "nonexistent-org-zz", "probe-zz"); u != nil {
		t.Fatal("the probe user was created despite the password floor")
	}
}

// TestOrgNamePolicyRefusesEmail pins that a signup cannot mint one org per human.
// A form that defaults the org field to the address just typed produced 56
// email-shaped orgs out of 124 on the live instance — nearly half the tenant
// registry was people. It is also the wrong money shape: account.Payer gives a
// member of the SIGNUP org a personal wallet, and minting them an org routes
// them down the org-pool branch instead.
func TestOrgNamePolicyRefusesEmail(t *testing.T) {
	for _, bad := range []string{"z@hanzo.ai", "qa_probe_x@hanzo-qa.dev", "a@b.co"} {
		if orgNamePolicyError(bad) == "" {
			t.Fatalf("orgNamePolicyError(%q) = \"\"; an email is never an organization", bad)
		}
	}
	// A real company name still creates a real org — this refuses a shape, not the intent.
	for _, ok := range []string{"acme", "wayne-enterprises", "hanzo"} {
		if msg := orgNamePolicyError(ok); msg != "" {
			t.Fatalf("orgNamePolicyError(%q) = %q; want \"\"", ok, msg)
		}
	}
}
