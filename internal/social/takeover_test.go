// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package social_test

import (
	"testing"
)

// The link law, from the attacker's side. Each case below is an account
// takeover that v1 performs today (controllers/auth.go:1063-1090): an attacker
// who controls a third-party account whose username, email or phone happens to
// equal a victim's signs in AS the victim. Every case asserts on the STORE and
// on WHO the minted code names — a redirect alone proves nothing, because the
// takeover also redirects.

// github returns a GitHub identity body for the fake upstream.
func github(id int, login, name, email string) map[string]any {
	return map[string]any{"id": id, "login": login, "name": name, "email": email}
}

func TestTakeoverByUsername(t *testing.T) {
	// v1: `if user == nil && userInfo.Username != "" { user = GetUserByFields(org, userInfo.Username) }`
	// — auth.go:1084-1090, outside every gate. An attacker registers the GitHub
	// login "z" and signs in as the Hanzo user "z".
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{link: true, signup: true, canSignIn: true, canSignUp: true})
	seedUser(t, db, user("z", "z@hanzo.ai", true))

	up.user = github(999, "z", "Not The Victim", "attacker@evil.com")
	resp, _ := signin(t, app, "provider-github")

	code := issued(t, resp)
	if sub := subjectOf(t, db, code); sub == "hanzo/z" {
		t.Fatalf("TAKEOVER: a GitHub login equal to a username signed in as %s", sub)
	}
	if v := getUser(t, db, "hanzo", "z"); v.Github != "" {
		t.Fatalf("TAKEOVER: the victim's account was linked to the attacker's subject %q", v.Github)
	}
	if n := countUsers(t, db, "hanzo"); n != 2 {
		t.Fatalf("want a new account created alongside the victim, got %d accounts", n)
	}
}

func TestTakeoverByUsernameMatchingEmail(t *testing.T) {
	// v1's GetUserByFields tries name, THEN email, THEN phone
	// (object/user_util.go:163-200), so a GitHub LOGIN equal to a victim's
	// EMAIL selects the victim too — with no verification anywhere.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{link: true, signup: true, canSignIn: true, canSignUp: true})
	seedUser(t, db, user("z", "z@hanzo.ai", true))

	up.user = github(999, "z@hanzo.ai", "Not The Victim", "attacker@evil.com")
	resp, _ := signin(t, app, "provider-github")

	if sub := subjectOf(t, db, issued(t, resp)); sub == "hanzo/z" {
		t.Fatalf("TAKEOVER: a GitHub login equal to a victim's email signed in as %s", sub)
	}
	if v := getUser(t, db, "hanzo", "z"); v.Github != "" {
		t.Fatalf("TAKEOVER: the victim's account was linked to %q", v.Github)
	}
}

func TestTakeoverByUnverifiedEmail(t *testing.T) {
	// The provider does NOT assert the address. v1 never asks
	// (auth.go:1063-1070), so a provider that lets an account claim an
	// unverified address hands over every account with that address.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{kind: "GitLab", link: true, signup: true, canSignIn: true, canSignUp: true})
	seedUser(t, db, user("z", "z@hanzo.ai", true))

	// GitLab with no confirmed_at: the address is unconfirmed.
	up.user = map[string]any{"id": 999, "username": "attacker", "name": "A", "email": "z@hanzo.ai"}
	resp, _ := signin(t, app, "provider-gitlab")

	if sub := subjectOf(t, db, issued(t, resp)); sub == "hanzo/z" {
		t.Fatalf("TAKEOVER: an UNVERIFIED provider email signed in as %s", sub)
	}
	if v := getUser(t, db, "hanzo", "z"); v.Gitlab != "" {
		t.Fatalf("TAKEOVER: the victim's account was linked to %q", v.Gitlab)
	}
}

func TestTakeoverByLocallyUnverifiedEmail(t *testing.T) {
	// The pre-registration squat: the attacker registers victim@x with a
	// password of their choosing, leaving it unverified. If a provider-verified
	// address may link onto an unverified local row, the real owner's first
	// social sign-in hands the account to the attacker, password and all.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{link: true, signup: true, canSignIn: true, canSignUp: true})
	squat := user("squatter", "z@hanzo.ai", false) // local row NOT verified
	squat.PasswordHash = "$2a$10$attackerchosen"
	seedUser(t, db, squat)

	up.user = github(999, "realz", "Real Z", "z@hanzo.ai")
	up.emails = []map[string]any{{"email": "z@hanzo.ai", "primary": true, "verified": true}}
	resp, _ := signin(t, app, "provider-github")

	if sub := subjectOf(t, db, issued(t, resp)); sub == "hanzo/squatter" {
		t.Fatalf("SQUAT: a verified provider email linked onto an unverified local row as %s", sub)
	}
	if s := getUser(t, db, "hanzo", "squatter"); s.Github != "" {
		t.Fatalf("SQUAT: the squatted row was linked to %q", s.Github)
	}
}

func TestTakeoverByPhone(t *testing.T) {
	// v1 links by phone as well (auth.go:1072-1079). A phone is provider-side
	// data the attacker controls, so it can never select an account.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{kind: "Google", link: true, signup: true, canSignIn: true, canSignUp: true})
	v := user("z", "z@hanzo.ai", true)
	v.Phone = "+14155551234"
	seedUser(t, db, v)

	up.user = map[string]any{
		"id": "999", "email": "attacker@evil.com", "verified_email": true,
		"name": "A", "phone": "+14155551234",
	}
	resp, _ := signin(t, app, "provider-google")

	if sub := subjectOf(t, db, issued(t, resp)); sub == "hanzo/z" {
		t.Fatalf("TAKEOVER: a phone collision signed in as %s", sub)
	}
	if got := getUser(t, db, "hanzo", "z"); got.Google != "" {
		t.Fatalf("TAKEOVER: the victim's account was linked to %q", got.Google)
	}
}

func TestTakeoverIntoReservedOrg(t *testing.T) {
	// A new account in the reserved "admin" org IS a SuperAdmin (internal/authz:
	// Super ⟺ Org == "admin"). Any org admin may register an application, and an
	// application names the organization it signs users into — so sign-up must
	// refuse a reserved organization outright, or one GitHub sign-in through an
	// attacker-registered app is platform sudo.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{
		link: true, signup: true, canSignIn: true, canSignUp: true,
		org: "evil", appOrg: "admin", // the app claims the reserved org
	})

	up.user = github(999, "attacker", "A", "attacker@evil.com")
	resp, _ := signin(t, app, "provider-github")

	if code := issued(t, resp); code != "" {
		t.Fatalf("ESCALATION: sign-up into the reserved admin org issued %q for %s",
			code, subjectOf(t, db, code))
	}
	if n := countUsers(t, db, "admin"); n != 0 {
		t.Fatalf("ESCALATION: %d account(s) were minted into the reserved admin org", n)
	}
}
