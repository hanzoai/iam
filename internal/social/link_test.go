// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package social_test

import (
	"testing"

	"github.com/hanzoai/iam2/internal/schema"
)

// The link law from the legitimate side: the two keys that DO select an
// account, and the sign-up that happens when neither does.

// user builds an account row.
func user(name, email string, verified bool) schema.User {
	return schema.User{
		Owner: "hanzo", Name: name, Email: email, EmailVerified: verified,
		Type: "normal-user", SignupApplication: "console",
	}
}

func TestLinkByVerifiedEmail(t *testing.T) {
	// Key (b): both sides assert the address, and the application enables email
	// linking. This is the ONLY way an email selects an account.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{link: true, signup: true, canSignIn: true, canSignUp: true})
	seedUser(t, db, user("z", "z@hanzo.ai", true))

	up.user = github(999, "zeekay", "Z", "")
	up.emails = []map[string]any{{"email": "z@hanzo.ai", "primary": true, "verified": true}}
	resp, _ := signin(t, app, "provider-github")

	if sub := subjectOf(t, db, issued(t, resp)); sub != "hanzo/z" {
		t.Fatalf("want a code for hanzo/z, got %q", sub)
	}
	if v := getUser(t, db, "hanzo", "z"); v.Github != "999" {
		t.Fatalf("want the subject linked onto the account, got GitHub=%q", v.Github)
	}
	if n := countUsers(t, db, "hanzo"); n != 1 {
		t.Fatalf("want the existing account reused, got %d accounts", n)
	}
}

func TestLinkByEmailOffCreatesAccount(t *testing.T) {
	// Same identity, EnableLinkWithEmail off: the address selects nothing.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{link: false, signup: true, canSignIn: true, canSignUp: true})
	seedUser(t, db, user("z", "z@hanzo.ai", true))

	up.user = github(999, "zeekay", "Z", "")
	up.emails = []map[string]any{{"email": "z@hanzo.ai", "primary": true, "verified": true}}
	resp, _ := signin(t, app, "provider-github")

	if sub := subjectOf(t, db, issued(t, resp)); sub == "hanzo/z" {
		t.Fatalf("email linking is off, yet the address selected %s", sub)
	}
	if n := countUsers(t, db, "hanzo"); n != 2 {
		t.Fatalf("want a second account, got %d", n)
	}
	if v := getUser(t, db, "hanzo", "z"); v.Github != "" {
		t.Fatalf("the existing account was linked anyway: %q", v.Github)
	}
}

func TestRelinkBySubject(t *testing.T) {
	// Key (a): the second sign-in resolves by the subject already on file — one
	// account, not two, and no email involved.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})

	up.user = github(999, "zeekay", "Z", "z@hanzo.ai")
	if sub := subjectOf(t, db, issued(t, first(signin(t, app, "provider-github")))); sub != "hanzo/zeekay" {
		t.Fatalf("first sign-in: want hanzo/zeekay, got %q", sub)
	}
	if sub := subjectOf(t, db, issued(t, first(signin(t, app, "provider-github")))); sub != "hanzo/zeekay" {
		t.Fatalf("second sign-in: want the SAME account, got %q", sub)
	}
	if n := countUsers(t, db, "hanzo"); n != 1 {
		t.Fatalf("want one account across two sign-ins, got %d", n)
	}
}

func TestSignupShape(t *testing.T) {
	// The account a new identity gets: the provider's verdict on the address is
	// carried through verbatim (never a blanket true), no password digest is
	// set, and the provenance fields match v1's.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})

	up.user = github(999, "zeekay", "Zach", "")
	up.emails = nil // /user/emails unreadable → the noreply identifier, unverified
	signin(t, app, "provider-github")

	u := getUser(t, db, "hanzo", "zeekay")
	if u == nil {
		t.Fatal("no account was created")
	}
	if u.EmailVerified {
		t.Fatal("the noreply identifier is not a verified address, yet the account says it is")
	}
	if u.Email != "999+zeekay@users.noreply.github.com" {
		t.Fatalf("want the canonical noreply identifier, got %q", u.Email)
	}
	if u.PasswordHash != "" {
		t.Fatalf("a social account must carry no password digest, got %q", u.PasswordHash)
	}
	if u.Github != "999" || u.Type != "normal-user" ||
		u.SignupApplication != "console" || u.RegisterType != "Application Signup" {
		t.Fatalf("provenance: %+v", *u)
	}
}

func TestSignupRefusedWhenDisabled(t *testing.T) {
	for _, tc := range []struct {
		name string
		s    seed
	}{
		{"app", seed{signup: false, canSignIn: true, canSignUp: true}},
		{"provider", seed{signup: true, canSignIn: true, canSignUp: false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			up := newUpstream(t)
			seedAll(t, db, up, tc.s)
			up.user = github(999, "zeekay", "Z", "z@hanzo.ai")
			resp, _ := signin(t, app, "provider-github")
			if code := issued(t, resp); code != "" {
				t.Fatalf("sign-up is disabled, yet a code was issued for %s", subjectOf(t, db, code))
			}
			if n := countUsers(t, db, "hanzo"); n != 0 {
				t.Fatalf("sign-up is disabled, yet %d account(s) exist", n)
			}
		})
	}
}

func TestSignupNameCollisionSuffixes(t *testing.T) {
	// A taken name is suffixed, never merged onto: the collision is exactly the
	// takeover v1 performs, so the two accounts must stay two accounts.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true})
	seedUser(t, db, user("zeekay", "z@hanzo.ai", true))

	up.user = github(999, "zeekay", "Impostor", "other@evil.com")
	resp, _ := signin(t, app, "provider-github")

	sub := subjectOf(t, db, issued(t, resp))
	if sub == "hanzo/zeekay" {
		t.Fatal("the taken name was reused, selecting the existing account")
	}
	if sub == "" {
		t.Fatal("no code was issued")
	}
	if n := countUsers(t, db, "hanzo"); n != 2 {
		t.Fatalf("want two distinct accounts, got %d", n)
	}
	if v := getUser(t, db, "hanzo", "zeekay"); v.Github != "" {
		t.Fatalf("the original account was linked: %q", v.Github)
	}
}

func TestGitlabWritesItsOwnColumn(t *testing.T) {
	// The capital-L trap: the provider TYPE is "GitLab", the user column is
	// `Gitlab`. v1 reads the column by reflecting the type and gets an invalid
	// value back for every GitLab account. The link must land on the column, and
	// resolving by it must find the account again.
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{kind: "GitLab", signup: true, canSignIn: true, canSignUp: true})

	up.user = map[string]any{
		"id": 42, "username": "zeekay", "name": "Z", "email": "z@gitlab.com",
		"confirmed_at": "2026-01-01T00:00:00Z",
	}
	signin(t, app, "provider-gitlab")

	u := getUser(t, db, "hanzo", "zeekay")
	if u == nil || u.Gitlab != "42" {
		t.Fatalf("want the subject on the Gitlab column, got %+v", u)
	}
	if u.Github != "" || u.Google != "" {
		t.Fatalf("the subject leaked onto another connector's column: %+v", u)
	}
	// Second hop: resolving by that column must find the same account.
	if sub := subjectOf(t, db, issued(t, first(signin(t, app, "provider-gitlab")))); sub != "hanzo/zeekay" {
		t.Fatalf("GitLab re-sign-in: want hanzo/zeekay, got %q", sub)
	}
	if n := countUsers(t, db, "hanzo"); n != 1 {
		t.Fatalf("want one account, got %d", n)
	}
}

func TestTenantIsFromTheApplication(t *testing.T) {
	// The account lands in the APPLICATION's organization, whatever the query
	// says (HIP-0111 Invariant 3).
	app, db := newServer(t)
	up := newUpstream(t)
	seedAll(t, db, up, seed{signup: true, canSignIn: true, canSignUp: true, org: "hanzo"})

	up.user = github(999, "zeekay", "Z", "z@hanzo.ai")
	state := hop(t, app, "provider_hint=provider-github&organization=admin&owner=admin")
	resp, _ := land(t, app, state, "upstream-code")

	if sub := subjectOf(t, db, issued(t, resp)); sub != "hanzo/zeekay" {
		t.Fatalf("want the app's org, got %q", sub)
	}
	if n := countUsers(t, db, "admin"); n != 0 {
		t.Fatalf("the query named another tenant and %d account(s) landed there", n)
	}
}

// first drops the body from a (resp, body) pair.
func first[A any, B any](a A, _ B) A { return a }
