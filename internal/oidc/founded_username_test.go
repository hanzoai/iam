// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A self-service account lives in an org of its own and keeps its username there.
// A sign-in screen can only name the application's org, so the username has to
// reach the account through the org that registered it, exactly as the address
// does — otherwise the right password is refused as a wrong one, and the refusal
// never reaches the account's own lockout.

// founded signs each address up at a founding application, with its password, and
// returns the server, its store and the accounts as they were filed.
func founded(t *testing.T, accounts map[string]string) (*zip.App, orm.DB, map[string]*schema.User) {
	t.Helper()
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")
	out := map[string]*schema.User{}
	for addr, pw := range accounts {
		if _, env := signupReq(t, app, map[string]string{
			"application": "hanzo-cloud", "organization": "hanzo", "password": pw, "email": addr,
		}); env["status"] != "ok" {
			t.Fatalf("signup %s failed: %v", addr, env)
		}
		u, err := store.GetSignupByEmail(tctx(), db, "hanzo", addr)
		if err != nil || u == nil {
			t.Fatalf("account for %s is missing: %v", addr, err)
		}
		if u.Owner == "hanzo" {
			t.Fatalf("%s stayed in the registration org; a founding application moves it to its own", addr)
		}
		out[addr] = u
	}
	return app, db, out
}

// passwordSignin posts the sign-in form the hosted page and the SDK both send.
func passwordSignin(t *testing.T, app *zip.App, identifier, password string) map[string]any {
	t.Helper()
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": identifier, "password": password,
		"application": "hanzo-cloud", "clientId": "hanzo-cloud",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	return decode(t, body)
}

func wrongTimes(t *testing.T, db orm.DB, u *schema.User) int {
	t.Helper()
	fresh, err := store.GetUserByName(tctx(), db, u.Owner, u.Name)
	if err != nil || fresh == nil {
		t.Fatalf("read %s/%s: %v", u.Owner, u.Name, err)
	}
	return fresh.SigninWrongTimes
}

func TestFoundedAccountSignsInWithItsUsername(t *testing.T) {
	const addr, pw = "named@example.com", "correct horse battery staple"
	app, db, accounts := founded(t, map[string]string{addr: pw})
	u := accounts[addr]

	m := passwordSignin(t, app, u.Name, pw)
	if m["status"] != "ok" {
		t.Fatalf("the username and the right password were refused: %v", m)
	}
	if c, _ := m["data"].(string); c == "" {
		t.Fatal("no authorization code was minted")
	}

	// A wrong password named by the username is counted against the account, as
	// one named by the address is.
	if m := passwordSignin(t, app, u.Name, "not the password"); m["msg"] != "the username or password is incorrect" {
		t.Fatalf("a wrong password answered %v", m)
	}
	if n := wrongTimes(t, db, u); n != 1 {
		t.Fatalf("signinWrongTimes = %d after one wrong password, want 1", n)
	}
}

// The second person whose address yields a name already held by one of the org's
// registrations gets the next free one, as they would in the org itself, so each
// signs in by their own username.
func TestFoundedAccountsGetUsernamesOfTheirOwn(t *testing.T) {
	const one, two = "ada@one.example", "ada@two.example"
	app, _, accounts := founded(t, map[string]string{one: "first passphrase here"})
	if accounts[one].Name != "ada" {
		t.Fatalf("first account is %q, want ada", accounts[one].Name)
	}
	if _, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo", "password": "second passphrase here", "email": two,
	}); env["status"] != "ok" {
		t.Fatalf("second signup failed: %v", env)
	}
	// A caller that names a username one of the org's registrations holds is refused.
	if _, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo", "password": "third passphrase here",
		"email": "third@three.example", "username": "ada",
	}); env["msg"] != "username already exists" {
		t.Fatalf("a held username was handed out again: %v", env)
	}
	for name, pw := range map[string]string{"ada": "first passphrase here", "ada2": "second passphrase here"} {
		if m := passwordSignin(t, app, name, pw); m["status"] != "ok" {
			t.Fatalf("%s does not sign in with its own username: %v", name, m)
		}
	}
}

// A name two of the org's registrations already hold signs neither in and counts
// against neither, and each still signs in with its address.
func TestFoundedAccountsSharingAUsernameSignInByAddress(t *testing.T) {
	const one, two = "ada@one.example", "grace@two.example"
	app, db, accounts := founded(t, map[string]string{one: "first passphrase here", two: "second passphrase here"})
	a, b := accounts[one], accounts[two]
	// The second row is given the first's name directly, the shape of rows written
	// before names were unique across a registration org.
	dup := orm.New[schema.User](db)
	fresh, err := store.GetUserByName(tctx(), db, b.Owner, b.Name)
	if err != nil || fresh == nil {
		t.Fatalf("read %s/%s: %v", b.Owner, b.Name, err)
	}
	*dup = *fresh
	dup.Model = orm.New[schema.User](db).Model
	dup.Name = a.Name
	dup.SetId(b.Owner + "/" + a.Name)
	if err := dup.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed duplicate: %v", err)
	}
	if err := fresh.DeleteCtx(tctx()); err != nil {
		t.Fatalf("drop original: %v", err)
	}
	b = dup

	if m := passwordSignin(t, app, a.Name, "first passphrase here"); m["msg"] != "the username or password is incorrect" {
		t.Fatalf("a username two accounts hold signed somebody in: %v", m)
	}
	if wrongTimes(t, db, a) != 0 || wrongTimes(t, db, b) != 0 {
		t.Fatal("a username two accounts hold was counted against one of them")
	}
	for addr, pw := range map[string]string{one: "first passphrase here", two: "second passphrase here"} {
		if m := passwordSignin(t, app, addr, pw); m["status"] != "ok" {
			t.Fatalf("%s no longer signs in with its address: %v", addr, m)
		}
	}
}

// registeredAt writes an account an application registered, in an org of its own.
func registeredAt(t *testing.T, db orm.DB, application, org, name, pw string) {
	t.Helper()
	seedUserInOrg(t, db, org, name, name+"@"+org+".example", pw)
	u, err := store.GetUserByName(tctx(), db, org, name)
	if err != nil || u == nil {
		t.Fatalf("read %s/%s: %v", org, name, err)
	}
	u.SignupApplication = application
	if err := u.UpdateCtx(tctx()); err != nil {
		t.Fatalf("register %s/%s: %v", org, name, err)
	}
}

// A shared application serves the people its org admitted by membership. A
// registration holding a member's name never outranks the member, and a name no
// member holds still reaches the one registration that holds it.
func TestSharedAppRosterOutranksARegisteredName(t *testing.T) {
	db, login := memberApp(t)
	registeredAt(t, db, "client-patrol", "solo", "josh", "pw-solo")
	registeredAt(t, db, "client-patrol", "kim", "kim", "pw-kim")

	if m := login("client", "josh", "pw-josh"); !minted(m) {
		t.Fatalf("the member josh lost his username to a registration: %v", m)
	}
	if m := login("client", "josh", "pw-solo"); minted(m) {
		t.Fatalf("a registration holding a member's name signed in as it: %v", m)
	}
	if m := login("client", "kim", "pw-kim"); !minted(m) {
		t.Fatalf("a registration the shared app's org made does not sign in by name: %v", m)
	}
}
