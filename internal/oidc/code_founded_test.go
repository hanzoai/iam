// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/store"
)

// A code is delivered to an ADDRESS and spent by an ACCOUNT, and the account a
// founding application registered works in an org of its own. The send resolves
// that account through its registration and the spend reads the account's own
// org, so the record has to be filed where the account lives — filed under the
// application's org, the code a person was sent could never be spent, and a
// self-service account could neither sign in with a code nor recover a forgotten
// password.

// foundedAccount signs someone up at a founding application that offers code
// sign-in, with a sender bound, and returns the server, its store and the sender.
func foundedAccount(t *testing.T, addr, pw string) (*zip.App, orm.DB, *fakeSender) {
	t.Helper()
	sent := &fakeSender{}
	bindSender(t, sent)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, codeSignin: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")
	if _, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo", "password": pw, "email": addr,
	}); env["status"] != "ok" {
		t.Fatalf("signup failed: %v", env)
	}
	return app, db, sent
}

// sentCode asks the send endpoint for a code to addr and returns the code the
// person would read.
func sentCode(t *testing.T, app *zip.App, sent *fakeSender, addr string) string {
	t.Helper()
	if status, env := sendCode(t, app, map[string]string{
		"dest": addr, "type": "email", "applicationId": "admin/hanzo-cloud",
	}); status != 200 || env["status"] != "ok" {
		t.Fatalf("send a code to %s: status=%d env=%v", addr, status, env)
	}
	if len(sent.sent) == 0 {
		t.Fatal("nothing was delivered")
	}
	return codeIn(t, sent.sent[len(sent.sent)-1].Body)
}

func TestFoundedAccountRecoversItsPasswordWithACode(t *testing.T) {
	const addr = "forgetful@example.com"
	app, _, sent := foundedAccount(t, addr, "correct horse battery staple")

	code := sentCode(t, app, sent, addr)
	status, env := putPassword(t, app, "", `{"organization":"hanzo","username":"`+addr+`",`+
		`"code":"`+code+`","password":"a brand new passphrase"}`)
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("a self-service account could not recover its password: status=%d env=%v", status, env)
	}

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": addr, "password": "a brand new passphrase",
		"application": "hanzo-cloud", "clientId": "hanzo-cloud",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	if m := decode(t, body); m["status"] != "ok" {
		t.Fatalf("the new password does not sign in: %v", m)
	}
}

func TestFoundedAccountSignsInWithACode(t *testing.T) {
	const addr = "codey@example.com"
	app, _, sent := foundedAccount(t, addr, "correct horse battery staple")

	code := sentCode(t, app, sent, addr)
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": addr, "code": code,
		"application": "hanzo-cloud", "clientId": "hanzo-cloud",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("a self-service account could not sign in with the code it was sent: %v", m)
	}
	if c, _ := m["data"].(string); c == "" {
		t.Fatal("no authorization code was minted")
	}
}

// An address is proven where IAM watched it receive a code. A signup that carries
// the code sent to its address records the address proven; a reset that spends a
// code sent to the account's address proves it too, and replaces the only
// password anybody holds in the same write. Everywhere else an address stays a
// claim — the federation broker will not link a social identity onto a row whose
// password was set by somebody who never proved the address.

func TestSignup_TheCodeSentToTheAddressProvesIt(t *testing.T) {
	sent := &fakeSender{}
	bindSender(t, sent)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	const addr = "proven@example.com"
	code := sentCode(t, app, sent, addr)
	if _, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo",
		"password": "correct horse battery staple", "email": addr, "code": code,
	}); env["status"] != "ok" {
		t.Fatalf("signup with the code it was sent failed: %v", env)
	}
	u, err := store.GetSignupByEmail(tctx(), db, "hanzo", addr)
	if err != nil || u == nil {
		t.Fatalf("the account is missing: %v", err)
	}
	if !u.EmailVerified {
		t.Fatal("the code sent to the address did not prove it")
	}
}

func TestSignup_AWrongCodeCreatesNothing(t *testing.T) {
	sent := &fakeSender{}
	bindSender(t, sent)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	const addr = "guess@example.com"
	sentCode(t, app, sent, addr)
	_, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo",
		"password": "correct horse battery staple", "email": addr, "code": "000000",
	})
	if msg, _ := env["msg"].(string); env["status"] != "error" || msg != "the code is incorrect or has expired" {
		t.Fatalf("a wrong code was not refused: %v", env)
	}
	if u, _ := store.GetSignupByEmail(tctx(), db, "hanzo", addr); u != nil {
		t.Fatal("an account was created on a wrong code")
	}
	if org, _ := store.GetOrganizationByName(tctx(), db, "guess"); org != nil {
		t.Fatal("an org was founded on a wrong code")
	}
}

func TestResetByCodeProvesTheAddress(t *testing.T) {
	const addr = "unproven@example.com"
	app, db, sent := foundedAccount(t, addr, "correct horse battery staple")

	if u, _ := store.GetSignupByEmail(tctx(), db, "hanzo", addr); u == nil || u.EmailVerified {
		t.Fatalf("premise: a password signup with no code is unproven, got %v", u)
	}
	code := sentCode(t, app, sent, addr)
	if status, env := putPassword(t, app, "", `{"organization":"hanzo","username":"`+addr+`",`+
		`"code":"`+code+`","password":"a brand new passphrase"}`); status != 200 || env["status"] != "ok" {
		t.Fatalf("reset failed: status=%d env=%v", status, env)
	}
	u, _ := store.GetSignupByEmail(tctx(), db, "hanzo", addr)
	if u == nil || !u.EmailVerified {
		t.Fatalf("a reset by the code sent to the address did not prove it: %v", u)
	}
}
