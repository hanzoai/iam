// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"fmt"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/store"
)

// PUT /v1/iam/password is the whole of self-service recovery and rotation, so
// these are the properties a person's account hangs on: a locked-out person gets
// back in with a code and no operator, a signed-in person cannot rotate without
// the password being replaced, and neither arm can be pointed at somebody else.

// putPassword drives the endpoint with a raw JSON body (and an optional session
// cookie), so a test can express a body the typed shape would tidy up.
func putPassword(t *testing.T, app *zip.App, cookie, body string) (int, map[string]any) {
	t.Helper()
	req := httptest.NewRequest("PUT", PathPassword, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Host = "hanzo.id"
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, raw := do(t, app, req)
	return resp.StatusCode, decode(t, raw)
}

// recoveryServer seeds the one shape every recovery test needs: an app that can
// send codes, an org, and hanzo/alice with a known password.
func recoveryServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	bindSender(t, &fakeSender{})
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedOrg(t, db, "hanzo")
	seedUser(t, db, "alice", "alice@hanzo.ai", "old correct horse")
	return app, db
}

// deliveredCode drives the real send endpoint and returns the code the person
// would have received.
func deliveredCode(t *testing.T, app *zip.App, db orm.DB, dest, typ string) string {
	t.Helper()
	if status, env := sendCode(t, app, map[string]string{
		"dest": dest, "type": typ, "applicationId": "admin/conf",
	}); status != 200 || env["status"] != "ok" {
		t.Fatalf("send a code to %s: status=%d env=%v", dest, status, env)
	}
	rec, err := store.GetLatestVerificationRecord(context.Background(), db, "hanzo", dest)
	if err != nil || rec == nil {
		t.Fatalf("the send persisted no code for %s: %v", dest, err)
	}
	return rec.Code
}

// signInWith reports what POST /v1/iam/login says about a password: whether it
// was accepted, and the refusal message when it was not.
func signInWith(t *testing.T, app *zip.App, password string) (bool, string) {
	t.Helper()
	resp, raw := do(t, app, formReq("POST", PathLogin, url.Values{
		"organization": {"hanzo"}, "application": {"conf"},
		"username": {"alice"}, "password": {password}, "type": {"login"},
	}))
	env := decode(t, raw)
	msg, _ := env["msg"].(string)
	return resp.StatusCode == 200 && env["status"] == "ok", msg
}

// THE PATH: a locked-out person gets back in, with no operator.
//
// Five wrong passwords lock the account for fifteen minutes. A code delivered to
// the address on file sets a new password, and the new password works
// IMMEDIATELY — the lockout is cleared by the same transaction that writes the
// digest, because replacing a credential retires the run of guesses against the
// old one. Without that clear, a person who had just chosen a new password was
// still refused with it for up to fifteen more minutes.
func TestLockedOutPersonRecoversWithACode(t *testing.T) {
	app, db := recoveryServer(t)
	ctx := context.Background()

	for i := 0; i < users.LockThreshold; i++ {
		if ok, _ := signInWith(t, app, "wrong"); ok {
			t.Fatal("a wrong password signed in")
		}
	}
	if ok, msg := signInWith(t, app, "old correct horse"); ok || msg == "" {
		t.Fatalf("the account should be locked: ok=%v msg=%q", ok, msg)
	}

	code := deliveredCode(t, app, db, "alice@hanzo.ai", "email")
	status, env := putPassword(t, app, "", `{"organization":"hanzo","username":"alice@hanzo.ai",`+
		`"code":"`+code+`","password":"new correct horse"}`)
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("the reset was refused: status=%d env=%v", status, env)
	}

	// The counter is genuinely clear on the row, not merely bypassed once. Read
	// before any further sign-in, since a wrong password would start a fresh run.
	u, _ := store.GetUserByName(ctx, db, "hanzo", "alice")
	if u.SigninWrongTimes != 0 || u.LastSigninWrongTime != "" {
		t.Errorf("lockout survived the reset: wrongTimes=%d lastWrong=%q",
			u.SigninWrongTimes, u.LastSigninWrongTime)
	}
	if ok, msg := signInWith(t, app, "new correct horse"); !ok {
		t.Fatalf("the brand-new password was refused: %q", msg)
	}
	if ok, _ := signInWith(t, app, "old correct horse"); ok {
		t.Error("the replaced password still signs in")
	}
}

// The code is one-time here too: a replay after the reset lands changes nothing.
func TestResetSpendsTheCodeOnce(t *testing.T) {
	app, db := recoveryServer(t)
	code := deliveredCode(t, app, db, "alice@hanzo.ai", "email")
	reset := func(pw string) (int, map[string]any) {
		return putPassword(t, app, "", fmt.Sprintf(
			`{"organization":"hanzo","username":"alice@hanzo.ai","code":%q,"password":%q}`, code, pw))
	}

	if status, env := reset("first new password"); status != 200 || env["status"] != "ok" {
		t.Fatalf("the first reset was refused: status=%d env=%v", status, env)
	}
	if status, env := reset("second new password"); status == 200 && env["status"] == "ok" {
		t.Fatal("a replayed code reset the password a second time")
	}
	if ok, msg := signInWith(t, app, "first new password"); !ok {
		t.Fatalf("the replay overwrote the password the person actually set: %q", msg)
	}
}

// A code minted for one account must not reset another, even inside one org and
// even for an address that reaches both rows. The stamp on the record is what
// decides, not the identifier on the request.
func TestResetRefusesACodeMintedForAnotherAccount(t *testing.T) {
	app, db := recoveryServer(t)
	ctx := context.Background()
	seedUser(t, db, "bob", "bob@hanzo.ai", "bob's password")

	code := deliveredCode(t, app, db, "bob@hanzo.ai", "email")
	// Bob's code, Alice's identifier — and Alice's own address, so nothing but the
	// binding stands in the way.
	status, env := putPassword(t, app, "", `{"organization":"hanzo","username":"alice@hanzo.ai",`+
		`"code":"`+code+`","password":"stolen account"}`)
	if status == 200 && env["status"] == "ok" {
		t.Fatal("another account's code reset this one")
	}
	if msg, _ := env["msg"].(string); msg != errPasswordCode {
		t.Errorf("msg = %q, want the one opaque refusal %q", msg, errPasswordCode)
	}
	u, _ := store.GetUserByName(ctx, db, "hanzo", "alice")
	if users.VerifyPassword(u, "stolen account", "") {
		t.Error("the digest was replaced anyway")
	}
}

// A signed-in rotation needs the password being replaced. A live session is not
// enough: a stolen session would otherwise become a permanent account takeover.
func TestRotationNeedsTheCurrentPassword(t *testing.T) {
	app, db := recoveryServer(t)
	ctx := context.Background()
	cookie := sessionFor(t, app, "old correct horse")

	if status, env := putPassword(t, app, cookie,
		`{"oldPassword":"not it","password":"new correct horse"}`); status == 200 && env["status"] == "ok" {
		t.Fatal("a wrong current password rotated the credential")
	}
	u, _ := store.GetUserByName(ctx, db, "hanzo", "alice")
	if users.VerifyPassword(u, "new correct horse", "") {
		t.Fatal("the digest moved on a refused rotation")
	}

	if status, env := putPassword(t, app, cookie,
		`{"oldPassword":"old correct horse","password":"new correct horse"}`); status != 200 || env["status"] != "ok" {
		t.Fatalf("a correct rotation was refused: status=%d env=%v", status, env)
	}
	if ok, msg := signInWith(t, app, "new correct horse"); !ok {
		t.Fatalf("the rotated password does not sign in: %q", msg)
	}
}

// The rotation arm is SELF-SCOPED: the subject is the caller, and a body naming
// somebody else changes nothing about whose row is written. This is the shape that
// keeps the endpoint from being the escalation internal/authz's GET-only self
// clause exists to prevent.
func TestRotationIgnoresAnAccountNamedInTheBody(t *testing.T) {
	app, db := recoveryServer(t)
	ctx := context.Background()
	seedUser(t, db, "bob", "bob@hanzo.ai", "bob's password")
	cookie := sessionFor(t, app, "old correct horse")

	if status, env := putPassword(t, app, cookie,
		`{"organization":"hanzo","username":"bob","oldPassword":"old correct horse","password":"alice wrote this"}`,
	); status != 200 || env["status"] != "ok" {
		t.Fatalf("the rotation was refused: status=%d env=%v", status, env)
	}
	bob, _ := store.GetUserByName(ctx, db, "hanzo", "bob")
	if users.VerifyPassword(bob, "alice wrote this", "") {
		t.Fatal("alice wrote bob's password by naming him in the body")
	}
	if !users.VerifyPassword(bob, "bob's password", "") {
		t.Fatal("bob's credential was disturbed")
	}
	alice, _ := store.GetUserByName(ctx, db, "hanzo", "alice")
	if !users.VerifyPassword(alice, "alice wrote this", "") {
		t.Fatal("the caller's own password was not the one written")
	}
}

// Without a session there is nothing to rotate against, and the answer says so in
// a form the portal routes on rather than reading a sentence.
func TestRotationWithoutASessionIsRefused(t *testing.T) {
	app, _ := recoveryServer(t)
	status, env := putPassword(t, app, "",
		`{"organization":"hanzo","username":"alice","oldPassword":"old correct horse","password":"new correct horse"}`)
	if status == 200 && env["status"] == "ok" {
		t.Fatal("an unauthenticated caller rotated a password by naming the account")
	}
	if env["code"] != CodeLoginRequired {
		t.Errorf("code = %v, want %q", env["code"], CodeLoginRequired)
	}
}

// One proof, never two and never none. A request carrying both proves nothing
// more than either, and answering it would mean deciding which one mattered.
func TestExactlyOneProofIsAccepted(t *testing.T) {
	app, db := recoveryServer(t)
	code := deliveredCode(t, app, db, "alice@hanzo.ai", "email")
	for name, body := range map[string]string{
		"both": `{"organization":"hanzo","username":"alice@hanzo.ai","code":"` + code +
			`","oldPassword":"old correct horse","password":"new correct horse"}`,
		"neither":     `{"organization":"hanzo","username":"alice@hanzo.ai","password":"new correct horse"}`,
		"no password": `{"organization":"hanzo","username":"alice@hanzo.ai","code":"` + code + `"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if status, env := putPassword(t, app, "", body); status == 200 && env["status"] == "ok" {
				t.Fatalf("accepted: %s", body)
			}
		})
	}
}

// A password that could not have been REGISTERED must not be reachable by
// resetting either — same rule, same function, so the two cannot drift.
func TestResetEnforcesThePasswordPolicy(t *testing.T) {
	bindSender(t, &fakeSender{})
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedOrg(t, db, "hanzo", "Aa123", "SpecialChar")
	seedUser(t, db, "alice", "alice@hanzo.ai", "old correct horse")
	ctx := context.Background()

	code := deliveredCode(t, app, db, "alice@hanzo.ai", "email")
	for name, pw := range map[string]string{
		"under the platform floor":  "short",
		"missing the org's classes": "all lowercase letters",
	} {
		t.Run(name, func(t *testing.T) {
			status, env := putPassword(t, app, "", `{"organization":"hanzo","username":"alice@hanzo.ai",`+
				`"code":"`+code+`","password":"`+pw+`"}`)
			if status == 200 && env["status"] == "ok" {
				t.Fatalf("%q was accepted", pw)
			}
			u, _ := store.GetUserByName(ctx, db, "hanzo", "alice")
			if users.VerifyPassword(u, pw, "") {
				t.Fatal("the refused password was written anyway")
			}
		})
	}
}

// A texted code is redeemed against the account's canonical number however the
// person retypes it, so recovery by SMS does not hinge on reproducing their own
// punctuation.
func TestRecoveryByTextAcceptsEitherSpelling(t *testing.T) {
	bindSender(t, &fakeSender{})
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedOrg(t, db, "hanzo")
	seedPhoneUser(t, db, "carol", "+14155550134")
	ctx := context.Background()

	code := deliveredCode(t, app, db, "+14155550134", "phone")
	status, env := putPassword(t, app, "", `{"organization":"hanzo","username":"+1 (415) 555-0134",`+
		`"code":"`+code+`","password":"new correct horse"}`)
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("a texted recovery was refused: status=%d env=%v", status, env)
	}
	u, _ := store.GetUserByName(ctx, db, "hanzo", "carol")
	if !users.VerifyPassword(u, "new correct horse", "") {
		t.Fatal("the new password was not written")
	}
}

// With nothing able to deliver, no code can have been sent, so the code arm
// refuses — the same precondition codeLogin holds, for the same reason.
func TestCodeResetRefusedWithNoDelivery(t *testing.T) {
	app, db := recoveryServer(t)
	code := deliveredCode(t, app, db, "alice@hanzo.ai", "email")
	bindSender(t, nil)

	if status, env := putPassword(t, app, "", `{"organization":"hanzo","username":"alice@hanzo.ai",`+
		`"code":"`+code+`","password":"new correct horse"}`); status == 200 && env["status"] == "ok" {
		t.Fatal("a code was trusted by a process that cannot send one")
	}
}

// sessionFor signs hanzo/alice in with an explicit password and returns the
// session cookie. sessionCookieFor hardcodes "pw", which the recovery tests
// deliberately do not use — the password they replace has to be one they chose.
func sessionFor(t *testing.T, app *zip.App, password string) string {
	t.Helper()
	resp, body := do(t, app, formReq("POST", PathLogin, url.Values{
		"organization": {"hanzo"}, "application": {"conf"},
		"username": {"alice"}, "password": {password}, "type": {"login"},
	}))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("sign in for a session: %s", body)
	}
	return cookieKV(resp.Header.Get("Set-Cookie"))
}
