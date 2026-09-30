// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"io"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/store"
)

// A code sent to an address no account holds proves the address and nothing else.
// Sign-in then answers SignupRequired; the account is made only by a second
// request that carries the accepted terms.

func codeSignupServer(t *testing.T, signup bool) (*zip.App, orm.DB, *fakeSender) {
	t.Helper()
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: signup, codeSignin: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")
	sent := &fakeSender{}
	bindSender(t, sent)
	return app, db, sent
}

func codeLoginReq(t *testing.T, app *zip.App, addr, code string, extra map[string]any) map[string]any {
	t.Helper()
	body := map[string]any{
		"organization": "hanzo", "username": addr, "code": code,
		"application": "hanzo-cloud", "clientId": "hanzo-cloud",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}
	for k, v := range extra {
		body[k] = v
	}
	_, raw := do(t, app, jsonReq("POST", PathLogin, body))
	return decode(t, raw)
}

var accepted = map[string]any{"create": true, "terms": "2026-09", "aup": "2026-09"}

func TestCodeSignup_NewAddressIsToldSignupRequiredAndNothingIsMade(t *testing.T) {
	const addr = "new@example.com"
	app, db, sent := codeSignupServer(t, true)
	code := sentCode(t, app, sent, addr)

	m := codeLoginReq(t, app, addr, code, nil)
	if m["status"] != "ok" || m["data"] != SignupRequired {
		t.Fatalf("want ok/%s, got %v", SignupRequired, m)
	}
	if u, _ := store.GetSignupByEmail(tctx(), db, "hanzo", addr); u != nil {
		t.Fatal("an account was made before the person accepted anything")
	}
	// The code was not spent: the create that follows uses the same one.
	if m := codeLoginReq(t, app, addr, code, accepted); m["status"] != "ok" {
		t.Fatalf("the code was spent by the probe: %v", m)
	}
}

func TestCodeSignup_CreateMakesAPasswordlessAccountAndGrants(t *testing.T) {
	const addr = "grace@example.com"
	app, db, sent := codeSignupServer(t, true)
	code := sentCode(t, app, sent, addr)

	m := codeLoginReq(t, app, addr, code, accepted)
	if g, _ := m["data"].(string); m["status"] != "ok" || g == "" || g == SignupRequired {
		t.Fatalf("no grant was minted: %v", m)
	}
	u, err := store.GetSignupByEmail(tctx(), db, "hanzo", addr)
	if err != nil || u == nil {
		t.Fatalf("the account is missing: %v", err)
	}
	// IsAdmin is the founder of their own org, the rule provisionFederatedUser
	// follows; SuperAdmin is owner == "admin" and is never reached.
	if u.PasswordHash != "" || !u.EmailVerified || u.Owner == "admin" {
		t.Fatalf("wrong shape: hash=%q verified=%v owner=%s", u.PasswordHash, u.EmailVerified, u.Owner)
	}
	tm, ok := u.TermsAccepted()
	if !ok || tm.Terms != "2026-09" || tm.AUP != "2026-09" || tm.Method != methodEmailCode || tm.Time == "" {
		t.Fatalf("acceptance not recorded: %+v ok=%v", tm, ok)
	}
	// One use: the same code cannot make or sign in anything again.
	if m := codeLoginReq(t, app, addr, code, nil); m["status"] != "error" {
		t.Fatalf("a spent code was honoured: %v", m)
	}
}

func TestCodeSignup_CreateNeedsTheAcceptedTerms(t *testing.T) {
	const addr = "hasty@example.com"
	app, db, sent := codeSignupServer(t, true)
	code := sentCode(t, app, sent, addr)

	m := codeLoginReq(t, app, addr, code, map[string]any{"create": true})
	if m["status"] != "error" {
		t.Fatalf("an account was offered without terms: %v", m)
	}
	if u, _ := store.GetSignupByEmail(tctx(), db, "hanzo", addr); u != nil {
		t.Fatal("an account was made without terms")
	}
	if m := codeLoginReq(t, app, addr, code, accepted); m["status"] != "ok" {
		t.Fatalf("the refused attempt cost the person the code: %v", m)
	}
}

func TestCodeSignup_WrongCodeIsTheOpaqueRefusal(t *testing.T) {
	const addr = "guess@example.com"
	app, db, sent := codeSignupServer(t, true)
	sentCode(t, app, sent, addr)

	for _, extra := range []map[string]any{nil, accepted} {
		m := codeLoginReq(t, app, addr, "000000", extra)
		if msg, _ := m["msg"].(string); m["status"] != "error" || msg != "the code is incorrect or has expired" {
			t.Fatalf("a wrong code was not refused opaquely: %v", m)
		}
	}
	if u, _ := store.GetSignupByEmail(tctx(), db, "hanzo", addr); u != nil {
		t.Fatal("an account was made on a wrong code")
	}
}

func TestCodeSignup_ExistingAccountSignsInAsBefore(t *testing.T) {
	const addr = "ada@example.com"
	app, db, sent := codeSignupServer(t, true)
	seedUserInOrg(t, db, "hanzo", "ada", addr, "correct horse battery staple")
	code := sentCode(t, app, sent, addr)

	m := codeLoginReq(t, app, addr, code, accepted)
	if g, _ := m["data"].(string); m["status"] != "ok" || g == "" || g == SignupRequired {
		t.Fatalf("an existing account did not sign in: %v", m)
	}
	u, _ := store.GetUserByName(tctx(), db, "hanzo", "ada")
	if _, ok := u.TermsAccepted(); ok {
		t.Fatal("signing in recorded an acceptance it never asked for")
	}
}

func TestCodeSignup_DisabledSignupIsTheOpaqueRefusal(t *testing.T) {
	const addr = "closed@example.com"
	app, db, sent := codeSignupServer(t, false)
	code := sentCode(t, app, sent, addr)

	for _, extra := range []map[string]any{nil, accepted} {
		m := codeLoginReq(t, app, addr, code, extra)
		if msg, _ := m["msg"].(string); m["status"] != "error" || msg != "the code is incorrect or has expired" {
			t.Fatalf("an app with sign-up off revealed more: %v", m)
		}
	}
	if u, _ := store.GetSignupByEmail(tctx(), db, "hanzo", addr); u != nil {
		t.Fatal("an account was made where sign-up is off")
	}
}

func TestPutTerms_RecordsTheCallersAcceptanceAndNobodyElses(t *testing.T) {
	const addr = "social@example.com"
	app, db, sent := codeSignupServer(t, true)
	seedUserInOrg(t, db, "hanzo", "other", "other@example.com", "correct horse battery staple")
	code := sentCode(t, app, sent, addr)

	resp, _ := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"organization": "hanzo", "username": addr, "code": code, "create": true, "terms": "t1", "aup": "a1",
		"application": "hanzo-cloud", "clientId": "hanzo-cloud",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		t.Fatal("no session was opened")
	}

	put := func(body string, withCookie bool) map[string]any {
		req := jsonReq("PUT", PathTerms, nil)
		req.Body = io.NopCloser(strings.NewReader(body))
		req.ContentLength = int64(len(body))
		if withCookie {
			for _, c := range cookies {
				req.AddCookie(c)
			}
		}
		_, raw := do(t, app, req)
		return decode(t, raw)
	}
	if m := put(`{"terms":"t2","aup":"a2"}`, false); m["status"] != "error" {
		t.Fatalf("an anonymous caller recorded terms: %v", m)
	}
	if m := put(`{"terms":"","aup":"a2"}`, true); m["status"] != "error" {
		t.Fatalf("an empty version was accepted: %v", m)
	}
	if m := put(`{"terms":"t2","aup":"a2"}`, true); m["status"] != "ok" {
		t.Fatalf("the caller could not accept: %v", m)
	}
	u, _ := store.GetSignupByEmail(tctx(), db, "hanzo", addr)
	if tm, ok := u.TermsAccepted(); !ok || tm.Terms != "t2" || tm.Method != methodSignedIn {
		t.Fatalf("not recorded on the caller: %+v", tm)
	}
	other, _ := store.GetUserByName(tctx(), db, "hanzo", "other")
	if _, ok := other.TermsAccepted(); ok {
		t.Fatal("somebody else's row was touched")
	}
}
