// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// An account an agent made with a wallet at a founding application lives in an
// org of its own and holds no address. A person later signs in to that SAME
// account by text or by email: first the account is sent a code at a number on
// file (store.GetSignupByPhone), and before that the person adds the number
// (PUT /v1/iam/address).

const (
	founding  = "hanzo-cloud"
	phoneSent = "+1 (415) 555-0134"
	phoneKept = "+14155550134"
)

// addressServer is a founding application that offers code sign-in, its org, and
// a bound sender.
func addressServer(t *testing.T) (*zip.App, orm.DB, *schema.Application, *fakeSender) {
	t.Helper()
	sent := &fakeSender{}
	bindSender(t, sent)
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: founding, secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, codeSignin: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")
	return app, db, a, sent
}

// walletMade makes an account the way POST /v1/iam/web3/verify makes one for a
// first-seen wallet (internal/wallet provision): no address and no password,
// registered by the application, then founded into an org of its own (Charter).
func walletMade(t *testing.T, db orm.DB, a *schema.Application, name string) *schema.User {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner = a.Organization
	u.Name = name
	u.Type = "normal-user"
	u.SignupApplication = a.Name
	u.SetId(u.Owner + "/" + u.Name)
	if err := u.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed wallet account: %v", err)
	}
	founded, err := Charter(tctx(), db, a, u)
	if err != nil || founded == nil {
		t.Fatalf("charter: %v", err)
	}
	if founded.Owner == a.Organization {
		t.Fatalf("premise: %s was not founded into an org of its own", founded.Name)
	}
	return founded
}

// keep writes fields onto an account row as it stands.
func keep(t *testing.T, db orm.DB, u *schema.User, f func(*schema.User)) {
	t.Helper()
	if _, err := updateUser(tctx(), db, u.Owner, u.Name, func(_ orm.DB, row *schema.User) error {
		f(row)
		return nil
	}); err != nil {
		t.Fatalf("write %s/%s: %v", u.Owner, u.Name, err)
	}
}

// bearerOf is an access token the application issued to u.
func bearerOf(t *testing.T, db orm.DB, a *schema.Application, u *schema.User, edit func(*Identity)) string {
	t.Helper()
	signer, err := signerFor(tctx(), db, a, "https://hanzo.id")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	id := identityOf(tctx(), db, u)
	if edit != nil {
		edit(&id)
	}
	tok, err := signer.SignUserToken(id, u.Owner, a.ClientId, a.ClientId, "openid", time.Hour, nowFunc())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return tok
}

// putAddress drives PUT /v1/iam/address with a bearer and a raw body.
func putAddress(t *testing.T, app *zip.App, bearer, body string) (int, map[string]any) {
	t.Helper()
	req := jsonReq("PUT", PathAddress, json.RawMessage(body))
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, raw := do(t, app, req)
	return resp.StatusCode, decode(t, raw)
}

// addBody is the request a person's page sends.
func addBody(address, code string) string {
	b, _ := json.Marshal(map[string]string{"clientId": founding, "address": address, "code": code})
	return string(b)
}

// codeTo asks the send endpoint for a code to dest at the founding application and
// returns the code the person reads.
func codeTo(t *testing.T, app *zip.App, sent *fakeSender, typ, dest string) string {
	t.Helper()
	before := len(sent.sent)
	if status, env := sendCode(t, app, map[string]string{
		"dest": dest, "type": typ, "applicationId": "admin/" + founding,
	}); status != 200 || env["status"] != "ok" {
		t.Fatalf("send a code to %s: status=%d env=%v", dest, status, env)
	}
	if len(sent.sent) != before+1 {
		t.Fatalf("send to %s delivered %d messages", dest, len(sent.sent)-before)
	}
	return codeIn(t, sent.sent[len(sent.sent)-1].Body)
}

// signInByCode signs in at the founding application with a code and returns the
// envelope: on success `data` is the account signed in as.
func signInByCode(t *testing.T, app *zip.App, identifier, code string) map[string]any {
	t.Helper()
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": identifier, "code": code,
		"application": founding, "clientId": founding, "type": "login",
	}))
	return decode(t, body)
}

// filed is the latest UNSPENT code filed for receiver under owner: finding one
// says it was not spent.
func filed(t *testing.T, db orm.DB, owner, receiver string) *schema.VerificationRecord {
	t.Helper()
	rec, err := store.GetLatestVerificationRecord(tctx(), db, owner, receiver)
	if err != nil || rec == nil {
		t.Fatalf("no code filed for %s under %s: %v", receiver, owner, err)
	}
	return rec
}

func row(t *testing.T, db orm.DB, u *schema.User) *schema.User {
	t.Helper()
	got, err := store.GetUserByName(tctx(), db, u.Owner, u.Name)
	if err != nil || got == nil {
		t.Fatalf("read %s/%s: %v", u.Owner, u.Name, err)
	}
	return got
}

// GAP 1. A founded account with a phone on file is sent a code BOUND to it, filed
// where it lives, and that code signs it in at the founding application.
func TestFoundedPhoneIsSentACodeAndSignsInByIt(t *testing.T) {
	app, db, a, sent := addressServer(t)
	u := walletMade(t, db, a, "wallet_evm_0123456789abcdef")
	keep(t, db, u, func(r *schema.User) { r.Phone = store.NormalizePhone(phoneSent) })

	code := codeTo(t, app, sent, "phone", phoneSent)
	if rec := filed(t, db, u.Owner, phoneKept); rec.User != u.Owner+"/"+u.Name {
		t.Fatalf("the code was filed for %q, want %s/%s", rec.User, u.Owner, u.Name)
	}
	m := signInByCode(t, app, phoneKept, code)
	if m["status"] != "ok" || m["data"] != u.Owner+"/"+u.Name {
		t.Fatalf("sign-in by the texted code = %v, want %s/%s", m, u.Owner, u.Name)
	}
}

// A number two registrations carry names nobody: no code is minted for either, and
// sign-in by it gets the refusal a wrong password gets.
func TestAmbiguousFoundedPhoneIsRefused(t *testing.T) {
	app, db, a, sent := addressServer(t)
	for _, name := range []string{"wallet_evm_aaaaaaaaaaaaaaaa", "wallet_evm_bbbbbbbbbbbbbbbb"} {
		keep(t, db, walletMade(t, db, a, name), func(r *schema.User) { r.Phone = phoneKept })
	}

	status, env := sendCode(t, app, map[string]string{"dest": phoneSent, "type": "phone", "applicationId": "admin/" + founding})
	if status == 200 || env["msg"] != "verification code cannot be sent" {
		t.Fatalf("send to an ambiguous number: status=%d env=%v, want the opaque refusal", status, env)
	}
	if len(sent.sent) != 0 {
		t.Fatalf("an ambiguous number was sent %d codes", len(sent.sent))
	}
	if m := signInByCode(t, app, phoneKept, "123456"); m["msg"] != "the username or password is incorrect" {
		t.Fatalf("sign-in by an ambiguous number = %v", m)
	}
}

// An account that LIVES in the org still resolves first, exactly as before, even
// when a founded account registered there carries the same number.
func TestInOrgPhoneStillResolvesFirst(t *testing.T) {
	app, db, a, sent := addressServer(t)
	seedPhoneUser(t, db, "carol", phoneSent)
	keep(t, db, walletMade(t, db, a, "wallet_evm_cccccccccccccccc"), func(r *schema.User) { r.Phone = phoneKept })

	code := codeTo(t, app, sent, "phone", phoneSent)
	if rec := filed(t, db, "hanzo", phoneKept); rec.User != "hanzo/carol" {
		t.Fatalf("the code was filed for %q, want hanzo/carol", rec.User)
	}
	// carol holds no registration at the founding app, so sign in where she lives.
	if m := signInByCode(t, app, phoneKept, code); m["status"] != "ok" || m["data"] != "hanzo/carol" {
		t.Fatalf("sign-in by the in-org number = %v, want hanzo/carol", m)
	}
}

// GAP 2, the whole path. The agent's wallet account adds a number proved by a code
// sent to it; after that the person is texted a code for THAT account and signs in
// with it.
func TestAddressAddsAPhoneAndThePhoneSignsIn(t *testing.T) {
	app, db, a, sent := addressServer(t)
	u := walletMade(t, db, a, "wallet_evm_0123456789abcdef")

	proof := codeTo(t, app, sent, "phone", phoneSent)
	if rec := filed(t, db, "hanzo", phoneKept); rec.User != "" {
		t.Fatalf("premise: a number nobody holds is sent a code for nobody, got %q", rec.User)
	}
	status, env := putAddress(t, app, bearerOf(t, db, a, u, nil), addBody(phoneSent, proof))
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("add a phone: status=%d env=%v", status, env)
	}
	data, _ := env["data"].(map[string]any)
	if data["owner"] != u.Owner || data["name"] != u.Name || data["phone"] != phoneKept || data["email"] != "" {
		t.Fatalf("answer = %v, want %s/%s with phone %s", data, u.Owner, u.Name, phoneKept)
	}
	if got := row(t, db, u); got.Phone != phoneKept {
		t.Fatalf("stored phone = %q, want %q", got.Phone, phoneKept)
	}
	if rec, _ := store.GetLatestVerificationRecord(tctx(), db, "hanzo", phoneKept); rec != nil {
		t.Fatal("the proving code was not spent")
	}

	rows := auditRows(t, db, schema.ActionAddress)
	if len(rows) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(rows))
	}
	r := rows[0]
	if r.Owner != u.Owner || r.User != u.Owner+"/"+u.Name || r.RequestUri != PathAddress || r.Object != `{"client":"`+founding+`","field":"phone"}` {
		t.Fatalf("audit row = %+v", r)
	}
	if strings.Contains(r.Object+r.Response, "5550134") || strings.Contains(r.Object+r.Response, proof) {
		t.Fatalf("the audit row carries the number or the code: %+v", r)
	}
	if !schema.PlatformWritten(r.Action) {
		t.Fatal("the audit row can be forged or trimmed through the audit CRUD")
	}

	code := codeTo(t, app, sent, "phone", phoneKept)
	if m := signInByCode(t, app, phoneSent, code); m["status"] != "ok" || m["data"] != u.Owner+"/"+u.Name {
		t.Fatalf("sign-in by the added phone = %v, want %s/%s", m, u.Owner, u.Name)
	}
}

// An email is added proved, stored in its one form, and then signs the account in.
func TestAddressAddsAnEmailVerified(t *testing.T) {
	app, db, a, sent := addressServer(t)
	u := walletMade(t, db, a, "wallet_evm_0123456789abcdef")

	proof := codeTo(t, app, sent, "email", "Ada@Example.com")
	if status, env := putAddress(t, app, bearerOf(t, db, a, u, nil), addBody("Ada@Example.com", proof)); status != 200 {
		t.Fatalf("add an email: status=%d env=%v", status, env)
	}
	got := row(t, db, u)
	if got.Email != "ada@example.com" || !got.EmailVerified {
		t.Fatalf("stored email=%q verified=%v, want ada@example.com verified", got.Email, got.EmailVerified)
	}
	code := codeTo(t, app, sent, "email", "ada@example.com")
	if m := signInByCode(t, app, "ada@example.com", code); m["status"] != "ok" || m["data"] != u.Owner+"/"+u.Name {
		t.Fatalf("sign-in by the added email = %v", m)
	}
}

// A wrong code writes nothing and is counted against the code.
func TestAddressWrongCodeIsRefusedAndCounted(t *testing.T) {
	app, db, a, sent := addressServer(t)
	u := walletMade(t, db, a, "wallet_evm_0123456789abcdef")

	proof := codeTo(t, app, sent, "phone", phoneSent)
	wrong := "000000"
	if proof == wrong {
		wrong = "111111"
	}
	status, env := putAddress(t, app, bearerOf(t, db, a, u, nil), addBody(phoneSent, wrong))
	if status != 400 || env["msg"] != errCodeRefused {
		t.Fatalf("a wrong code: status=%d env=%v", status, env)
	}
	if got := row(t, db, u); got.Phone != "" {
		t.Fatalf("a wrong code wrote the phone %q", got.Phone)
	}
	if rec := filed(t, db, "hanzo", phoneKept); rec.Attempts != 1 {
		t.Fatalf("record attempts=%d, want one counted guess", rec.Attempts)
	}
}

// An address another account signs in with at the application is refused in the
// words a wrong code gets, before the code is looked at: nothing is spent or
// counted, and nothing is written.
func TestAddressHeldByAnotherIsRefusedWithoutSpending(t *testing.T) {
	for _, c := range []struct {
		name, typ, address, receiver string
		hold                         func(t *testing.T, db orm.DB, a *schema.Application)
	}{
		{"a founded account's phone", "phone", phoneSent, phoneKept, func(t *testing.T, db orm.DB, a *schema.Application) {
			keep(t, db, walletMade(t, db, a, "wallet_evm_dddddddddddddddd"), func(r *schema.User) { r.Phone = phoneKept })
		}},
		{"a username", "email", "grace@example.com", "grace@example.com", func(t *testing.T, db orm.DB, _ *schema.Application) {
			seedUserInOrg(t, db, "hanzo", "grace@example.com", "", "pw")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			app, db, a, sent := addressServer(t)
			u := walletMade(t, db, a, "wallet_evm_0123456789abcdef")
			// The code went out while nobody held the address.
			proof := codeTo(t, app, sent, c.typ, c.address)
			c.hold(t, db, a)

			status, env := putAddress(t, app, bearerOf(t, db, a, u, nil), addBody(c.address, proof))
			if status != 400 || env["msg"] != errCodeRefused {
				t.Fatalf("a held address: status=%d env=%v, want the wrong-code refusal", status, env)
			}
			if rec := filed(t, db, "hanzo", c.receiver); rec.Attempts != 0 {
				t.Fatalf("the code was counted: attempts=%d", rec.Attempts)
			}
			if got := row(t, db, u); got.Phone != "" || got.Email != "" {
				t.Fatalf("a held address was written: phone=%q email=%q", got.Phone, got.Email)
			}
		})
	}
}

// It adds and never replaces. The same value again is ok without a code; another
// value is refused and its code is not spent.
func TestAddressNeverReplaces(t *testing.T) {
	app, db, a, sent := addressServer(t)
	u := walletMade(t, db, a, "wallet_evm_0123456789abcdef")
	keep(t, db, u, func(r *schema.User) { r.Phone = phoneKept })
	bearer := bearerOf(t, db, a, u, nil)

	if status, env := putAddress(t, app, bearer, addBody(phoneSent, "")); status != 200 || env["status"] != "ok" {
		t.Fatalf("the number already on file: status=%d env=%v, want ok", status, env)
	}

	proof := codeTo(t, app, sent, "phone", "+1 212 555 0100")
	status, env := putAddress(t, app, bearer, addBody("+1 212 555 0100", proof))
	if status != 409 || !strings.Contains(env["msg"].(string), "never replaced") {
		t.Fatalf("another number: status=%d env=%v, want 409", status, env)
	}
	if got := row(t, db, u); got.Phone != phoneKept {
		t.Fatalf("the phone was replaced with %q", got.Phone)
	}
	if rec := filed(t, db, "hanzo", "+12125550100"); rec.Attempts != 0 {
		t.Fatalf("a refused replacement counted the code: attempts=%d", rec.Attempts)
	}
}

// The body names nobody: a caller naming another account still writes only its own.
func TestAddressWritesOnlyTheCaller(t *testing.T) {
	app, db, a, sent := addressServer(t)
	caller := walletMade(t, db, a, "wallet_evm_0123456789abcdef")
	victim := walletMade(t, db, a, "wallet_evm_eeeeeeeeeeeeeeee")

	proof := codeTo(t, app, sent, "phone", phoneSent)
	b, _ := json.Marshal(map[string]string{
		"clientId": founding, "address": phoneSent, "code": proof,
		"owner": victim.Owner, "name": victim.Name, "user": victim.Owner + "/" + victim.Name,
	})
	if status, env := putAddress(t, app, bearerOf(t, db, a, caller, nil), string(b)); status != 200 {
		t.Fatalf("status=%d env=%v", status, env)
	}
	if got := row(t, db, victim); got.Phone != "" {
		t.Fatalf("the account the body named was written: %q", got.Phone)
	}
	if got := row(t, db, caller); got.Phone != phoneKept {
		t.Fatalf("the caller's own phone = %q", got.Phone)
	}
}

// A credential someone else acts through writes no address: an impersonation or
// a delegation names a person it is not, and an anonymous request names nobody.
func TestAddressRefusesABearerSomeoneActsThrough(t *testing.T) {
	app, db, a, sent := addressServer(t)
	u := walletMade(t, db, a, "wallet_evm_0123456789abcdef")
	proof := codeTo(t, app, sent, "phone", phoneSent)

	for name, bearer := range map[string]string{
		"impersonated": bearerOf(t, db, a, u, func(id *Identity) {
			id.Imp = true
			id.Act = &Actor{Sub: "admin/z", Owner: "admin", Name: "z"}
		}),
		"delegated": bearerOf(t, db, a, u, func(id *Identity) { id.Act = &Actor{Sub: "admin/hanzo-cloud"} }),
		"anonymous": "",
	} {
		status, env := putAddress(t, app, bearer, addBody(phoneSent, proof))
		if status != 400 || env["code"] != CodeLoginRequired {
			t.Fatalf("%s: status=%d env=%v, want login_required", name, status, env)
		}
	}
	if got := row(t, db, u); got.Phone != "" {
		t.Fatalf("an acting bearer wrote the phone %q", got.Phone)
	}
	if rec := filed(t, db, "hanzo", phoneKept); rec.Attempts != 0 {
		t.Fatal("a refused caller counted the code")
	}
}

// A machine has no sign-in address, an application that does not sign the caller
// in cannot be named, and anything that is not an address is refused.
func TestAddressRefusals(t *testing.T) {
	app, db, a, _ := addressServer(t)
	u := walletMade(t, db, a, "wallet_evm_0123456789abcdef")
	bearer := bearerOf(t, db, a, u, nil)

	machine := orm.New[schema.User](db)
	machine.Owner, machine.Name, machine.Type = "hanzo", "builder", schema.ServiceAccount
	machine.SetId("hanzo/builder")
	if err := machine.CreateCtx(tctx()); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	if status, env := putAddress(t, app, bearerOf(t, db, a, machine, nil), addBody(phoneSent, "123456")); status != http.StatusForbidden {
		t.Fatalf("a machine: status=%d env=%v, want 403", status, env)
	}

	seedOrg(t, db, "lux")
	lux := orm.New[schema.Application](db)
	lux.Owner, lux.Name, lux.ClientId, lux.Organization = "admin", "lux-cloud", "lux-cloud", "lux"
	lux.SetId("admin/lux-cloud")
	if err := lux.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed lux app: %v", err)
	}
	for _, c := range []struct {
		name, body string
		status     int
	}{
		{"another org's application", `{"clientId":"lux-cloud","address":"+14155550134","code":"123456"}`, http.StatusForbidden},
		{"no application", `{"clientId":"nope","address":"+14155550134","code":"123456"}`, 400},
		{"no address", `{"clientId":"` + founding + `","address":"ada","code":"123456"}`, 400},
		{"a display name", `{"clientId":"` + founding + `","address":"Ada <ada@example.com>","code":"123456"}`, 400},
		{"a short number", `{"clientId":"` + founding + `","address":"12345","code":"123456"}`, 400},
		{"no code", `{"clientId":"` + founding + `","address":"+14155550134"}`, 400},
	} {
		if status, env := putAddress(t, app, bearer, c.body); status != c.status || env["status"] != "error" {
			t.Fatalf("%s: status=%d env=%v, want %d", c.name, status, env, c.status)
		}
	}
	if got := row(t, db, u); got.Phone != "" || got.Email != "" {
		t.Fatalf("a refusal wrote an address: phone=%q email=%q", got.Phone, got.Email)
	}
}

// The sign-in screen is told a person can add an address only where a code can be
// sent to it, because the add is proved by one. With no sender the route could not
// be finished, so the descriptor must not offer it.
func TestMethodsSaysWhetherAnAddressCanBeAdded(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "addr", secret: "s3cret", redirectURIs: []string{testRedirect}})

	flag := func() any {
		t.Helper()
		_, body := do(t, app, formReqNoBody("GET", PathAuthMethods+"?clientId=addr"))
		data, _ := decode(t, body)["data"].(map[string]any)
		return data["address"]
	}

	bindSender(t, nil)
	if got := flag(); got != false {
		t.Errorf("address = %v with no sender bound, want false", got)
	}
	bindSender(t, &fakeSender{})
	if got := flag(); got != true {
		t.Errorf("address = %v with a sender bound, want true", got)
	}
}
