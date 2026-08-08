// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/pquerna/otp/totp"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The MFA gate at login, driven through the REAL registered router. The contract is
// not a status code: every one of these answers is a 200, because the envelope
// carries the outcome. What matters is WHICH answer, and — the point of the whole
// gate — whether a token row exists afterwards. A test that checked only the
// status would pass while every 2FA user signed in with a password alone.

// newApp registers the OIDC surface on an EXISTING store, so a test can seed the
// same db the router serves (newServer opens its own).
func newApp(t *testing.T, db orm.DB) *zip.App {
	t.Helper()
	app := zip.New(zip.Config{AppName: "iam-test", DisableStartupMessage: true})
	// The OIDC surface is the pre-auth PUBLIC group; login + the challenge finish
	// both live here, so a root (empty-prefix) router registers them at their absolute
	// paths (main renamed Route→Route on the zip-group model).
	Route(app.Group("").(*zip.App), db)
	return app
}

// enrolled seeds a user with a password AND a live TOTP factor, returning the
// TOTP secret.
func enrolled(t *testing.T, db orm.DB, name, password string) string {
	t.Helper()
	seedUser(t, db, name, name+"@hanzo.ai", password)
	secret, _, err := factor.Enroll("hanzo/"+name, "Hanzo")
	if err != nil {
		t.Fatal(err)
	}
	u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", "hanzo").Filter("Name=", name).First()
	if err != nil {
		t.Fatal(err)
	}
	u.TotpSecret = secret
	u.PreferredMfaType = factor.App
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	return secret
}

// tokens counts persisted token rows — the store-side proof that no credential
// was minted. The gate's whole job is that this stays zero until the second
// factor lands.
func tokens(t *testing.T, db orm.DB) int {
	t.Helper()
	n, err := orm.TypedQuery[schema.Token](db).Count(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// passcode computes the code an authenticator would show right now.
func passcode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return code
}

// challengeOf extracts the challenge id the gate set as a cookie.
func challengeOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	for _, ck := range resp.Cookies() {
		if ck.Name == challengeCookie && ck.Value != "" {
			return ck.Value
		}
	}
	t.Fatal("the gate set no challenge cookie")
	return ""
}

// TestEnrolledUserIsChallengedAndGetsNoToken is THE regression. Before the gate,
// login verified the password and minted a code directly: an enrolled user signed
// in with one factor and the second was never asked for. Not a missing feature —
// a silent downgrade of every 2FA account.
func TestEnrolledUserIsChallengedAndGetsNoToken(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	enrolled(t, db, "alice", "correct horse battery staple")

	resp, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "correct horse battery staple",
		"type": "code", "clientId": "hanzo-app",
	}))
	m := decode(t, body)

	if m["status"] != "ok" {
		t.Fatalf("gate answered an error: %v", m["msg"])
	}
	// `data` is the literal string the portal compares against. Any other shape
	// and the client reads it as an authorization code.
	if m["data"] != NextMfa {
		t.Fatalf("data = %q, want %q — the client treats anything else as a code, so MFA is bypassed", m["data"], NextMfa)
	}
	// data2 carries the factors to choose from.
	list, ok := m["data2"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("data2 = %#v, want exactly the one enrolled factor", m["data2"])
	}
	got := list[0].(map[string]any)
	if got["mfaType"] != factor.App || got["enabled"] != true {
		t.Fatalf("offered factor = %#v, want the enabled app factor", got)
	}
	// The masked projection must not carry the shared secret out.
	if s := string(body); strings.Contains(s, "secret") || strings.Contains(s, "recoveryCodes") {
		t.Fatalf("the challenge leaked secret material: %s", s)
	}

	// THE assertion: nothing was minted.
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted at the challenge — the password alone bought a credential", n)
	}
	challengeOf(t, resp)
}

// TestChallengeAnsweredWithPasscodeMintsCode — the happy path: the second factor
// lands and the code appears.
func TestChallengeAnsweredWithPasscodeMintsCode(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	secret := enrolled(t, db, "alice", "pw")

	resp, _ := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"type": "code", "clientId": "hanzo-app",
	}))
	id := challengeOf(t, resp)

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app",
		"challenge": id, "mfaType": factor.App, "passcode": passcode(t, secret),
	}))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("the correct passcode was refused: %v", m["msg"])
	}
	code, _ := m["data"].(string)
	if code == "" || code == NextMfa || code == RequiredMfa {
		t.Fatalf("data = %q, want an authorization code", m["data"])
	}
	tok, err := store2GetTokenByCode(db, code)
	if err != nil || tok == nil {
		t.Fatalf("the minted code resolves to no token row: %v", err)
	}
	if tok.User != "hanzo/alice" {
		t.Fatalf("code bound to %q, want hanzo/alice", tok.User)
	}
}

// TestWrongPasscodeMintsNothing — a failed second factor must leave the sign-in
// exactly where it was: nowhere.
func TestWrongPasscodeMintsNothing(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	enrolled(t, db, "alice", "pw")

	resp, _ := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"type": "code", "clientId": "hanzo-app",
	}))
	id := challengeOf(t, resp)

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app",
		"challenge": id, "mfaType": factor.App, "passcode": "000000",
	}))
	if m := decode(t, body); m["status"] != "error" {
		t.Fatalf("a wrong passcode was accepted: %#v", m)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted for a wrong passcode", n)
	}
}

// TestChallengeIsSingleUse — a challenge is spent by the attempt that takes it,
// so a captured id cannot be replayed. The wrong passcode below spends it; the
// RIGHT passcode afterwards must still fail, on the challenge and not the code.
func TestChallengeIsSingleUse(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	secret := enrolled(t, db, "alice", "pw")

	resp, _ := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"type": "code", "clientId": "hanzo-app",
	}))
	id := challengeOf(t, resp)

	first := map[string]any{"type": "code", "clientId": "hanzo-app", "challenge": id, "mfaType": factor.App, "passcode": passcode(t, secret)}
	if m := decode(t, mustBody(t, app, first)); m["status"] != "ok" {
		t.Fatalf("first use failed: %v", m["msg"])
	}
	// Same id, same valid passcode, second time.
	m := decode(t, mustBody(t, app, first))
	if m["status"] != "error" {
		t.Fatalf("a spent challenge was accepted again: %#v", m)
	}
	if m["msg"] != ErrChallenge.Error() {
		t.Fatalf("msg = %q, want the challenge refusal %q", m["msg"], ErrChallenge.Error())
	}
}

// TestChallengeBindsItsOwnSubject — invariant 3. A challenge minted for alice
// must resolve alice even when the body names mallory. The user comes from the
// verified server-side record, never from a request parameter.
func TestChallengeBindsItsOwnSubject(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	secret := enrolled(t, db, "alice", "pw")
	seedUser(t, db, "mallory", "mallory@hanzo.ai", "pw")

	resp, _ := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"type": "code", "clientId": "hanzo-app",
	}))
	id := challengeOf(t, resp)

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app",
		"challenge": id, "mfaType": factor.App, "passcode": passcode(t, secret),
		// The body tries to redirect the ceremony at another account.
		"username": "", "organization": "hanzo", "name": "mallory",
	}))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("the ceremony failed: %v", m["msg"])
	}
	tok, err := store2GetTokenByCode(db, m["data"].(string))
	if err != nil || tok == nil {
		t.Fatal("no token row for the minted code")
	}
	if tok.User != "hanzo/alice" {
		t.Fatalf("code bound to %q — the body redirected the challenge's subject", tok.User)
	}
}

// TestRecoveryCodeIsAcceptedOnceAndStoredHashed proves three things at once: a
// recovery code answers the challenge, it is CONSUMED (a second use fails), and
// what sits in the row is a bcrypt digest — never the code itself.
func TestRecoveryCodeIsAcceptedOnceAndStoredHashed(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	enrolled(t, db, "alice", "pw")

	plain, err := factor.MintRecovery()
	if err != nil {
		t.Fatal(err)
	}
	hash, err := factor.HashRecovery(plain)
	if err != nil {
		t.Fatal(err)
	}
	u := userRow(t, db, "alice")
	u.RecoveryCodes = []string{hash}
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(hash, plain) {
		t.Fatal("the stored value contains the plaintext recovery code")
	}

	login := map[string]string{"organization": "hanzo", "username": "alice", "password": "pw", "type": "code", "clientId": "hanzo-app"}
	resp, _ := do(t, app, jsonReq("POST", PathLogin, login))
	id := challengeOf(t, resp)

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app", "challenge": id, "recoveryCode": plain,
	}))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("the recovery code was refused: %v", m["msg"])
	}
	if code, _ := m["data"].(string); code == "" || code == NextMfa {
		t.Fatalf("data = %q, want an authorization code", m["data"])
	}
	// Spent: the row no longer carries it.
	if got := userRow(t, db, "alice").RecoveryCodes; len(got) != 0 {
		t.Fatalf("recovery codes after use = %v, want none — a one-time code survived", got)
	}
	// And a second sign-in cannot reuse it.
	resp2, _ := do(t, app, jsonReq("POST", PathLogin, login))
	_, body2 := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app", "challenge": challengeOf(t, resp2), "recoveryCode": plain,
	}))
	if m2 := decode(t, body2); m2["status"] != "error" {
		t.Fatalf("a spent recovery code signed in a second time: %#v", m2)
	}
}

// TestLegacyPlaintextRecoveryCodeStillVerifies — every recovery code migrated
// from v1 is PLAINTEXT (object/factor.go:81 compares in the clear). The algorithm is
// a property of the stored value, so a legacy row must still verify, and the
// plaintext must die on first use.
func TestLegacyPlaintextRecoveryCodeStillVerifies(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	enrolled(t, db, "alice", "pw")

	const legacy = "0d5a7f0e-3a1e-4a1a-9f6c-2b1d3e4f5a6b" // a v1 uuid.NewString() code
	u := userRow(t, db, "alice")
	u.RecoveryCodes = []string{legacy}
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	resp, _ := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw", "type": "code", "clientId": "hanzo-app",
	}))
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app", "challenge": challengeOf(t, resp), "recoveryCode": legacy,
	}))
	if m := decode(t, body); m["status"] != "ok" {
		t.Fatalf("a migrated v1 plaintext recovery code was refused: %v — every live 2FA user's way back is gone", m["msg"])
	}
	if got := userRow(t, db, "alice").RecoveryCodes; len(got) != 0 {
		t.Fatalf("the legacy plaintext survived its use: %v", got)
	}
}

// TestPasscodeRefusedWhenItRepeatsTheUsedFactor — v1 controllers/auth.go:1325.
// The factor already used to get here cannot answer for the one still owed. The
// gate never OFFERS the just-used factor (allowList drops it), so a challenge that
// was minted after an app factor and is answered with the app factor is answering
// something it was not offered.
func TestPasscodeRefusedWhenItRepeatsTheUsedFactor(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	secret := enrolled(t, db, "alice", "pw")
	u := userRow(t, db, "alice")

	// A challenge minted the way the gate mints one for an app-only account whose app
	// factor was already used: nothing left to offer.
	id, err := MintChallenge(context.Background(), db, KindMfa, "hanzo/"+u.Name, factor.App, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app",
		"challenge": id, "mfaType": factor.App, "passcode": passcode(t, secret),
	}))
	if m := decode(t, body); m["status"] != "error" {
		t.Fatalf("the just-used factor answered its own challenge: %#v", m)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted", n)
	}
}

// TestChallengeRefusesAFactorItDidNotOffer — the downgrade this closes. alice holds
// ONLY an authenticator; nothing on her row enables email. A challenge answered with
// mfaType=email and a live code for her address used to mint, because the finish
// checked only that the answering factor differed from the one already proven. Her
// deliberate choice of TOTP silently became possession of a mailbox.
//
// The code seeded here is worse than a stray one: it is filed under a DIFFERENT
// tenant and bound to no user, because a verification record resolves by address
// alone. One delivered code was valid for every purpose that shares the address.
func TestChallengeRefusesAFactorItDidNotOffer(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	bindSender(t, &fakeSender{})
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	secret := enrolled(t, db, "alice", "pw")
	_ = secret

	// The password login: the offer is her authenticator and nothing else.
	resp, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"type": "code", "clientId": "hanzo-app",
	}))
	m := decode(t, body)
	if m["data"] != NextMfa {
		t.Fatalf("data = %q, want %q", m["data"], NextMfa)
	}
	list, _ := m["data2"].([]any)
	if len(list) != 1 {
		t.Fatalf("the offer carried %d factors, want only the authenticator: %#v", len(list), list)
	}

	// A live code for her address, minted by another tenant for another purpose.
	if err := otp.Issue(context.Background(), db, "lux", "alice@hanzo.ai", "", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	rec, err := store.GetLatestVerificationRecord(context.Background(), db, "alice@hanzo.ai")
	if err != nil || rec == nil {
		t.Fatalf("seed code not persisted: %v", err)
	}

	_, body2 := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app", "challenge": challengeOf(t, resp),
		"mfaType": factor.Email, "passcode": rec.Code,
	}))
	if m2 := decode(t, body2); m2["status"] != "error" {
		t.Fatalf("an emailed code answered an authenticator-only challenge: %#v", m2)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted — TOTP was downgraded to mailbox possession", n)
	}
}

// TestPreferredFactorNobodyHoldsDivertsToEnrollment — factor.Enabled reads
// PreferredMfaType, so a row naming a factor it does not hold reported "MFA is on"
// and then had nothing to challenge with. The password alone minted a code. The gate
// must not read an empty offer as "everything owed has been proven".
func TestPreferredFactorNobodyHoldsDivertsToEnrollment(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	seedUser(t, db, "bob", "bob@hanzo.ai", "pw")

	u := userRow(t, db, "bob")
	u.PreferredMfaType = factor.SMS // nothing enrolled; no phone on file
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "bob", "password": "pw", "type": "code", "clientId": "hanzo-app",
	}))
	m := decode(t, body)
	if m["data"] != RequiredMfa {
		t.Fatalf("data = %#v, want %q — a factor nobody holds waved the sign-in through", m["data"], RequiredMfa)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted", n)
	}
}

// TestTextedFactorIsSentAndAnswered — the whole SMS second factor, end to end. It
// could not be completed by anyone before: the gate answered NextMfa and delivered
// NOTHING, and the one send endpoint filed a record under the punctuation somebody
// typed while the verify looked it up under the account's digits.
func TestTextedFactorIsSentAndAnswered(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	f := &fakeSender{}
	bindSender(t, f)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	seedUser(t, db, "carol", "carol@hanzo.ai", "pw")

	// A phone stored the way a person types one, and an SMS factor enrolled on it.
	u := userRow(t, db, "carol")
	u.Phone = "+1 (415) 555-0134"
	factor.Add(u, factor.SMS, "")
	if err := factor.Prefer(u, factor.SMS); err != nil {
		t.Fatal(err)
	}
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	resp, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "carol", "password": "pw", "type": "code", "clientId": "hanzo-app",
	}))
	if m := decode(t, body); m["data"] != NextMfa {
		t.Fatalf("data = %#v, want %q", m["data"], NextMfa)
	}
	if len(f.sent) != 1 {
		t.Fatalf("the challenge sent %d messages, want 1 — nothing delivers the code", len(f.sent))
	}
	// The code goes to the account's OWN number, in the canonical spelling the record
	// is keyed on — which is what makes the delivered code verifiable below.
	if m := f.sent[0]; m.Org != "hanzo" || m.Channel != otp.Phone || m.To != "+14155550134" {
		t.Fatalf("sent %+v — the code must go to the account's own number, normalized", m)
	}
	code := codeIn(t, f.sent[0].Body)

	// The code that was actually delivered verifies. Filed under the digits, found
	// under the digits.
	_, body2 := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app", "challenge": challengeOf(t, resp),
		"mfaType": factor.SMS, "passcode": code,
	}))
	m2 := decode(t, body2)
	if m2["status"] != "ok" {
		t.Fatalf("the delivered code was refused: %v", m2["msg"])
	}
	if got, _ := m2["data"].(string); got == "" || got == NextMfa {
		t.Fatalf("data = %#v, want an authorization code", m2["data"])
	}
}

// TestRememberDeadlineRoundTrips — the "don't ask again" window short-circuits
// the whole gate, so the value the writer writes must be the value the reader
// reads. A format mismatch is silent: a permanent skip, or a permanent challenge.
func TestRememberDeadlineRoundTrips(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	secret := enrolled(t, db, "alice", "pw")

	// An org with a real remember window (live orgs leave it at zero).
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name, o.MfaRememberInHours = "admin", "hanzo", 24
	o.SetId("admin/hanzo")
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	login := map[string]string{"organization": "hanzo", "username": "alice", "password": "pw", "type": "code", "clientId": "hanzo-app"}
	resp, _ := do(t, app, jsonReq("POST", PathLogin, login))
	answered, body := do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app", "challenge": challengeOf(t, resp),
		"mfaType": factor.App, "passcode": passcode(t, secret), "enableMfaRemember": true,
	}))
	if m := decode(t, body); m["status"] != "ok" {
		t.Fatalf("the passcode was refused: %v", m["msg"])
	}

	// The exact stored string must parse for the exact reader the gate uses.
	stored := userRow(t, db, "alice").MfaRememberDeadline
	if stored == "" {
		t.Fatal("enableMfaRemember wrote no deadline")
	}
	token := rememberOf(t, answered)

	// THIS browser skips the challenge: it presents the token the window was opened
	// with, and the next password login mints.
	same := jsonReq("POST", PathLogin, login)
	same.Header.Set("Cookie", rememberCookie+"="+token)
	_, body2 := do(t, app, same)
	m2 := decode(t, body2)
	if m2["data"] == NextMfa {
		t.Fatal("a live remember window still challenged the browser that opened it")
	}
	if code, _ := m2["data"].(string); code == "" {
		t.Fatalf("remembered login did not mint: %#v", m2)
	}

	// ANOTHER browser does NOT. This is the defect: the deadline lived on the user
	// row alone, so a factor proven once skipped the factor everywhere — including for
	// whoever else held the password.
	_, body3 := do(t, app, jsonReq("POST", PathLogin, login))
	if m3 := decode(t, body3); m3["data"] != NextMfa {
		t.Fatalf("a browser carrying no remember token skipped the factor: %#v — "+
			"\"don't ask again on this browser\" turned 2FA off for the account", m3)
	}

	// A PAST deadline challenges again, token or no token.
	u := userRow(t, db, "alice")
	u.MfaRememberDeadline = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	expired := jsonReq("POST", PathLogin, login)
	expired.Header.Set("Cookie", rememberCookie+"="+token)
	_, body4 := do(t, app, expired)
	if m4 := decode(t, body4); m4["data"] != NextMfa {
		t.Fatalf("an expired remember window skipped the gate: %#v", m4)
	}
}

// rememberOf extracts the remember token the gate set on a browser.
func rememberOf(t *testing.T, resp *http.Response) string {
	t.Helper()
	for _, ck := range resp.Cookies() {
		if ck.Name == rememberCookie && ck.Value != "" {
			return ck.Value
		}
	}
	t.Fatal("enableMfaRemember set no remember cookie — nothing binds the window to a browser")
	return ""
}

// TestZeroRememberWindowStillChallenges pins the LIVE configuration: every
// organization today leaves MfaRememberInHours at zero, which puts the deadline
// in the past the instant it is written. "Fixing" a zero into an always-on skip
// would turn 2FA off for every tenant at once.
func TestZeroRememberWindowStillChallenges(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	secret := enrolled(t, db, "alice", "pw")

	login := map[string]string{"organization": "hanzo", "username": "alice", "password": "pw", "type": "code", "clientId": "hanzo-app"}
	resp, _ := do(t, app, jsonReq("POST", PathLogin, login))
	do(t, app, jsonReq("POST", PathLogin, map[string]any{
		"type": "code", "clientId": "hanzo-app", "challenge": challengeOf(t, resp),
		"mfaType": factor.App, "passcode": passcode(t, secret), "enableMfaRemember": true,
	}))

	_, body := do(t, app, jsonReq("POST", PathLogin, login))
	if m := decode(t, body); m["data"] != NextMfa {
		t.Fatalf("a zero remember window skipped the gate: %#v — 2FA is off for every live org", m)
	}
}

// TestOrgRequiredFactorPromptsEnrollment — v1 object/organization.go:770. The org
// demands a factor the user has not enrolled, so the answer is "go enroll", not a
// challenge it could never answer.
func TestOrgRequiredFactorPromptsEnrollment(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw") // no factor

	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", "hanzo"
	o.MfaItems = []*schema.MfaItem{{Name: factor.App, Rule: "Required"}}
	o.SetId("admin/hanzo")
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw", "type": "code", "clientId": "hanzo-app",
	}))
	m := decode(t, body)
	if m["data"] != RequiredMfa {
		t.Fatalf("data = %q, want %q", m["data"], RequiredMfa)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted while a required factor was missing", n)
	}
}

// TestUnenrolledUserSignsInUnchanged — the gate must be invisible to everyone
// else. A user with no factor still logs in with a password, exactly as before.
func TestUnenrolledUserSignsInUnchanged(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	seedUser(t, db, "bob", "bob@hanzo.ai", "pw")

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "bob", "password": "pw", "type": "code", "clientId": "hanzo-app",
	}))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("an unenrolled user was refused: %v", m["msg"])
	}
	if code, _ := m["data"].(string); code == "" || code == NextMfa || code == RequiredMfa {
		t.Fatalf("data = %q, want an authorization code", m["data"])
	}
}

// --- helpers ---

func mustBody(t *testing.T, app *zip.App, body any) []byte {
	t.Helper()
	_, b := do(t, app, jsonReq("POST", PathLogin, body))
	return b
}

func userRow(t *testing.T, db orm.DB, name string) *schema.User {
	t.Helper()
	u, err := orm.TypedQuery[schema.User](db).Filter("Owner=", "hanzo").Filter("Name=", name).First()
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func store2GetTokenByCode(db orm.DB, code string) (*schema.Token, error) {
	t, err := orm.TypedQuery[schema.Token](db).Filter("Code=", code).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return t, err
}

// TestEmailOnlyAccountIsNotAskedTwice — the third branch of an empty offer, and the
// only one that proceeds. An account whose ONLY factor is its email address signs in
// with an emailed code: that code IS the factor, so nothing further is owed and the
// grant is minted. Collapsing this case with the two refusals in either direction is a
// bug both ways — waving the others through downgrades 2FA, and refusing this one
// makes an email-only account unable to sign in at all.
func TestEmailOnlyAccountIsNotAskedTwice(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	f := &fakeSender{}
	bindSender(t, f)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret", codeSignin: true})
	seedUser(t, db, "erin", "erin@hanzo.ai", "pw")

	u := userRow(t, db, "erin")
	factor.Add(u, factor.Email, "")
	if err := factor.Prefer(u, factor.Email); err != nil {
		t.Fatal(err)
	}
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	// A code to her address, then a sign-in with it instead of a password.
	if err := otp.Issue(context.Background(), db, "hanzo", "erin@hanzo.ai", "", u, time.Now()); err != nil {
		t.Fatal(err)
	}
	rec, err := store.GetLatestVerificationRecord(context.Background(), db, "erin@hanzo.ai")
	if err != nil || rec == nil {
		t.Fatalf("code not persisted: %v", err)
	}

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "erin@hanzo.ai", "code": rec.Code,
		"type": "code", "clientId": "hanzo-app",
	}))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("an email-only account could not sign in with its own factor: %v", m["msg"])
	}
	if code, _ := m["data"].(string); code == "" || code == NextMfa || code == RequiredMfa {
		t.Fatalf("data = %#v, want an authorization code — the factor that was already proven was demanded again", m["data"])
	}
}
