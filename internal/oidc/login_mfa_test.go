// Copyright 2026 Hanzo AI, Inc. All rights reserved.

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
	"github.com/hanzoai/iam/internal/schema"
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
	app := zip.New(zip.Config{AppName: "iam2-test", DisableStartupMessage: true})
	// The OIDC surface is the pre-auth PUBLIC group; login + the challenge finish
	// both live here, so a root (empty-prefix) router registers them at their absolute
	// paths (main renamed Route→Route on the zip-group model).
	Route(app.Group(""), db)
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
// The factor already used to get here cannot answer for the one still owed.
func TestPasscodeRefusedWhenItRepeatsTheUsedFactor(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	secret := enrolled(t, db, "alice", "pw")
	u := userRow(t, db, "alice")

	// A challenge whose payload says "the app factor was already used".
	id, err := MintChallenge(context.Background(), db, KindMfa, "hanzo/"+u.Name, factor.App, time.Now())
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
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]any{
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
	if !remembered(userRow(t, db, "alice"), time.Now()) {
		t.Fatalf("the gate cannot read back the deadline it wrote (%q) — the window is silently dead", stored)
	}

	// A future deadline SKIPS the challenge: the next password login mints.
	_, body2 := do(t, app, jsonReq("POST", PathLogin, login))
	m2 := decode(t, body2)
	if m2["data"] == NextMfa {
		t.Fatal("a live remember window still challenged")
	}
	if code, _ := m2["data"].(string); code == "" {
		t.Fatalf("remembered login did not mint: %#v", m2)
	}

	// A PAST deadline challenges again.
	u := userRow(t, db, "alice")
	u.MfaRememberDeadline = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, body3 := do(t, app, jsonReq("POST", PathLogin, login))
	if m3 := decode(t, body3); m3["data"] != NextMfa {
		t.Fatalf("an expired remember window skipped the gate: %#v", m3)
	}
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
