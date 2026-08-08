// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/pkg/store"
)

// The federated-login second-factor gate, driven through the REAL registered routes
// and the same httptest mock IdP the federation suite uses. The contract that
// matters is a store fact: an MFA-enrolled user who signs in through an external
// IdP gets NO authorization code until the factor lands — the hole a live MFA gate
// would otherwise leave open.

// fedEnroll seeds a user (in org hanzo) with the given email AND a live TOTP
// factor, returning the secret. The email must match the mock IdP so the callback
// links to this account by verified email.
func fedEnroll(t *testing.T, db orm.DB, name, email string) string {
	t.Helper()
	seedUser(t, db, name, email, "pw")
	// The callback reaches this account by its ADDRESS, and an address is only
	// linkable once it has been proven — otherwise federation refuses rather than
	// adopt a row an unproven password already opens. These tests are about the MFA
	// gate, so they state the premise instead of relying on it.
	proveEmail(t, db, name)
	secret, _, err := factor.Enroll("hanzo/"+name, "Hanzo")
	if err != nil {
		t.Fatal(err)
	}
	u := userRow(t, db, name)
	u.TotpSecret = secret
	u.PreferredMfaType = factor.App
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	return secret
}

// (a) An MFA-enrolled user signing in through federation is CHALLENGED, not minted:
// the callback sends the browser to the 2FA page, sets the challenge cookie, and
// persists no token. Presenting the factor then mints the code for that user.
func TestFederationMfa_EnrolledUserChallengedThenResumes(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	secret := fedEnroll(t, db, "alice", "alice@example.com")
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := resp.Header.Get("Location")
	if resp.StatusCode != 302 {
		t.Fatalf("callback status = %d, want 302", resp.StatusCode)
	}
	// The load-bearing negative: the callback must NOT have minted a code to the RP.
	if strings.HasPrefix(loc, testRedirect) {
		t.Fatalf("PASSWORD-FREE MFA BYPASS: federation minted a code for a 2FA user without the factor: %q", loc)
	}
	if !strings.HasSuffix(loc, PathMfaVerify) {
		t.Fatalf("a 2FA-enrolled federated login must go to the 2FA page, got %q", loc)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted before the second factor", n)
	}
	id := challengeOf(t, resp)

	// Present the factor → the code is minted and the RP redirect returned.
	req := jsonReq("POST", PathFederationMfa, map[string]string{"mfaType": factor.App, "passcode": passcode(t, secret)})
	req.Header.Set("Cookie", challengeCookie+"="+id)
	_, body := do(t, app, req)
	mm := decode(t, body)
	if mm["status"] != "ok" {
		t.Fatalf("resume with a valid factor failed: %v", mm["msg"])
	}
	rurl, _ := mm["data"].(string)
	if !strings.HasPrefix(rurl, testRedirect) {
		t.Fatalf("resume must return the RP redirect, got %q", rurl)
	}
	cb, _ := url.Parse(rurl)
	code := cb.Query().Get("code")
	if code == "" {
		t.Fatal("resume returned no authorization code")
	}
	if cb.Query().Get("state") != fedAppState {
		t.Errorf("app state not echoed on resume: %q", cb.Query().Get("state"))
	}
	tok, err := store2GetTokenByCode(db, code)
	if err != nil || tok == nil {
		t.Fatalf("minted code resolves to no token: %v", err)
	}
	if tok.User != "hanzo/alice" {
		t.Fatalf("code bound to %q, want hanzo/alice", tok.User)
	}
}

// A recovery code answers the federated challenge too, and is consumed once.
func TestFederationMfa_RecoveryCodeResumes(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", secret: "s3cret", redirectURIs: []string{testRedirect}})
	fedEnroll(t, db, "alice", "alice@example.com")
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

	p := fedResumeParams{ClientId: "webapp", RedirectUri: testRedirect, AppState: fedAppState, Scope: "openid"}
	payload, _ := json.Marshal(p)
	id, err := MintChallenge(context.Background(), db, KindFederation, "hanzo/alice", string(payload), []string{factor.App}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	req := jsonReq("POST", PathFederationMfa, map[string]string{"recoveryCode": plain})
	req.Header.Set("Cookie", challengeCookie+"="+id)
	_, body := do(t, app, req)
	if m := decode(t, body); m["status"] != "ok" {
		t.Fatalf("recovery-code resume failed: %v", m["msg"])
	}
	if got := userRow(t, db, "alice").RecoveryCodes; len(got) != 0 {
		t.Fatalf("recovery code not consumed: %v", got)
	}
}

// (b) A user with NO factor flows straight through federation exactly as before —
// the gate is invisible to everyone else.
func TestFederationMfa_UnenrolledUserFlowsThrough(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "bob", "alice@example.com", "pw") // matches the mock email, NO factor
	proveEmail(t, db, "bob")                          // linkable by address; see fedEnroll
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	cb, _ := url.Parse(loc)
	if cb.Query().Get("code") == "" {
		t.Fatalf("an unenrolled federated login must mint a code directly, got %q", loc)
	}
}

// (c) The federation challenge is single-use and expiring.
func TestFederationMfa_ChallengeSingleUseAndExpiring(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", secret: "s3cret", redirectURIs: []string{testRedirect}})
	secret := fedEnroll(t, db, "alice", "alice@example.com")

	mk := func(now time.Time) string {
		p := fedResumeParams{ClientId: "webapp", RedirectUri: testRedirect, AppState: fedAppState, Scope: "openid"}
		payload, _ := json.Marshal(p)
		id, err := MintChallenge(context.Background(), db, KindFederation, "hanzo/alice", string(payload), []string{factor.App}, now)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	resume := func(id string) map[string]any {
		req := jsonReq("POST", PathFederationMfa, map[string]string{"mfaType": factor.App, "passcode": passcode(t, secret)})
		req.Header.Set("Cookie", challengeCookie+"="+id)
		_, body := do(t, app, req)
		return decode(t, body)
	}

	// single-use: first spends, second is refused.
	id := mk(time.Now())
	if m := resume(id); m["status"] != "ok" {
		t.Fatalf("first resume failed: %v", m["msg"])
	}
	if m := resume(id); m["status"] != "error" {
		t.Fatalf("a spent federation challenge was accepted again: %v", m)
	}

	// expiring: a challenge past its TTL is refused before any factor is checked.
	start := time.Unix(1_800_000_000, 0)
	nowFuncSet(t, start)
	id2 := mk(start)
	nowFuncSet(t, start.Add(challengeTTL+time.Second))
	if m := resume(id2); m["status"] != "error" {
		t.Fatalf("an expired federation challenge was accepted: %v", m)
	}
}

// (d) The target user and redirect_uri are PINNED in the challenge: the resume
// body has no field that can swap them, and extra request fields are ignored.
func TestFederationMfa_UserAndRedirectPinned(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedApp(t, db, appOpts{clientID: "evil", secret: "x", redirectURIs: []string{"https://evil.example/cb"}})
	secret := fedEnroll(t, db, "alice", "alice@example.com")
	seedUser(t, db, "mallory", "mallory@example.com", "pw")

	p := fedResumeParams{ClientId: "webapp", RedirectUri: testRedirect, AppState: fedAppState, Scope: "openid"}
	payload, _ := json.Marshal(p)
	id, err := MintChallenge(context.Background(), db, KindFederation, "hanzo/alice", string(payload), []string{factor.App}, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	// The body tries to steer the ceremony at another user, app, and redirect.
	req := jsonReq("POST", PathFederationMfa, map[string]string{
		"mfaType": factor.App, "passcode": passcode(t, secret),
		"username": "mallory", "name": "mallory", "clientId": "evil", "redirectUri": "https://evil.example/cb",
	})
	req.Header.Set("Cookie", challengeCookie+"="+id)
	_, body := do(t, app, req)
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("resume failed: %v", m["msg"])
	}
	rurl, _ := m["data"].(string)
	if !strings.HasPrefix(rurl, testRedirect) {
		t.Fatalf("redirect_uri not pinned — the body steered it to %q", rurl)
	}
	cb, _ := url.Parse(rurl)
	tok, err := store2GetTokenByCode(db, cb.Query().Get("code"))
	if err != nil || tok == nil {
		t.Fatalf("no token for the minted code: %v", err)
	}
	if tok.User != "hanzo/alice" {
		t.Fatalf("target user not pinned — code bound to %q", tok.User)
	}
	if tok.RedirectUri != testRedirect {
		t.Fatalf("redirect_uri not pinned on the code: %q", tok.RedirectUri)
	}
}

// A missing/forged challenge fails closed — no user, no code.
func TestFederationMfa_NoChallengeFailsClosed(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	req := jsonReq("POST", PathFederationMfa, map[string]string{"mfaType": factor.App, "passcode": "000000"})
	_, body := do(t, app, req) // no cookie, no body challenge
	if m := decode(t, body); m["status"] != "error" {
		t.Fatalf("a resume with no challenge must fail closed, got %v", m)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token(s) minted with no challenge", n)
	}
}

// A DELIVERED factor answers a federated login too. This is the drift the one shared
// verify closes: there were two switches, and the federated one accepted only TOTP
// while calling itself "the ONE factor seam, shared with the password gate". An
// account holding just an emailed or texted factor could answer a password login and
// not this one — it was simply locked out of signing in through Google.
func TestFederationMfa_DeliveredFactorResumes(t *testing.T) {
	app, db := newServer(t)
	f := &fakeSender{}
	bindSender(t, f)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@example.com", "pw")
	proveEmail(t, db, "alice") // linkable by address; see fedEnroll

	// An EMAIL factor and nothing else — no authenticator on the row.
	u := userRow(t, db, "alice")
	factor.Add(u, factor.Email, "")
	if err := factor.Prefer(u, factor.Email); err != nil {
		t.Fatal(err)
	}
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}

	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	if loc := resp.Header.Get("Location"); !strings.HasSuffix(loc, PathMfaVerify) {
		t.Fatalf("a federated login owing a delivered factor went to %q", loc)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted before the second factor", n)
	}
	// The challenge SENT the code, to the address on the account.
	if len(f.sent) != 1 {
		t.Fatalf("sent %d messages, want one code to the account's own address", len(f.sent))
	}
	if m := f.sent[0]; m.Org != "hanzo" || m.Channel != otp.Email || m.To != "alice@example.com" {
		t.Fatalf("sent %+v, want one code to the account's own address", m)
	}
	code := codeIn(t, f.sent[0].Body)

	req := jsonReq("POST", PathFederationMfa, map[string]string{"mfaType": factor.Email, "passcode": code})
	req.Header.Set("Cookie", challengeCookie+"="+challengeOf(t, resp))
	_, body := do(t, app, req)
	mm := decode(t, body)
	if mm["status"] != "ok" {
		t.Fatalf("a delivered factor was refused on the federated resume: %v", mm["msg"])
	}
	if rurl, _ := mm["data"].(string); !strings.HasPrefix(rurl, testRedirect) {
		t.Fatalf("resume returned %q, want the RP redirect", rurl)
	}
}

// The federated resume checks the offer too, on the same challenge row and through
// the same function. An account holding only an authenticator cannot be resumed with
// an emailed code.
func TestFederationMfa_RefusesAFactorItDidNotOffer(t *testing.T) {
	app, db := newServer(t)
	bindSender(t, &fakeSender{})
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	fedEnroll(t, db, "alice", "alice@example.com") // authenticator only

	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)

	// A live code for her address, minted for another purpose entirely.
	if err := otp.Issue(context.Background(), db, "hanzo", "alice@example.com", "", nil, time.Now()); err != nil {
		t.Fatal(err)
	}
	rec, err := store.GetLatestVerificationRecord(context.Background(), db, "hanzo", "alice@example.com")
	if err != nil || rec == nil {
		t.Fatalf("seed code not persisted: %v", err)
	}

	req := jsonReq("POST", PathFederationMfa, map[string]string{"mfaType": factor.Email, "passcode": rec.Code})
	req.Header.Set("Cookie", challengeCookie+"="+challengeOf(t, resp))
	_, body := do(t, app, req)
	if mm := decode(t, body); mm["status"] != "error" {
		t.Fatalf("an emailed code resumed an authenticator-only federated login: %#v", mm)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted", n)
	}
}
