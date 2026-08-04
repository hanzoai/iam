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
	id, err := MintChallenge(context.Background(), db, KindFederation, "hanzo/alice", string(payload), time.Now())
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
		id, err := MintChallenge(context.Background(), db, KindFederation, "hanzo/alice", string(payload), now)
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
	id, err := MintChallenge(context.Background(), db, KindFederation, "hanzo/alice", string(payload), time.Now())
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
