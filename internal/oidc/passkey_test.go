// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/store"
)

// An operator signs in with a passkey. These read the doors a password can be
// typed into and assert the reserved org is not behind any of them.
//
// Each seeds a CORRECT password and a working application, so the only thing
// standing between the request and a grant is the rule under test — remove it and
// every one of these mints. That is the point: a test that would pass with the
// rule deleted is not evidence of anything.

// seedOperator creates a user anchored in a brand org who holds a membership in
// the reserved org. This is the shape an operator actually has — someone who runs
// the platform AND does ordinary work in a brand org — and it is the shape a guard
// written on the org NAME cannot see.
func seedOperator(t *testing.T, db orm.DB, org, name, password string) {
	t.Helper()
	seedUserInOrg(t, db, org, name, name+"@"+org+".example", password)
	if _, err := store.EnsureMembership(tctx(), db, org+"/"+name, store.AdminOrg, store.RoleAdmin); err != nil {
		t.Fatalf("grant the reserved-org membership: %v", err)
	}
}

// The headline. An operator anchored in a brand org types the right password into
// the front door and gets no code.
//
// Nothing else in the request is wrong: the org is the application's own, the
// application is an ordinary one, the password verifies. Reserved-org confinement
// (mint.go) reads the OWNER half of the user id, which here is "hanzo" — so that
// rule sees an ordinary tenant user and would mint. This is the case the estate's
// other reserved-org guards miss, and it is the one that matters, because it is
// how the real operators are provisioned.
func TestPasswordAloneMintsNothingForAnOperator(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedOperator(t, db, "hanzo", "z", "correct-horse")

	code, _, body := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "z", "password": "correct-horse",
		"clientId": "conf", "redirectUri": testRedirect, "scope": "openid",
	})
	m := decode(t, body)
	if m["status"] != "error" {
		t.Fatalf("a correct password minted a grant for an operator; got %v", m)
	}
	if code != "" {
		t.Fatalf("an authorization code was minted for an operator: %q", code)
	}
	if m["msg"] != PasskeyOnly {
		t.Errorf("msg = %q, want %q — the refusal must say which credential is owed, "+
			"or the operator cannot tell it from a mistyped password", m["msg"], PasskeyOnly)
	}
}

// The same refusal for an account anchored IN the reserved org, through the one
// application that serves it. Confinement admits this pair by design (that console
// is exactly where a reserved-org principal is allowed to sign in), so the password
// reaches the end of the flow and this is the only thing that stops it.
func TestPasswordAloneMintsNothingForTheReservedOrg(t *testing.T) {
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: "console", secret: "s3cret", redirectURIs: []string{testRedirect}})
	a.Organization = "admin" // the reserved org's own console
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatalf("point the app at the reserved org: %v", err)
	}
	seedUserInOrg(t, db, "admin", "a", "a@hanzo.ai", "correct-horse")

	code, _, body := loginForCode(t, app, map[string]string{
		"organization": "admin", "username": "a", "password": "correct-horse",
		"clientId": "console", "redirectUri": testRedirect, "scope": "openid",
	})
	m := decode(t, body)
	if m["status"] != "error" || code != "" {
		t.Fatalf("a correct password minted a grant for the reserved org: code=%q %v", code, m)
	}
	if m["msg"] != PasskeyOnly {
		t.Errorf("msg = %q, want %q", m["msg"], PasskeyOnly)
	}
}

// The control, and the reason the two above are not simply "login is broken".
// An ordinary account in the same org, same application, same shape of request,
// still signs in with its password.
func TestAnOrdinaryAccountStillSignsInWithItsPassword(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "dana", "dana@hanzo.example", "correct-horse")

	code, _, body := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "dana", "password": "correct-horse",
		"clientId": "conf", "redirectUri": testRedirect, "scope": "openid",
	})
	if m := decode(t, body); m["status"] != "ok" {
		t.Fatalf("an ordinary password sign-in was refused; got %v", m)
	}
	if code == "" {
		t.Fatal("an ordinary password sign-in minted no code")
	}
}

// The password grant is the same password over a different door, and it must
// answer the same way.
//
// The reserved-org check already on this grant reads the `organization` PARAMETER,
// so it refuses organization=admin and admits this request, whose organization is
// the operator's brand org. The password verifies; only the identity question
// stops it.
func TestPasswordGrantMintsNothingForAnOperator(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{
		clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect},
		grants: []string{"password"},
	})
	seedOperator(t, db, "hanzo", "z", "correct-horse")

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "conf")
	form.Set("client_secret", "s3cret")
	form.Set("organization", "hanzo")
	form.Set("username", "z")
	form.Set("password", "correct-horse")
	_, body := do(t, app, formReq("POST", PathToken, form))

	m := decode(t, body)
	if _, minted := m["access_token"]; minted {
		t.Fatalf("the password grant minted an access token for an operator: %v", m)
	}
	if m["error"] != "invalid_grant" {
		t.Errorf("error = %v, want invalid_grant; got %v", m["error"], m)
	}
	if m["error_description"] != PasskeyOnly {
		t.Errorf("error_description = %q, want %q", m["error_description"], PasskeyOnly)
	}
}

// Signing in through Google is a password somewhere else, and it does not open the
// reserved org either.
//
// This door decides its second factor inline instead of through Gate, so it is the
// one that would have drifted: an operator who could not type a password into the
// front door could still arrive here holding a Google account and be minted a code.
// The identity is the same identity, so the answer is the same answer.
func TestFederatedSignInMintsNothingForAnOperator(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "bob", "alice@example.com", "pw") // matches the mock IdP's email
	proveEmail(t, db, "bob")                          // linkable by verified address
	if _, err := store.EnsureMembership(tctx(), db, "hanzo/bob", store.AdminOrg, store.RoleAdmin); err != nil {
		t.Fatalf("grant the reserved-org membership: %v", err)
	}
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-1", cookie), testRedirect)
	cb, _ := url.Parse(loc)
	if code := cb.Query().Get("code"); code != "" {
		t.Fatalf("a federated login minted a code for an operator: %q", code)
	}
	if got := cb.Query().Get("error"); got != errAccessDenied {
		t.Fatalf("error = %q, want %q (%s)", got, errAccessDenied, loc)
	}
	if got := cb.Query().Get("error_description"); got != PasskeyOnly {
		t.Errorf("error_description = %q, want %q", got, PasskeyOnly)
	}
}

// The paired control: the SAME federated flow, the same mock IdP, an ordinary
// account — still mints. Without it the refusal above could be a broken callback.
func TestFederatedSignInStillWorksForAnOrdinaryAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "bob", "alice@example.com", "pw")
	proveEmail(t, db, "bob")
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-1", cookie), testRedirect)
	cb, _ := url.Parse(loc)
	if cb.Query().Get("code") == "" {
		t.Fatalf("an ordinary federated login minted no code: %q", loc)
	}
}

// mintedToken reads the access token out of the mint's envelope, which carries it
// under `data` — reading the top level finds nothing and would call every refusal a
// pass.
func mintedToken(t *testing.T, body []byte) string {
	t.Helper()
	data, _ := decode(t, body)["data"].(map[string]any)
	tok, _ := data["accessToken"].(string)
	return tok
}

// The on-behalf-of mint takes no user credential at all, so it is the one door a
// passkey rule cannot reach by asking what was proven — it has to ask who the
// TARGET is.
//
// The reserved-org gate here refused ?id=admin/z and admitted ?id=hanzo/z, because
// it read the owner half of the target id. Both ids name a SuperAdmin; only one of
// them looks like one. A general minter reaching the second mints a token whose
// `orgs` claim carries admin/admin — the same platform authority, from a client
// secret and nothing else.
func TestOnBehalfOfMintCannotReachAnOperatorInABrandOrg(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console") // general minter, not an admin minter
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedOperator(t, db, "hanzo", "z", "correct-horse")

	resp, body := do(t, app, keyReq(PathTokensIssue, "hanzo-console", "top-secret", "?id=hanzo/z"))
	if resp.StatusCode != 403 {
		t.Fatalf("a general minter reached an operator target hanzo/z (status=%d); body=%s", resp.StatusCode, body)
	}
	if mintedToken(t, body) != "" {
		t.Fatalf("a token was minted for an operator: %s", body)
	}
}

// The paired control: an ordinary target in the same org is still mintable, so the
// refusal above is about the identity and not about the endpoint being shut.
func TestOnBehalfOfMintStillReachesAnOrdinaryTarget(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "dana", "dana@hanzo.example", "correct-horse")

	resp, body := do(t, app, keyReq(PathTokensIssue, "hanzo-console", "top-secret", "?id=hanzo/dana"))
	if resp.StatusCode != 200 {
		t.Fatalf("an ordinary target was refused (status=%d); body=%s", resp.StatusCode, body)
	}
	if mintedToken(t, body) == "" {
		t.Fatalf("no token minted for an ordinary target: %s", body)
	}
}

// An ordinary account still holds a password grant — the same control, one door
// over, so a refusal above cannot be the whole endpoint being closed.
func TestPasswordGrantStillWorksForAnOrdinaryAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{
		clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect},
		grants: []string{"password"},
	})
	seedUser(t, db, "dana", "dana@hanzo.example", "correct-horse")

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", "conf")
	form.Set("client_secret", "s3cret")
	form.Set("organization", "hanzo")
	form.Set("username", "dana")
	form.Set("password", "correct-horse")
	_, body := do(t, app, formReq("POST", PathToken, form))

	if m := decode(t, body); m["access_token"] == nil {
		t.Fatalf("an ordinary password grant minted no token: %v", m)
	}
}
