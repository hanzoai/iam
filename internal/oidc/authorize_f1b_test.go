// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"net/url"
	"strings"
	"testing"
)

// F1b — the /oauth/authorize SSO fast path mints silently ONLY for a SAME-TENANT session
// (session subject's org == app.Organization). This is the defense-in-depth half of the
// login-CSRF fix: even if an app ever carries EnableAutoSignin + IsShared (the field gate
// F1a is the root closure), the silent mint is bounded to one tenant, so a code can never
// be minted for a victim signed into a DIFFERENT tenant and shipped to an attacker's
// callback. A cross-tenant session falls through to the interactive hosted login instead.

// (F1b-neg) THE DEAD CROSS-TENANT CSRF CHAIN. An attacker-owned PUBLIC app served under a
// DIFFERENT tenant ("acme"), shared + autosignin + an attacker redirect, is hit by a victim
// who holds a hanzo session (established through an unrelated hanzo app) — the top-nav the
// attacker triggers. The victim's org (hanzo) != the app's org (acme), so authorize mints
// NO code: it falls through to the hosted login, and nothing reaches the attacker's
// callback. FAIL-BEFORE (v1.33.5 @ 9a2706cc): IsShared bypassed MintFor's tenant gate, so
// the fast path minted a hanzo victim's code through the acme app and 302'd it to the
// attacker redirect_uri — full impersonation on one click.
func TestAuthorizeSSO_crossTenantSharedApp_fallsThrough(t *testing.T) {
	app, db := newServer(t)
	// The victim's own tenant login app + the victim, so we can mint a genuine hanzo session.
	seedAppFull(t, db, fullApp{clientID: "victim-portal", secret: "s3cret", org: "hanzo", redirects: []string{testRedirect}})
	seedUser(t, db, "victim", "victim@hanzo.ai", "pw")
	cookie := establishSession(t, app, "hanzo", "victim-portal", "victim", "pw")

	// The attacker's cross-tenant surface: PUBLIC (no secret, redeemed with the attacker's
	// own verifier), shared, autosignin, served under "acme", callback to the attacker.
	seedAppFull(t, db, fullApp{clientID: "evil-app", org: "acme", shared: true, autosignin: true, redirects: []string{testRedirect}})

	loc := authorizeSSO(t, app, cookie, url.Values{
		"response_type":  {"code"},
		"client_id":      {"evil-app"},
		"redirect_uri":   {testRedirect},
		"scope":          {"openid"},
		"code_challenge": {ComputeS256Challenge(pkceVerifier)},
	})
	if strings.HasPrefix(loc, testRedirect) {
		u, _ := url.Parse(loc)
		t.Fatalf("F1b/login-CSRF REOPENED: a cross-tenant shared+autosignin app minted a victim "+
			"code and 302'd it to the attacker redirect_uri (code=%q); Location=%q", u.Query().Get("code"), loc)
	}
	if !strings.HasPrefix(loc, hostedLoginPath) {
		t.Fatalf("expected fall-through to the hosted login; Location=%q", loc)
	}
}

// (F1b-pos) SAME-TENANT SSO IS UNCHANGED. The victim's own-tenant autosignin app (org ==
// session org) still mints silently and the public PKCE code redeems with only the verifier
// — the console/commerce flow the fast path exists for. Proves F1b did not break legitimate
// same-org silent SSO (the existing SSO suite mints same-org too and stays green).
func TestAuthorizeSSO_sameTenant_stillMints(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "good-app", org: "hanzo", autosignin: true, redirects: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	cookie := establishSession(t, app, "hanzo", "good-app", "alice", "pw")

	code := codeFromRedirect(t, authorizeSSO(t, app, cookie, url.Values{
		"response_type":  {"code"},
		"client_id":      {"good-app"},
		"redirect_uri":   {testRedirect},
		"scope":          {"openid"},
		"code_challenge": {ComputeS256Challenge(pkceVerifier)},
	}))
	resp, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"good-app"}, "redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
	})
	if resp.StatusCode != 200 || tok["access_token"] == nil {
		t.Fatalf("same-tenant SSO must still mint + redeem: status=%d body=%v; want 200", resp.StatusCode, tok)
	}
}
