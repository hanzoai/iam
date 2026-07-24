// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/iam/internal/store"
)

// Client authentication on the browser-redeem grants (authorization_code +
// refresh_token) gates on what the REQUEST presents, never on whether a secret is
// STORED on the app. Every one of the 275 casdoor-migrated apps carries a
// casdoor-generated secret, so the old `app.ClientSecret != ""` discriminator made
// EVERY public PKCE browser redeem fail 401 invalid_client — the defect that broke
// commerce/admin/insights/analytics/base and every brand *.id SPA and forced the
// production rollback.
//
// The invariant these tests pin:
//   - a secret is REQUIRED only when the request presents one (confidential) OR the
//     code is not PKCE-bound (nothing else proves the client);
//   - a secretless redeem is accepted ONLY when PKCE (auth_code) / the rotating
//     refresh token (refresh) proves possession;
//   - a secretless NON-PKCE redeem is REJECTED (strictly more secure than casdoor,
//     which accepted it);
//   - the confidential path is UNCHANGED: a presented secret must match, constant-time.

// migratedSecret stands in for the casdoor-generated secret every migrated app row
// carries — the value that made `app.ClientSecret != ""` true for all of them.
const migratedSecret = "casdoor-generated-client-secret"

// pkceVerifier is a fixed RFC 7636 verifier reused across the browser-path cases.
const pkceVerifier = "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"

// loginPKCE returns a type=code login body carrying the S256 challenge for
// pkceVerifier — the browser (public) authorize shape.
func loginPKCE(clientID, scope string) map[string]string {
	p := loginParams(clientID, scope)
	p["codeChallenge"] = ComputeS256Challenge(pkceVerifier)
	p["codeChallengeMethod"] = "S256"
	return p
}

// TestAuthCodeFlow_ClientAuthGatesOnRequest is the authorization_code half of the
// re-cutover gate. Every sub-case runs against an app record that HAS a stored
// secret — the exact shape (migrated app) the old discriminator mis-handled.
func TestAuthCodeFlow_ClientAuthGatesOnRequest(t *testing.T) {
	// (1) THE BROKEN CASE, fail-before = 401: a migrated app (stored secret) redeemed
	// in-browser as a public PKCE client that presents NO secret → 200.
	t.Run("migrated_app_pkce_without_secret_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "cloud", secret: migratedSecret, redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		code, _, _ := loginForCode(t, app, loginPKCE("cloud", "openid"))
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"cloud"}, "redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
			// no client_secret — the browser has none
		})
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("migrated-app PKCE redeem without secret: status=%d body=%v; want 200 "+
				"(fail-before: old app.ClientSecret!=\"\" branch returned 401 invalid_client)", resp.StatusCode, tok)
		}
	})

	// (2) Confidential client, correct secret → 200 (a non-PKCE, server-side code).
	t.Run("confidential_correct_secret_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "cloud", secret: migratedSecret, redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		code, _, _ := loginForCode(t, app, loginParams("cloud", "openid"))
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"cloud"}, "client_secret": {migratedSecret}, "redirect_uri": {testRedirect},
		})
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("confidential redeem with correct secret: status=%d body=%v; want 200", resp.StatusCode, tok)
		}
	})

	// (3) Confidential client, WRONG secret → 401 (unchanged from prior behavior).
	t.Run("confidential_wrong_secret_401", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "cloud", secret: migratedSecret, redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		code, _, _ := loginForCode(t, app, loginParams("cloud", "openid"))
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"cloud"}, "client_secret": {"WRONG"}, "redirect_uri": {testRedirect},
		})
		requireError(t, resp, tok, 401, "invalid_client")
	})

	// (3b) HARDENING: presenting a secret commits you to the confidential path — a
	// WRONG secret is 401 EVEN WITH a valid PKCE verifier. No secret→PKCE downgrade.
	t.Run("wrong_secret_not_rescued_by_valid_pkce_401", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "cloud", secret: migratedSecret, redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		code, _, _ := loginForCode(t, app, loginPKCE("cloud", "openid"))
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"cloud"}, "client_secret": {"WRONG"},
			"redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
		})
		requireError(t, resp, tok, 401, "invalid_client")
	})

	// (4a) Secretless NON-PKCE redeem against a migrated (stored-secret) app →
	// rejected 401. Neither a secret nor a PKCE proof is presented.
	t.Run("secretless_nonpkce_migrated_app_rejected", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "cloud", secret: migratedSecret, redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		code, _, _ := loginForCode(t, app, loginParams("cloud", "openid")) // non-PKCE code (allowed: app has a secret)
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"cloud"}, "redirect_uri": {testRedirect},
			// no secret, no verifier
		})
		requireError(t, resp, tok, 401, "invalid_client")
	})

	// (4b) Secretless NON-PKCE redeem against a PUBLIC (no stored secret) app →
	// rejected 401. Login refuses to MINT a non-PKCE code for a public app, so the
	// code is crafted directly: the token endpoint's own guard must still reject it,
	// independent of how the code arrived (casdoor accepted this; we do not).
	t.Run("secretless_nonpkce_public_app_rejected", func(t *testing.T) {
		app, db := newServer(t)
		pub := seedApp(t, db, appOpts{clientID: "pubapp", redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		ctx := context.Background()
		code, err := MintCode(pub, "hanzo/alice", "openid", "", "", "", nowFunc()) // no challenge → non-PKCE
		if err != nil {
			t.Fatalf("mint non-pkce code: %v", err)
		}
		if err := store.PersistToken(ctx, db, code); err != nil {
			t.Fatalf("persist code: %v", err)
		}
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code.Code}, "client_id": {"pubapp"}, "redirect_uri": {testRedirect},
		})
		requireError(t, resp, tok, 401, "invalid_client")
	})

	// (5) THE DUAL-USE PROOF: ONE app record (hanzo-cloud, stored secret) is redeemed
	// BOTH server-side WITH the secret (console) AND in-browser via PKCE WITHOUT it
	// (insights/analytics) — both 200. This is why clearing the secret cannot fix the
	// defect and the discriminator must be per-REQUEST.
	t.Run("dual_use_one_record_both_paths_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "console-secret", redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		// console: server-side, confidential, non-PKCE code + secret
		codeA, _, _ := loginForCode(t, app, loginParams("hanzo-cloud", "openid"))
		respA, tokA := exchangeCode(t, app, url.Values{
			"code": {codeA}, "client_id": {"hanzo-cloud"}, "client_secret": {"console-secret"}, "redirect_uri": {testRedirect},
		})
		if respA.StatusCode != 200 || tokA["access_token"] == nil {
			t.Fatalf("console (confidential) redeem on dual-use record: status=%d body=%v; want 200", respA.StatusCode, tokA)
		}

		// insights/analytics: in-browser, public, PKCE, NO secret — SAME record
		codeB, _, _ := loginForCode(t, app, loginPKCE("hanzo-cloud", "openid"))
		respB, tokB := exchangeCode(t, app, url.Values{
			"code": {codeB}, "client_id": {"hanzo-cloud"}, "redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
		})
		if respB.StatusCode != 200 || tokB["access_token"] == nil {
			t.Fatalf("browser (public PKCE) redeem on the SAME dual-use record: status=%d body=%v; want 200", respB.StatusCode, tokB)
		}
	})
}

// TestRefresh_ClientAuthGatesOnRequest is the refresh_token mirror: a public client
// refreshes with no secret (bound by the rotating, reuse-detected refresh token
// itself); a request that presents a secret is held to the confidential rule. Every
// case runs against a dual-use record that HAS a stored secret.
func TestRefresh_ClientAuthGatesOnRequest(t *testing.T) {
	// (6) Public/browser refresh with NO secret → 200, against a record that has a
	// stored secret. Fail-before: grantViaPKCE itself 401s on the has-secret app.
	t.Run("dual_use_refresh_without_secret_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "console-secret", redirectURIs: []string{testRedirect}, refreshHours: 24})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		tok := grantViaPKCE(t, app, "hanzo-cloud", "openid offline_access") // browser grant, no secret
		rt := tok["refresh_token"].(string)

		status, out := refresh(t, app, "hanzo-cloud", rt, nil) // refresh with NO secret
		if status != 200 || out["refresh_token"] == nil {
			t.Fatalf("dual-use browser refresh without secret: status=%d body=%v; want 200", status, out)
		}
	})

	// (6b) Confidential refresh with the CORRECT secret → 200 (same record).
	t.Run("dual_use_refresh_correct_secret_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "console-secret", redirectURIs: []string{testRedirect}, refreshHours: 24})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		tok := grantViaPKCE(t, app, "hanzo-cloud", "openid offline_access")
		rt := tok["refresh_token"].(string)

		status, out := refresh(t, app, "hanzo-cloud", rt, url.Values{"client_secret": {"console-secret"}})
		if status != 200 || out["refresh_token"] == nil {
			t.Fatalf("dual-use refresh with correct secret: status=%d body=%v; want 200", status, out)
		}
	})

	// (6c) A presented-but-WRONG secret on refresh → 401: the confidential path stays
	// strict; presenting a secret commits you to it.
	t.Run("refresh_wrong_secret_401", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "console-secret", redirectURIs: []string{testRedirect}, refreshHours: 24})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		tok := grantViaPKCE(t, app, "hanzo-cloud", "openid offline_access")
		rt := tok["refresh_token"].(string)

		status, out := refresh(t, app, "hanzo-cloud", rt, url.Values{"client_secret": {"WRONG"}})
		if status != 401 || out["error"] != "invalid_client" {
			t.Fatalf("refresh with wrong secret: status=%d err=%v; want 401 invalid_client", status, out["error"])
		}
	})
}
