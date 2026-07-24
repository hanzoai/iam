// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/iam/internal/store"
)

// Client authentication on the browser-redeem grants (authorization_code +
// refresh_token) is discriminated by the GRANT — the code's PKCE binding, and the
// token family's provenance on refresh — never by whether the REQUEST carries a
// secret. Every one of the 275 migrated apps carries a stored client secret, and the
// real SPAs and backends (hanzo-commerce, admin-console, hanzo-cloud, insights,
// analytics, base, every brand *.id) redeem a PKCE code while ALSO echoing a
// configured, often-STALE secret. Verifying that presented secret 401'd
// invalid_client on every browser redeem — the defect that forced the production
// rollback. The in-fork authority never verified it.
//
// The RFC 7636 invariant these tests pin:
//   - a PKCE-bound code is authenticated by the code_verifier; a presented
//     client_secret is IGNORED — even a wrong/stale one is NOT a 401 (the regression);
//   - a non-PKCE code is confidential: a matching client_secret is REQUIRED,
//     constant-time, and a secretless non-PKCE redeem is REJECTED (stronger than the
//     fork, which accepted it);
//   - a PKCE redeem with an INVALID verifier still fails (no secret→PKCE or
//     PKCE→secret bypass);
//   - on refresh, a public grant (PKCE-origin, or a secretless client) is
//     authenticated by its rotating, reuse-detected refresh token and a presented
//     secret is ignored; a confidential grant (stored secret + non-PKCE origin) MUST
//     present its secret.
//
// Every case runs against an app record that HAS a stored secret — the exact shape (a
// migrated app) the in-browser flow hits and a secretless programmatic probe missed.

// migratedSecret stands in for the generated secret every migrated app row carries —
// the value that made `app.ClientSecret != ""` true for all of them.
const migratedSecret = "migrated-generated-client-secret"

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

	// (2b) UNIFICATION: a confidential (non-PKCE) client that sends client_id in the FORM
	// but its secret in the Authorization: Basic header authenticates → 200. The prior
	// clientAuth returned as soon as a form client_id was present, silently DROPPING the
	// Basic secret, so this legitimate client 401'd (it verified "" against the stored
	// secret). The extraction now fills the secret from either channel uniformly.
	// fail-before = 401.
	t.Run("confidential_form_id_basic_secret_unified_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "cloud", secret: migratedSecret, redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		code, _, _ := loginForCode(t, app, loginParams("cloud", "openid")) // non-PKCE code
		form := url.Values{
			"grant_type": {"authorization_code"}, "code": {code},
			"client_id": {"cloud"}, "redirect_uri": {testRedirect},
			// client_id in the FORM; secret in the BASIC header below
		}
		req := formReq("POST", PathToken, form)
		req.SetBasicAuth("cloud", migratedSecret)
		resp, body := do(t, app, req)
		tok := decode(t, body)
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("confidential form-id + Basic-secret: status=%d body=%v; want 200 "+
				"(fail-before: prior clientAuth dropped the Basic secret when client_id was in the form → 401)", resp.StatusCode, tok)
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

	// (1b) THE REGRESSION, fail-before = 401: a migrated app redeemed in-browser via
	// PKCE while ALSO presenting a stale/wrong client_secret in the FORM → 200. PKCE
	// authenticates; the presented secret is IGNORED. This is the exact in-browser shape
	// (the SPA echoes a configured, often-stale secret) that the prior fix still 401'd —
	// its programmatic gate sent NO secret and went green, so ONLY this case, WITH a
	// secret, reproduces the live break.
	t.Run("pkce_redeem_ignores_stale_form_secret_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "cloud", secret: migratedSecret, redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		code, _, _ := loginForCode(t, app, loginPKCE("cloud", "openid"))
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"cloud"}, "client_secret": {"STALE-secret-from-the-SPA"},
			"redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
		})
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("PKCE redeem with a stale FORM secret: status=%d body=%v; want 200 "+
				"(fail-before: the prior fix verified the presented secret → 401 invalid_client)", resp.StatusCode, tok)
		}
	})

	// (1c) THE SAME REGRESSION via the HTTP-Basic channel: PKCE code, NO form secret, a
	// stale secret in Authorization: Basic → 200. Proves the secret source is unified — a
	// Basic stale secret is ignored on a PKCE redeem exactly as a form one is. Before the
	// clientAuth unification a Basic secret was silently dropped whenever client_id rode
	// in the form, so a form wrong-secret 401'd while a Basic wrong-secret was ignored;
	// the extraction now treats both channels identically.
	t.Run("pkce_redeem_ignores_stale_basic_secret_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "cloud", secret: migratedSecret, redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		code, _, _ := loginForCode(t, app, loginPKCE("cloud", "openid"))
		form := url.Values{
			"grant_type": {"authorization_code"},
			"code":       {code}, "client_id": {"cloud"},
			"redirect_uri": {testRedirect}, "code_verifier": {pkceVerifier},
			// no client_secret in the body — it rides in the Basic header below
		}
		req := formReq("POST", PathToken, form)
		req.SetBasicAuth("cloud", "STALE-secret-from-the-SPA")
		resp, body := do(t, app, req)
		tok := decode(t, body)
		if resp.StatusCode != 200 || tok["access_token"] == nil {
			t.Fatalf("PKCE redeem with a stale BASIC secret: status=%d body=%v; want 200", resp.StatusCode, tok)
		}
	})

	// (3b) HARDENING: a PKCE redeem with an INVALID verifier still fails — presenting a
	// (here, matching) secret does NOT rescue a broken PKCE proof. No PKCE→secret
	// fallback: on a PKCE-bound code the verifier is the authentication, and RedeemCode
	// refuses a bad one (400 invalid_grant) before any secret could be consulted.
	t.Run("pkce_bad_verifier_not_rescued_by_secret_400", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "cloud", secret: migratedSecret, redirectURIs: []string{testRedirect}})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		code, _, _ := loginForCode(t, app, loginPKCE("cloud", "openid"))
		resp, tok := exchangeCode(t, app, url.Values{
			"code": {code}, "client_id": {"cloud"}, "client_secret": {migratedSecret},
			"redirect_uri": {testRedirect}, "code_verifier": {"the-WRONG-verifier-000000000000000000000000"},
		})
		requireError(t, resp, tok, 400, "invalid_grant")
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

	// (6b) A public (PKCE-origin) refresh that presents the CORRECT secret → 200. The
	// secret is now IGNORED (a public grant is authenticated by the rotating token); the
	// value simply does not matter. Same 200 as the fork, different reason.
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

	// (6c) THE REFRESH REGRESSION, fail-before = 401: a public (PKCE-origin) grant
	// refreshed while presenting a stale/WRONG secret → 200. The rotating,
	// reuse-detected refresh token authenticates; the presented secret is IGNORED — the
	// SPA echoes a configured stale secret on refresh exactly as on the code exchange.
	t.Run("dual_use_refresh_ignores_stale_secret_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "console-secret", redirectURIs: []string{testRedirect}, refreshHours: 24})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		tok := grantViaPKCE(t, app, "hanzo-cloud", "openid offline_access")
		rt := tok["refresh_token"].(string)

		status, out := refresh(t, app, "hanzo-cloud", rt, url.Values{"client_secret": {"STALE"}})
		if status != 200 || out["refresh_token"] == nil {
			t.Fatalf("public refresh with a stale secret: status=%d body=%v; want 200 "+
				"(fail-before: the prior rule verified a presented secret → 401 invalid_client)", status, out)
		}
	})

	// (6d) DURABILITY across rotation: rotate a dual-use PKCE grant once, then refresh
	// the SUCCESSOR with a stale secret → still 200. Without carrying the PKCE provenance
	// onto the rotated row, the successor (against a record that HAS a stored secret)
	// would be misread as confidential and 401 — the bug re-emerging one hop later.
	t.Run("dual_use_refresh_public_survives_rotation_200", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "console-secret", redirectURIs: []string{testRedirect}, refreshHours: 24})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		tok := grantViaPKCE(t, app, "hanzo-cloud", "openid offline_access")
		rt1 := tok["refresh_token"].(string)

		_, out1 := refresh(t, app, "hanzo-cloud", rt1, nil) // rotate → successor
		rt2, _ := out1["refresh_token"].(string)
		if rt2 == "" {
			t.Fatalf("first rotation did not mint a successor: %v", out1)
		}
		status, out2 := refresh(t, app, "hanzo-cloud", rt2, url.Values{"client_secret": {"STALE"}})
		if status != 200 || out2["refresh_token"] == nil {
			t.Fatalf("rotated public successor with a stale secret: status=%d body=%v; want 200 "+
				"(fail-before: PKCE provenance not carried onto the rotated row → misclassified confidential → 401)", status, out2)
		}
	})

	// (7) CONFIDENTIAL refresh — the console/server-side grant (a NON-PKCE code redeemed
	// with the secret). Its family carries NO PKCE provenance, so the client MUST present
	// a matching secret on refresh (RFC 9700 §4.13.2). Correct → 200; wrong → 401. This
	// path stays strict — the browser fix does not downgrade it.
	t.Run("confidential_refresh_correct_then_wrong_secret", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "console-secret", redirectURIs: []string{testRedirect}, refreshHours: 24})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		tok := grantViaConfidential(t, app, "hanzo-cloud", "console-secret", "openid offline_access")
		rt := tok["refresh_token"].(string)

		status, out := refresh(t, app, "hanzo-cloud", rt, url.Values{"client_secret": {"console-secret"}})
		if status != 200 || out["refresh_token"] == nil {
			t.Fatalf("confidential refresh with correct secret: status=%d body=%v; want 200", status, out)
		}
		rt2 := out["refresh_token"].(string)

		status, out = refresh(t, app, "hanzo-cloud", rt2, url.Values{"client_secret": {"WRONG"}})
		if status != 401 || out["error"] != "invalid_client" {
			t.Fatalf("confidential refresh with wrong secret: status=%d err=%v; want 401 invalid_client", status, out["error"])
		}
	})

	// (7b) A confidential grant refreshed with NO secret → 401. Per the decided rule, a
	// confidential grant (stored secret + non-PKCE origin) must authenticate on refresh;
	// the rotating token alone is not sufficient for it — the mirror of the auth-code
	// confidential path, which also rejects a secretless non-PKCE redeem.
	t.Run("confidential_refresh_without_secret_401", func(t *testing.T) {
		app, db := newServer(t)
		seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "console-secret", redirectURIs: []string{testRedirect}, refreshHours: 24})
		seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

		tok := grantViaConfidential(t, app, "hanzo-cloud", "console-secret", "openid offline_access")
		rt := tok["refresh_token"].(string)

		status, out := refresh(t, app, "hanzo-cloud", rt, nil) // no secret presented
		if status != 401 || out["error"] != "invalid_client" {
			t.Fatalf("confidential refresh without secret: status=%d err=%v; want 401 invalid_client "+
				"(a confidential grant must authenticate on refresh — RFC 9700 §4.13.2)", status, out["error"])
		}
	})
}
