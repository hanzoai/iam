// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Unlink self-authenticates (session cookie / bearer) on the public OIDC surface,
// so the harness only needs the one registered group — the same one the confidential
// flow mints the bearer from.
func newUnlinkServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	db := openTestDB(t)
	app := zip.New(zip.Config{AppName: "iam-unlink-test", DisableStartupMessage: true})
	Route(app.Group("").(*zip.App), db) // public: authorize/login/token AND the self-authenticating unlink
	return app, db
}

// linkGitHub declares a GitHub provider on the "conf" app (CanUnlink toggled) and
// stamps a GitHub subject onto the user, whose SignupApplication is that app.
func linkGitHub(t *testing.T, db orm.DB, user, subject string, canUnlink bool) {
	t.Helper()
	pv := orm.New[schema.Provider](db)
	pv.Owner, pv.Name, pv.Category, pv.Type = "admin", "prov-github-unlink", "OAuth", "GitHub"
	pv.SetId("admin/prov-github-unlink")
	// Idempotent across sub-tests sharing a db is not needed (each test opens its own).
	if err := pv.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed provider: %v", err)
	}
	a, err := orm.Get[schema.Application](db, "admin/conf")
	if err != nil {
		t.Fatalf("load conf app: %v", err)
	}
	a.Providers = append(a.Providers, &schema.ProviderItem{Owner: "admin", Name: "prov-github-unlink", CanSignIn: true, CanUnlink: canUnlink})
	if err := a.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("link provider: %v", err)
	}
	u := userRow(t, db, user)
	u.GitHub = subject
	u.SignupApplication = "conf"
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("stamp connector: %v", err)
	}
}

func doUnlink(t *testing.T, app *zip.App, bearer, providerType, owner, name string) (int, map[string]any) {
	t.Helper()
	req := jsonReq("POST", PathUnlink, map[string]any{
		"providerType": providerType,
		"user":         map[string]string{"owner": owner, "name": name},
	})
	req.Header.Set("Authorization", "Bearer "+bearer)
	resp, body := do(t, app, req)
	return resp.StatusCode, decode(t, body)
}

// The account holder unlinks its own GitHub link when the app permits it; the
// connector column is cleared.
func TestUnlink_SelfClearsLinkWhenPermitted(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkGitHub(t, db, "alice", "gh-alice", true)

	access := accessTokenFor(t, app, "openid") // bearer for hanzo/alice
	if _, m := doUnlink(t, app, access, "GitHub", "hanzo", "alice"); m["status"] != "ok" {
		t.Fatalf("self-unlink failed: %v", m["msg"])
	}
	if got := userRow(t, db, "alice").GitHub; got != "" {
		t.Fatalf("self-unlink did not clear the connector, got %q", got)
	}
}

// A holder cannot unlink ANOTHER account (not self, not super), and the target's
// link survives.
func TestUnlink_CrossUserRefused(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	seedUser(t, db, "bob", "bob@hanzo.ai", "pw")
	linkGitHub(t, db, "bob", "gh-bob", true)

	access := accessTokenFor(t, app, "openid") // bearer for hanzo/alice
	status, m := doUnlink(t, app, access, "GitHub", "hanzo", "bob")
	if m["status"] != "error" {
		t.Fatalf("cross-user unlink must be refused, got %v (status %d)", m, status)
	}
	if got := userRow(t, db, "bob").GitHub; got != "gh-bob" {
		t.Fatalf("a non-owner removed bob's link: %q", got)
	}
}

// When the application forbids unlinking (CanUnlink=false), a self-unlink is
// refused — an org that mandates federated sign-in keeps its users linked.
func TestUnlink_SelfRefusedWhenAppForbids(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkGitHub(t, db, "alice", "gh-alice", false)

	access := accessTokenFor(t, app, "openid")
	if _, m := doUnlink(t, app, access, "GitHub", "hanzo", "alice"); m["status"] != "error" {
		t.Fatalf("self-unlink must be refused when the app forbids it, got %v", m)
	}
	if got := userRow(t, db, "alice").GitHub; got != "gh-alice" {
		t.Fatalf("a forbidden unlink still cleared the connector: %q", got)
	}
}

// An unauthenticated request is refused (the SDK envelope carries status:error on
// a 200, the casibase contract) and clears nothing.
func TestUnlink_RequiresAuthentication(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkGitHub(t, db, "alice", "gh-alice", true)

	req := jsonReq("POST", PathUnlink, map[string]any{"providerType": "GitHub", "user": map[string]string{"owner": "hanzo", "name": "alice"}})
	_, body := do(t, app, req) // no bearer, no session cookie
	if m := decode(t, body); m["status"] != "error" {
		t.Fatalf("unlink without authentication must be refused, got %v", m)
	}
	if got := userRow(t, db, "alice").GitHub; got != "gh-alice" {
		t.Fatal("an unauthenticated request cleared the connector")
	}
}

// --- the account's last credential, and the application a name resolves to ---

// clearPassword strips the account's password digest, leaving it as federated
// provisioning does (users.Create writes no digest for a row created without a
// password). The bearer is minted BEFORE this runs — how the person authenticated
// is a separate question from what the account can still be signed in as, which is
// what the unlink check reads.
func clearPassword(t *testing.T, db orm.DB, name string) {
	t.Helper()
	u := userRow(t, db, name)
	u.PasswordHash, u.PasswordType = "", ""
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("clear password: %v", err)
	}
}

// A federated account with nothing else to sign in with keeps its link: unlinking
// it would destroy the account, with no password, no passkey and no wallet left.
func TestUnlink_RefusedWhenItIsTheOnlyCredential(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkGitHub(t, db, "alice", "gh-alice", true)

	access := accessTokenFor(t, app, "openid")
	clearPassword(t, db, "alice")

	_, m := doUnlink(t, app, access, "GitHub", "hanzo", "alice")
	if m["status"] != "error" {
		t.Fatalf("unlinking the only credential must be refused, got %v", m)
	}
	if got := userRow(t, db, "alice").GitHub; got != "gh-alice" {
		t.Fatalf("the account's only credential was removed: %q", got)
	}
}

// A second linked provider IS another way in, so the first one may go.
func TestUnlink_PermittedWhenAnotherLinkRemains(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkGitHub(t, db, "alice", "gh-alice", true)

	access := accessTokenFor(t, app, "openid")
	clearPassword(t, db, "alice")
	u := userRow(t, db, "alice")
	u.Google = "goog-alice"
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("stamp second connector: %v", err)
	}

	if _, m := doUnlink(t, app, access, "GitHub", "hanzo", "alice"); m["status"] != "ok" {
		t.Fatalf("unlink with another link remaining must be permitted, got %v", m["msg"])
	}
	if got := userRow(t, db, "alice").GitHub; got != "" {
		t.Fatalf("the link survived a permitted unlink: %q", got)
	}
}

// A bound wallet is a credential too — the account can still sign in, so the link
// may go. Without this arm the check would refuse an unlink that is perfectly safe.
func TestUnlink_WalletIsACredential(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkGitHub(t, db, "alice", "gh-alice", true)

	access := accessTokenFor(t, app, "openid")
	clearPassword(t, db, "alice")
	w := orm.New[schema.Wallet](db)
	w.Owner, w.User, w.Chain, w.Address = "hanzo", "alice", "evm", "0xabc"
	w.SetId("hanzo/alice/evm/0xabc")
	if err := w.CreateCtx(context.Background()); err != nil {
		t.Fatalf("bind wallet: %v", err)
	}

	if _, m := doUnlink(t, app, access, "GitHub", "hanzo", "alice"); m["status"] != "ok" {
		t.Fatalf("unlink with a bound wallet must be permitted, got %v", m["msg"])
	}
}

// A SuperAdmin is not bound by the last-credential refusal — it is the platform's
// recovery path, the same carve-out the CanUnlink flag already has.
func TestUnlink_SuperAdminMayRemoveTheOnlyCredential(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	seedUserInOrg(t, db, "admin", "z", "z@hanzo.ai", "pw") // member of the reserved org
	linkGitHub(t, db, "alice", "gh-alice", true)
	clearPassword(t, db, "alice")

	code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "admin", "username": "z", "password": "pw",
		"clientId": "conf", "redirectUri": testRedirect, "scope": "openid",
	})
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	super, _ := tok["access_token"].(string)
	if super == "" {
		t.Skip("no SuperAdmin grant available through this application")
	}

	if _, m := doUnlink(t, app, super, "GitHub", "hanzo", "alice"); m["status"] != "ok" {
		t.Fatalf("a SuperAdmin must be able to force the unlink, got %v", m["msg"])
	}
}

// The operator who actually exists. Anchored in a brand org, holding the
// reserved-org membership an existing SuperAdmin granted — the deliberate,
// signed, revocable way operators are made. Asking the HOME org refused exactly
// this identity, so the platform's recovery path was shut to every operator who
// is also an ordinary member of some brand. TestUnlink_CrossUserRefused is the
// other half: without that membership the same request is still refused.
func TestUnlink_BrandAnchoredOperatorMayRemoveTheOnlyCredential(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	seedUser(t, db, "op", "op@hanzo.ai", "pw") // home org hanzo, NOT the reserved org
	if _, err := store.EnsureMembership(tctx(), db, "hanzo/op", policy.AdminOrg, store.RoleAdmin); err != nil {
		t.Fatalf("grant the reserved-org membership: %v", err)
	}
	linkGitHub(t, db, "alice", "gh-alice", true)
	clearPassword(t, db, "alice")

	code, _, _ := loginForCode(t, app, map[string]string{
		"organization": "hanzo", "username": "op", "password": "pw",
		"clientId": "conf", "redirectUri": testRedirect, "scope": "openid",
	})
	_, tok := exchangeCode(t, app, url.Values{
		"code": {code}, "client_id": {"conf"}, "client_secret": {"s3cret"}, "redirect_uri": {testRedirect},
	})
	operator, _ := tok["access_token"].(string)
	if operator == "" {
		t.Fatalf("the operator must be able to sign in: %v", tok)
	}

	if _, m := doUnlink(t, app, operator, "GitHub", "hanzo", "alice"); m["status"] != "ok" {
		t.Fatalf("an operator holding the reserved-org membership must be able to force "+
			"the unlink, got %v", m["msg"])
	}
}

// The signup application is resolved by NAME, so a TENANT-registered one is found
// and its CanUnlink flag is honoured. Pinning the lookup to the "admin" registry
// missed the row and fail-closed every unlink for such an account.
func TestUnlink_TenantOwnedSignupApplicationResolves(t *testing.T) {
	app, db := newUnlinkServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	linkGitHub(t, db, "alice", "gh-alice", true)

	// The same provider item, on an application the TENANT owns.
	tenant := orm.New[schema.Application](db)
	tenant.Owner, tenant.Name, tenant.Organization = "hanzo", "storefront", "hanzo"
	tenant.Providers = []*schema.ProviderItem{{Owner: "admin", Name: "prov-github-unlink", CanSignIn: true, CanUnlink: true}}
	tenant.SetId("hanzo/storefront")
	if err := tenant.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed tenant app: %v", err)
	}
	u := userRow(t, db, "alice")
	u.SignupApplication = "storefront"
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("repoint signup application: %v", err)
	}

	access := accessTokenFor(t, app, "openid")
	if _, m := doUnlink(t, app, access, "GitHub", "hanzo", "alice"); m["status"] != "ok" {
		t.Fatalf("a tenant-owned signup application must resolve, got %v", m["msg"])
	}
	if got := userRow(t, db, "alice").GitHub; got != "" {
		t.Fatalf("the link survived a permitted unlink: %q", got)
	}
}
