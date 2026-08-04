// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// Unlink self-authenticates (session cookie / bearer) on the public OIDC surface,
// so the harness only needs the one registered group — the same one the confidential
// flow mints the bearer from.
func newUnlinkServer(t *testing.T) (*zip.App, orm.DB) {
	t.Helper()
	db := openTestDB(t)
	app := zip.New(zip.Config{AppName: "iam-unlink-test", DisableStartupMessage: true})
	Route(app.Group(""), db) // public: authorize/login/token AND the self-authenticating unlink
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
