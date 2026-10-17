// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// seedHeldActKey seeds an act-granted server key in owner held by holder (a bare
// name in owner), the shape an org admin files for an agent to act through.
func seedHeldActKey(t *testing.T, db orm.DB, owner, name, holder, secret string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.User = owner, name, holder
	k.Application = "hanzo-app"
	k.AccessSecretDigest = schema.DigestSecret(secret)
	k.State = "Active"
	k.Act = true
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed held act key %s/%s: %v", owner, name, err)
	}
}

// An act key acts only while its holder could present it: live, and running the
// org. Suspending the admin who filed it ends it at the next mint, and a plain
// member's act key never mints.
func TestAs_anActKeyDiesWithItsHolder(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActAdmin(t, db, "acme", "boss", "ext-boss")
	seedActUser(t, db, "acme", "alice", "ext-alice")
	seedActUser(t, db, "acme", "carl", "ext-carl")
	seedHeldActKey(t, db, "acme", "boss-act", "boss", "sk-live-bossact")
	seedHeldActKey(t, db, "acme", "carl-act", "carl", "sk-live-carlact")

	if resp, body := do(t, app, asReq("sk-live-bossact", "?id=acme/alice")); resp.StatusCode != 200 {
		t.Fatalf("the admin's act key: %d %s", resp.StatusCode, body)
	}
	if resp, body := do(t, app, asReq("sk-live-carlact", "?id=acme/alice")); resp.StatusCode != 403 {
		t.Fatalf("a plain member's act key minted: %d %s", resp.StatusCode, body)
	}

	boss, err := orm.Get[schema.User](db, "acme/boss")
	if err != nil {
		t.Fatal(err)
	}
	boss.IsForbidden = true
	if err := boss.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resp, body := do(t, app, asReq("sk-live-bossact", "?id=acme/alice")); resp.StatusCode != 403 {
		t.Fatalf("a suspended admin's act key minted: %d %s", resp.StatusCode, body)
	}
}

// An act key that names no holder has no one whose standing could end it, so it
// mints nothing.
func TestAs_anActKeyNamesItsHolder(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "acme", "alice", "ext-alice")
	k := orm.New[schema.Key](db)
	k.Owner, k.Name = "acme", "orphan-act"
	k.Application = "hanzo-app"
	k.AccessSecretDigest = schema.DigestSecret("sk-live-orphan")
	k.State, k.Act = "Active", true
	k.SetId("acme/orphan-act")
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	if resp, body := do(t, app, asReq("sk-live-orphan", "?id=acme/alice")); resp.StatusCode != 403 {
		t.Fatalf("a holderless act key minted: %d %s", resp.StatusCode, body)
	}
}

// A machine signs in as an application or presents its key, so a password grant
// and a form sign-in for one are refused, with the words a wrong password draws.
func TestLogin_aMachineHoldsNoSession(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	twoApps(t, db)
	seedUser(t, db, "robot", "robot@hanzo.ai", "pw")
	u, err := orm.Get[schema.User](db, "hanzo/robot")
	if err != nil {
		t.Fatal(err)
	}
	u.Type = schema.ServiceAccount
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-console"}, "client_secret": {"top-secret"},
		"username": {"robot@hanzo.ai"}, "password": {"pw"}, "scope": {"openid"},
	})
	if resp.StatusCode != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("a machine's password grant: %d %v", resp.StatusCode, tok)
	}
	form := url.Values{"organization": {"hanzo"}, "application": {"portal"}, "username": {"robot"}, "password": {"pw"}, "type": {"login"}}
	resp2, body := do(t, app, formReq("POST", PathLogin, form))
	if decode(t, body)["status"] == "ok" {
		t.Fatalf("a machine signed in at the form: %d %s", resp2.StatusCode, body)
	}
}
