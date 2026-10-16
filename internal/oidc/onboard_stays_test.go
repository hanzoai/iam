// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"fmt"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Founding an org never moves the founder. These hold what the move broke: the
// sign-in screen and the sign-in itself still find the founder by address, an org
// founded at two doors has one owner, and a platform operator founds nothing.

// The address a founder signed up with is still an account with a password at the
// application's sign-in screen, and it signs them in.
func TestOnboard_TheFounderIsStillFoundByAddress(t *testing.T) {
	fresh(t)
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true})
	seedFounder(t, db, "hanzo", "alice")

	if resp, env := onboardAs(t, app, portalSession(t, app, "hanzo", "alice"), "Acme"); resp.StatusCode != 200 {
		t.Fatalf("onboarding: %d %+v", resp.StatusCode, env)
	}
	st, m := identify(t, app, "203.0.113.7", map[string]string{"clientId": "conf", "identifier": "alice@example.com"})
	data, _ := m["data"].(map[string]any)
	if st != 200 || data["account"] != true || data["password"] != true {
		t.Fatalf("the sign-in screen after founding an org: %d %v, want an account with a password", st, m)
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "application": "conf", "clientId": "conf",
		"username": "alice@example.com", "password": "pw",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	if m := decode(t, body); m["status"] != "ok" {
		t.Fatalf("signing in by address after founding an org: %v", m)
	}
}

// An org founded at one door and asked for again at the other — cloud's
// POST /v1/account/orgs records the founder as owner by membership, then the
// person asks hanzo.id for the same name — resumes into the same org with the same
// single owner. Moving them here left the roster holding both spellings of one
// person and the org's key held by an account that no longer existed.
func TestOnboard_AnOrgFoundedAtTwoDoorsHasOneOwner(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "mixed")
	mixed := mustUser(t, db, "hanzo", "mixed")
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name, o.DisplayName, o.Founder = "admin", "mixco", "Mixco", mixed.Model.Id()
	o.SetId("admin/mixco")
	if err := o.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureMembership(ctx, db, "hanzo/mixed", "mixco", store.RoleOwner); err != nil {
		t.Fatal(err)
	}

	if resp, env := onboardAs(t, app, portalSession(t, app, "hanzo", "mixed"), "Mixco"); resp.StatusCode != 200 {
		t.Fatalf("the second door: %d %+v", resp.StatusCode, env)
	}
	roster, err := store.MembershipsByOrg(ctx, db, "mixco")
	if err != nil || len(roster) != 1 || roster[0].User != "hanzo/mixed" || roster[0].Role != store.RoleOwner {
		t.Fatalf("mixco roster = %+v (%v), want hanzo/mixed alone, as owner", roster, err)
	}
	if u, _ := store.GetUserByName(ctx, db, "hanzo", "mixed"); u == nil {
		t.Fatal("the founder was moved by the second door")
	}
	if k, _ := orm.Get[schema.Key](db, "mixco/default"); k == nil || k.User != "hanzo/mixed" {
		t.Fatalf("mixco/default = %+v, want it held by hanzo/mixed", k)
	}
}

// A platform operator holds no role in a customer org, so onboarding founds
// nothing for an account of the reserved admin org, and leaves it SuperAdmin.
func TestOnboard_ASuperAdminFoundsNothing(t *testing.T) {
	ctx := context.Background()
	_, db := newServer(t)
	seedUserIn(t, db, "admin", "root", "root@hanzo.ai")
	_, err := provision(ctx, db, claim{owner: "admin", name: "root", slug: "acme", display: "Acme"})
	if ft, ok := err.(*fault); !ok || ft.status != 403 {
		t.Fatalf("a SuperAdmin founding an org: %v, want a 403", err)
	}
	if org, _ := store.GetOrganizationByName(ctx, db, "acme"); org != nil {
		t.Fatalf("an org was founded for a SuperAdmin: %+v", org)
	}
	if u, _ := store.GetUserByName(ctx, db, "admin", "root"); u == nil {
		t.Fatal("the SuperAdmin left the admin org")
	}
}

// A founder who handed their org over and was removed does not take it back: the
// Founder stamp is permanent, so resuming on it alone would make them an owner
// again, with a fresh unlimited key on the org's pool. Owners are added by
// invitation.
func TestOnboard_ARemovedFounderDoesNotTakeTheOrgBack(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "alice", "alice")
	alice := mustUser(t, db, "alice", "alice")
	alice.IsAdmin = true
	if err := alice.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name, o.DisplayName, o.Founder = "admin", "acme", "Acme", alice.Model.Id()
	o.SetId("admin/acme")
	if err := o.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := store.EnsureMembership(ctx, db, "bob/bob", "acme", store.RoleOwner); err != nil {
		t.Fatal(err)
	}

	resp, env := onboardAs(t, app, portalSession(t, app, "alice", "alice"), "Acme")
	if resp.StatusCode != 409 || env["accessSecret"] != nil {
		t.Fatalf("a removed founder asking for the org again: %d %+v, want 409 and no key", resp.StatusCode, env)
	}
	roster, _ := store.MembershipsByOrg(ctx, db, "acme")
	if len(roster) != 1 || roster[0].User != "bob/bob" {
		t.Fatalf("acme roster = %+v, want bob/bob alone", roster)
	}
	if k, _ := orm.Get[schema.Key](db, "acme/default"); k != nil {
		t.Fatalf("a key was minted for the removed founder: %+v", k)
	}
}

// Onboarding founds at most store.MaxFoundedOrgs organizations per account, as the
// membership surface does: each holds its name for good.
func TestOnboard_FoundingIsCapped(t *testing.T) {
	ctx := context.Background()
	_, db := newServer(t)
	seedUserIn(t, db, "hanzo", "alice", "alice@example.com")
	for i := 1; i <= store.MaxFoundedOrgs; i++ {
		if _, err := provision(ctx, db, claim{owner: "hanzo", name: "alice", slug: fmt.Sprintf("org%d", i), display: "Org"}); err != nil {
			t.Fatalf("founding org %d of %d: %v", i, store.MaxFoundedOrgs, err)
		}
	}
	_, err := provision(ctx, db, claim{owner: "hanzo", name: "alice", slug: "one-more", display: "One More"})
	if ft, ok := err.(*fault); !ok || ft.status != 409 {
		t.Fatalf("founding past the cap: %v, want a 409", err)
	}
	if org, _ := store.GetOrganizationByName(ctx, db, "one-more"); org != nil {
		t.Fatalf("an org was founded past the cap: %+v", org)
	}
}
