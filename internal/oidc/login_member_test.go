// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/store"
)

// A shared app of an agency's client org serves the people that org admits by
// membership. The sign-in form names the app's org, the only org it can know, so
// those people are found through the org's roster, and nobody else is.

// memberApp seeds a shared app owned by org "client" and the people around it.
func memberApp(t *testing.T) (orm.DB, func(org, user, pw string) map[string]any) {
	t.Helper()
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: "client-patrol", secret: "s3cret", redirectURIs: []string{testRedirect}, shared: true})
	a.Organization = "client"
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	seedUserInOrg(t, db, "agency", "josh", "josh@agency.example", "pw-josh")
	seedUserInOrg(t, db, "elsewhere", "stray", "stray@elsewhere.example", "pw-stray")
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.example", "pw-root")
	for _, m := range [][2]string{{"agency/josh", "client"}, {"admin/root", "client"}} {
		if _, err := store.EnsureMembership(tctx(), db, m[0], m[1], store.RoleAdmin); err != nil {
			t.Fatal(err)
		}
	}
	login := func(org, user, pw string) map[string]any {
		_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
			"organization": org, "username": user, "password": pw, "clientId": "client-patrol",
			"redirectUri": testRedirect, "scope": "openid", "type": "code",
		}))
		return decode(t, body)
	}
	return db, login
}

func minted(m map[string]any) bool {
	code, _ := m["data"].(string)
	return m["status"] == "ok" && code != ""
}

func TestLogin_AMemberSignsInToTheSharedAppOfTheOrgTheyJoined(t *testing.T) {
	_, login := memberApp(t)
	for _, id := range []string{"josh", "josh@agency.example", "JOSH@Agency.Example"} {
		if m := login("client", id, "pw-josh"); !minted(m) {
			t.Fatalf("member signing in as %q: %v", id, m)
		}
	}
	for _, pw := range []string{"wrong", "pw-stray"} {
		if m := login("client", "josh", pw); minted(m) || m["msg"] != "the username or password is incorrect" {
			t.Fatalf("member josh with password %q: %v", pw, m)
		}
	}
}

func TestLogin_ANonMemberStaysIncorrect(t *testing.T) {
	_, login := memberApp(t)
	for _, id := range []string{"stray", "stray@elsewhere.example", "nobody"} {
		m := login("client", id, "pw-stray")
		if minted(m) || m["msg"] != "the username or password is incorrect" {
			t.Fatalf("non-member %q: %v", id, m)
		}
	}
	// A member homed in the reserved org is never reached through a tenant's form.
	if m := login("client", "root", "pw-root"); minted(m) {
		t.Fatalf("a reserved-org member signed in through a tenant app: %v", m)
	}
}

func TestLogin_AmbiguousMembersAreRefused(t *testing.T) {
	db, login := memberApp(t)
	seedUserInOrg(t, db, "other", "josh", "josh@agency.example", "pw-josh")
	if _, err := store.EnsureMembership(tctx(), db, "other/josh", "client", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"josh", "josh@agency.example"} {
		if m := login("client", id, "pw-josh"); minted(m) || m["msg"] != "the username or password is incorrect" {
			t.Fatalf("an identifier naming two members signed in as %q: %v", id, m)
		}
	}
}

// The roster reach is a shared app's, for the org the app serves, through an
// org-wide membership of someone who is still there. Each condition is one of
// these cases.
func TestLogin_MemberReachHasEveryCondition(t *testing.T) {
	db, login := memberApp(t)

	// A workspace grant admits the workspace, not the org.
	seedUserInOrg(t, db, "agency", "wren", "wren@agency.example", "pw-wren")
	if _, err := store.EnsureMembershipIn(tctx(), db, "agency/wren", "client", "w1", "", store.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if m := login("client", "wren", "pw-wren"); minted(m) {
		t.Fatalf("a workspace-only member signed in to the org's app: %v", m)
	}

	// A deleted account is nobody.
	seedUserInOrg(t, db, "agency", "gone", "gone@agency.example", "pw-gone")
	if _, err := store.EnsureMembership(tctx(), db, "agency/gone", "client", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	u, err := store.GetUserByName(tctx(), db, "agency", "gone")
	if err != nil || u == nil {
		t.Fatal(err)
	}
	u.IsDeleted = true
	if err := u.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.MemberByIdentifier(tctx(), db, "client", "gone"); got != nil {
		t.Fatalf("a deleted member was resolved: %s/%s", got.Owner, got.Name)
	}

	// A form naming another org than the app serves searches no roster, even one
	// that holds the person.
	if _, err := store.EnsureMembership(tctx(), db, "agency/josh", "other", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if m := login("other", "josh", "pw-josh"); minted(m) || m["msg"] != "the username or password is incorrect" {
		t.Fatalf("a form naming an org the app does not serve reached its roster: %v", m)
	}
}

// An app that is not shared never searches its org's roster: its member signs in
// at home, not here.
func TestLogin_AnUnsharedAppSearchesNoRoster(t *testing.T) {
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: "client-own", secret: "s3cret", redirectURIs: []string{testRedirect}})
	a.Organization = "client"
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	seedUserInOrg(t, db, "agency", "josh", "josh@agency.example", "pw-josh")
	if _, err := store.EnsureMembership(tctx(), db, "agency/josh", "client", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "client", "username": "josh", "password": "pw-josh", "clientId": "client-own",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	if m := decode(t, body); minted(m) || m["msg"] != "the username or password is incorrect" {
		t.Fatalf("an unshared app resolved a member through its roster: %v", m)
	}
}
