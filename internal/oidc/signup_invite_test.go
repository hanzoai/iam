// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A signup lands in one of three places: an org it founds, the application's own
// org where the application serves no other, or an org whose admin invited it.
// Each is pinned here, and so is every way an invitation fails to be one.

const (
	invitePassword = "correct horse battery staple"
	refused        = "the user is not permitted to sign up to this application"
)

// seedInvite writes an invitation the way /v1/iam/invitations does for the org's
// admin: owned by the org it admits to.
func seedInvite(t *testing.T, db orm.DB, inv schema.Invitation) {
	t.Helper()
	row := orm.New[schema.Invitation](db)
	row.Owner, row.Name = inv.Owner, inv.Name
	row.Code, row.IsRegexp = inv.Code, inv.IsRegexp
	row.Quota, row.UsedCount = inv.Quota, inv.UsedCount
	row.Application = inv.Application
	row.Username, row.Email, row.Phone = inv.Username, inv.Email, inv.Phone
	row.State = inv.State
	row.SetId(inv.Owner + "/" + inv.Name)
	if err := row.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed invitation %s/%s: %v", inv.Owner, inv.Name, err)
	}
}

func inviteOf(t *testing.T, db orm.DB, owner, name string) *schema.Invitation {
	t.Helper()
	inv, err := orm.Get[schema.Invitation](db, owner+"/"+name)
	if err != nil {
		t.Fatalf("read invitation %s/%s: %v", owner, name, err)
	}
	return inv
}

// Path 1: the application's own org, where it serves no other and founds nothing.
func TestSignup_unsharedApp_registersInItsOwnOrg(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "acme-app", secret: "s3cret", org: "acme", signup: true})
	seedOrg(t, db, "acme")

	status, env := signupReq(t, app, map[string]string{
		"application": "acme-app", "organization": "acme",
		"username": "alice", "password": invitePassword,
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("signup into the app's own org: status=%d env=%v, want 200 ok", status, env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "acme", "alice"); u == nil {
		t.Fatal("alice was not made in acme")
	}
}

// Path 2: an org the account founds — at a shared application too. Shared or not, a
// founding application moves each account out of its own org into one of its own.
func TestSignup_sharedFoundingApp_foundsItsOwnOrg(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", orgChoice: "create", shared: true, signup: true})
	seedOrg(t, db, "hanzo")

	status, env := signupReq(t, app, map[string]string{
		"application": "portal", "organization": "hanzo",
		"username": "pioneer", "password": invitePassword,
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("founding signup: status=%d env=%v, want 200 ok", status, env)
	}
	data, _ := env["data"].(map[string]any)
	if org, _ := data["owner"].(string); org == "" || org == "hanzo" {
		t.Fatalf("pioneer landed in %q, want an org of its own", org)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "pioneer"); u != nil {
		t.Fatal("pioneer is still an account of the shared application's org")
	}
}

// A shared application that founds nothing has no org to hand a stranger: its own
// is the operator's, and naming it is refused like naming any other.
func TestSignup_sharedApp_refusesItsOwnOrgUninvited(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", shared: true, signup: true})
	seedOrg(t, db, "hanzo")

	_, env := signupReq(t, app, map[string]string{
		"application": "portal", "organization": "hanzo",
		"username": "stranger", "password": invitePassword,
	})
	if msg, _ := env["msg"].(string); msg != refused {
		t.Fatalf("msg = %q, want %q", msg, refused)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "stranger"); u != nil {
		t.Fatal("a stranger was filed in the operator's org")
	}
}

// Path 3: an org whose admin invited it. The account is made in that org, stays
// there even at a founding application, records the invitation it came by, and
// spends one seat.
func TestSignup_invitation_joinsTheInvitingOrg(t *testing.T) {
	for _, tc := range []struct {
		name string
		app  fullApp
	}{
		{"shared", fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", shared: true, signup: true}},
		{"founding", fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", orgChoice: "create", signup: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			seedAppFull(t, db, tc.app)
			seedOrg(t, db, "hanzo")
			seedOrg(t, db, "acme")
			seedInvite(t, db, schema.Invitation{Owner: "acme", Name: "team", Code: "acme-7f3k", Quota: 2, State: "Active"})

			status, env := signupReq(t, app, map[string]string{
				"application": "portal", "organization": "acme", "invitationCode": "acme-7f3k",
				"username": "bob", "password": invitePassword,
			})
			if status != 200 || env["status"] != "ok" {
				t.Fatalf("invited signup: status=%d env=%v, want 200 ok", status, env)
			}
			data, _ := env["data"].(map[string]any)
			if org, _ := data["owner"].(string); org != "acme" {
				t.Fatalf("bob landed in %q, want acme", org)
			}
			u, _ := store.GetUserByName(context.Background(), db, "acme", "bob")
			if u == nil {
				t.Fatal("bob was not made in acme")
			}
			if u.Invitation != "team" {
				t.Errorf("invitation recorded = %q, want team", u.Invitation)
			}
			if u.IsAdmin {
				t.Error("an invited account is an admin of the org it joined")
			}
			if got := inviteOf(t, db, "acme", "team").UsedCount; got != 1 {
				t.Errorf("usedCount = %d, want 1", got)
			}
		})
	}
}

// A username pinned on the invitation is the name a signup that states none gets.
func TestSignup_invitation_givesThePinnedName(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", shared: true, signup: true})
	seedOrg(t, db, "acme")
	seedInvite(t, db, schema.Invitation{Owner: "acme", Name: "carol", Code: "c-1", Quota: 1, Username: "carol", Email: "carol@acme.example", State: "Active"})

	status, env := signupReq(t, app, map[string]string{
		"application": "portal", "organization": "acme", "invitationCode": "c-1",
		"email": "Carol@acme.example", "password": invitePassword,
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("pinned signup: status=%d env=%v, want 200 ok", status, env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "acme", "carol"); u == nil {
		t.Fatal("carol was not made in acme under the pinned name")
	}
}

// Every way an invitation fails to be one is refused with the tenant sentence, and
// leaves no account and no seat spent.
func TestSignup_invitation_refusals(t *testing.T) {
	good := schema.Invitation{Owner: "acme", Name: "team", Code: "acme-7f3k", Quota: 5, State: "Active"}
	for _, tc := range []struct {
		name   string
		invite schema.Invitation
		form   map[string]string
	}{
		{"no code", good, map[string]string{}},
		{"wrong code", good, map[string]string{"invitationCode": "acme-0000"}},
		{"suspended", with(good, func(i *schema.Invitation) { i.State = "Suspended" }), nil},
		{"never activated", with(good, func(i *schema.Invitation) { i.State = "" }), nil},
		{"no seats left", with(good, func(i *schema.Invitation) { i.UsedCount = 5 }), nil},
		{"another org's code", with(good, func(i *schema.Invitation) { i.Owner = "globex" }), nil},
		{"another application", with(good, func(i *schema.Invitation) { i.Application = "acme-app" }), nil},
		{"another address", with(good, func(i *schema.Invitation) { i.Email = "dave@acme.example" }), nil},
		{"another name", with(good, func(i *schema.Invitation) { i.Username = "dave" }), nil},
		{"a pattern the code does not wholly match", with(good, func(i *schema.Invitation) { i.Code, i.IsRegexp = "acme-[0-9]+", true }), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, db := newServer(t)
			seedAppFull(t, db, fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", shared: true, signup: true})
			seedOrg(t, db, "acme")
			seedOrg(t, db, "globex")
			seedInvite(t, db, tc.invite)

			body := map[string]string{
				"application": "portal", "organization": "acme", "invitationCode": "acme-7f3k",
				"username": "eve", "email": "eve@evil.example", "password": invitePassword,
			}
			for k, v := range tc.form {
				body[k] = v
			}
			if tc.form != nil && tc.form["invitationCode"] == "" {
				delete(body, "invitationCode")
			}
			_, env := signupReq(t, app, body)
			if msg, _ := env["msg"].(string); msg != refused {
				t.Fatalf("msg = %q, want %q (env=%v)", msg, refused, env)
			}
			if u, _ := store.GetUserByName(context.Background(), db, "acme", "eve"); u != nil {
				t.Fatal("eve was made in acme")
			}
			if got := inviteOf(t, db, tc.invite.Owner, tc.invite.Name).UsedCount; got != tc.invite.UsedCount {
				t.Fatalf("usedCount = %d, want %d unspent", got, tc.invite.UsedCount)
			}
		})
	}
}

// A pattern the admin wrote admits a code it wholly matches.
func TestSignup_invitation_pattern(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", shared: true, signup: true})
	seedOrg(t, db, "acme")
	seedInvite(t, db, schema.Invitation{Owner: "acme", Name: "batch", Code: "acme-[0-9]{4}", IsRegexp: true, Quota: 10, State: "Active"})

	status, env := signupReq(t, app, map[string]string{
		"application": "portal", "organization": "acme", "invitationCode": "acme-0042",
		"username": "frank", "password": invitePassword,
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("pattern signup: status=%d env=%v, want 200 ok", status, env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "acme", "frank"); u == nil {
		t.Fatal("frank was not made in acme")
	}
}

// The quota is the admin's bound: a one-seat invitation admits one account.
func TestSignup_invitation_quotaHolds(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", shared: true, signup: true})
	seedOrg(t, db, "acme")
	seedInvite(t, db, schema.Invitation{Owner: "acme", Name: "one", Code: "solo", Quota: 1, State: "Active"})

	for i, name := range []string{"first", "second"} {
		status, env := signupReq(t, app, map[string]string{
			"application": "portal", "organization": "acme", "invitationCode": "solo",
			"username": name, "password": invitePassword,
		})
		ok := status == 200 && env["status"] == "ok"
		if ok != (i == 0) {
			t.Fatalf("%s: status=%d env=%v", name, status, env)
		}
	}
	if u, _ := store.GetUserByName(context.Background(), db, "acme", "second"); u != nil {
		t.Fatal("a second account came in on a one-seat invitation")
	}
}

// A code brought to a founding application that redeems nothing is refused, not
// read as no code: the person asked to join an org, and founding one instead puts
// them where they did not ask to be.
func TestSignup_invitation_badCodeDoesNotFound(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "lux-cloud", org: "lux", orgChoice: "create", signup: true})
	seedOrg(t, db, "lux")

	_, env := signupReq(t, app, map[string]string{
		"clientId": "lux-cloud", "organization": "lux", "invitationCode": "nope",
		"username": "grace", "password": invitePassword,
	})
	if msg, _ := env["msg"].(string); msg != refused {
		t.Fatalf("msg = %q, want %q", msg, refused)
	}
	if org, _ := store.GetOrganizationByName(context.Background(), db, "grace"); org != nil {
		t.Fatal("an org was founded for a signup that brought a code nobody wrote")
	}
}

func with(inv schema.Invitation, edit func(*schema.Invitation)) schema.Invitation {
	edit(&inv)
	return inv
}
