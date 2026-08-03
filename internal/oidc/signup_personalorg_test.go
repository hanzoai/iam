// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// newbieBody is the minimal valid signup form used across these cases. It is a
// helper of its own rather than the one inside TestSignup, which is a closure
// private to that function.
func newbieBody() map[string]string {
	return map[string]string{
		"application": "conf", "organization": "hanzo",
		"username": "newbie", "password": "correct horse battery staple",
	}
}

// A self-serve signup under orgChoicePersonal must land in an org OF ITS OWN, never
// in the application's shared org.
//
// This is the property the whole lane exists for. A signup left in the shared org is
// a co-tenant of Hanzo's own org, and every org-scoped read path in cloud filters on
// `org = ?` alone — so "which org is this account in" decides whether a stranger can
// read the platform's projects, repositories, deploy keys and ledger. It also decides
// whether they can ever be funded, because the starter credit is refused for the
// shared signup org by name.
func TestSignup_PersonalOrgIsProvisioned(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true, orgChoice: orgChoicePersonal})
	seedOrg(t, db, "hanzo")

	_, env := signupReq(t, app, newbieBody())
	if env["status"] != "ok" {
		t.Fatalf("signup must succeed, got %v", env)
	}

	ctx := context.Background()
	// The user must NOT be left in the shared signup org.
	if u, _ := store.GetUserByName(ctx, db, "hanzo", "newbie"); u != nil {
		t.Fatal("user was left in the shared signup org 'hanzo' — the exposure this fix exists to close")
	}
	// They must be in their own org, and be its admin.
	u, err := store.GetUserByName(ctx, db, "newbie", "newbie")
	if err != nil || u == nil {
		t.Fatalf("user not found in their own org 'newbie': %v", err)
	}
	if u.Owner != "newbie" {
		t.Errorf("home org = %q, want %q", u.Owner, "newbie")
	}
	if !u.IsAdmin {
		t.Error("the founder must be an admin of their own org")
	}
	// The org itself must exist and be marked personal.
	org, err := store.GetOrganizationByName(ctx, db, "newbie")
	if err != nil || org == nil {
		t.Fatalf("personal org was not created: %v", err)
	}
	if !org.IsPersonal {
		t.Error("a derived signup org must be marked personal")
	}
	// A provisioned tenant is never unmetered: it owns one org-scoped credential.
	if sa, _ := store.GetUserByName(ctx, db, "newbie", "newbie-default"); sa == nil {
		t.Error("the org's default metered credential was not provisioned")
	}
}

// The default (non-personal) app policy is unchanged: without the opt-in a signup
// still lands in the application's own org. The new behaviour must be something an
// application asks for, not something every app silently acquires.
func TestSignup_WithoutPersonalModeStaysInAppOrg(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true}) // no orgChoice
	seedOrg(t, db, "hanzo")

	if _, env := signupReq(t, app, newbieBody()); env["status"] != "ok" {
		t.Fatalf("signup must succeed, got %v", env)
	}
	if u, _ := store.GetUserByName(context.Background(), db, "hanzo", "newbie"); u == nil {
		t.Error("without the opt-in the user belongs in the app's own org")
	}
}

// Two people whose usernames derive the same org name must each get their own tenant.
// The second is numbered rather than refused — a contended name may never cost
// someone their signup, and it must never silently place them in the first person's
// org.
func TestSignup_PersonalOrgNameCollisionIsNumbered(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true, orgChoice: orgChoicePersonal})
	seedOrg(t, db, "hanzo")

	first := newbieBody()
	first["username"] = "dave"
	first["email"] = "dave@one.example"
	if _, env := signupReq(t, app, first); env["status"] != "ok" {
		t.Fatalf("first signup failed: %v", env)
	}
	// A DIFFERENT person whose username slugifies to the same base.
	second := newbieBody()
	second["username"] = "dave."
	second["email"] = "dave@two.example"
	_, env := signupReq(t, app, second)
	if env["status"] != "ok" {
		t.Fatalf("second signup must succeed with a numbered org, got %v", env)
	}

	ctx := context.Background()
	o1, _ := store.GetOrganizationByName(ctx, db, "dave")
	o2, _ := store.GetOrganizationByName(ctx, db, "dave2")
	if o1 == nil || o2 == nil {
		t.Fatalf("both orgs must exist: dave=%v dave2=%v", o1 != nil, o2 != nil)
	}
	if o1.Founder == o2.Founder {
		t.Error("two distinct people must found two distinct orgs")
	}
}

// A username that cannot be an org name on its own — reserved, or too short — must
// still yield a signup. These are legal usernames; refusing them would turn an IAM
// naming rule into a closed front door.
func TestSignup_PersonalOrgAvoidsReservedAndTooShort(t *testing.T) {
	for _, tc := range []struct{ username, wantOrg string }{
		{"admin", "admin2"}, // reserved: must never provision INTO the SuperAdmin org
		{"a", "a2"},         // shorter than minOrgSlug
	} {
		t.Run(tc.username, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", signup: true, orgChoice: orgChoicePersonal})
			seedOrg(t, db, "hanzo")

			body := newbieBody()
			body["username"] = tc.username
			body["email"] = tc.username + "@example.com"
			if _, env := signupReq(t, app, body); env["status"] != "ok" {
				t.Fatalf("signup must succeed, got %v", env)
			}
			ctx := context.Background()
			u, _ := store.GetUserByName(ctx, db, tc.wantOrg, tc.username)
			if u == nil {
				t.Fatalf("user not provisioned into %q", tc.wantOrg)
			}
			// The critical half: never the reserved admin org.
			if u.Owner == "admin" {
				t.Fatal("a self-service signup was provisioned into the reserved admin org")
			}
		})
	}
}
