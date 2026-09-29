// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// HIP-0527 §8 R5, the provisioning guard, for the creation paths this package
// serves: after each one runs, the account it made is measured for a record under
// admin, an admin flag, and orgs other than [home] (plus a redeemed invitation's
// org). A path that takes an org from its request is also asked to create in
// admin, and admitting that is the violation admits-admin (R7 row 7).

func guard(t *testing.T, db orm.DB, row, owner, name string, want invariants.Expect, extra ...string) {
	t.Helper()
	found, err := invariants.Created(context.Background(), db, owner, name, want)
	if err != nil {
		t.Fatal(err)
	}
	invariants.Report(t, row, append(found, extra...))
}

// admittedAdmin is the admits-admin violation when a request naming the admin org made
// an account.
func admittedAdmin(ok bool) []string {
	if ok {
		return []string{"admits-admin"}
	}
	return nil
}

func TestAdminNamespace_signup(t *testing.T) {
	for _, c := range []struct {
		row, choice, owner, name string
	}{
		{"I19 signup", "", "hanzo", "newbie"},
		{"I19 signup-founding", "create", "newbie", "newbie"},
	} {
		t.Run(c.row, func(t *testing.T) {
			app, db := newServer(t)
			seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: c.choice})
			seedOrg(t, db, "hanzo")
			seedOrg(t, db, "admin")
			status, env := signupReq(t, app, map[string]string{
				"application": "conf", "organization": "hanzo", "username": "newbie",
				"password": "correct horse battery staple", "email": "newbie@example.com",
			})
			if status != 200 || env["status"] != "ok" {
				t.Fatalf("signup: %d %v", status, env)
			}
			status, env = signupReq(t, app, map[string]string{
				"application": "conf", "organization": "admin", "username": "intruder",
				"password": "correct horse battery staple", "email": "intruder@example.com",
			})
			guard(t, db, c.row, c.owner, c.name, invariants.Expect{}, admittedAdmin(status == 200 && env["status"] == "ok")...)
		})
	}
}

func TestAdminNamespace_signupWithInvitation(t *testing.T) {
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "portal", secret: "s3cret", org: "hanzo", shared: true, signup: true})
	seedOrg(t, db, "hanzo")
	seedOrg(t, db, "acme")
	seedInvite(t, db, schema.Invitation{Owner: "acme", Name: "team", Code: "acme-7f3k", Quota: 2, State: "Active"})
	status, env := signupReq(t, app, map[string]string{
		"application": "portal", "organization": "acme", "invitationCode": "acme-7f3k",
		"username": "bob", "password": invitePassword,
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("invited signup: %d %v", status, env)
	}
	guard(t, db, "I19 signup-invitation", "acme", "bob", invariants.Expect{Org: "acme"})
}

func TestAdminNamespace_federation(t *testing.T) {
	for _, c := range []struct {
		row, choice, owner string
	}{
		{"I19 oauth", "", "hanzo"},
		{"I19 oauth-founding", "create", "social"},
	} {
		t.Run(c.row, func(t *testing.T) {
			ctx := context.Background()
			db, app, prov, binding := federatedApp(t)
			app.OrgChoiceMode = c.choice
			u, err := provisionFederatedUser(ctx, db, app, prov, binding,
				federatedIdentity{subject: "idp-1", email: "social@example.com", emailVerified: true})
			if err != nil {
				t.Fatalf("provision: %v", err)
			}
			if u.Owner != c.owner {
				t.Fatalf("owner = %q, want %q", u.Owner, c.owner)
			}
			guard(t, db, c.row, u.Owner, u.Name, invariants.Expect{})
		})
	}
}

// An org's own identity provider: the application and its provider belong to
// acme, so the person it admits is expected to hold their org of one and acme.
func TestAdminNamespace_orgIdentityProvider(t *testing.T) {
	ctx := context.Background()
	db, app, prov, binding := federatedApp(t)
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", "acme"
	o.SetId("admin/acme")
	if err := o.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	app.Organization, app.OrgChoiceMode = "acme", ""
	prov.Owner = "acme"
	u, err := provisionFederatedUser(ctx, db, app, prov, binding,
		federatedIdentity{subject: "okta-1", email: "worker@acme.test", emailVerified: true})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	guard(t, db, "I19 org-idp", u.Owner, u.Name, invariants.Expect{Org: "acme"})
}

// Onboarding makes one account, the org's metered credential: a program that is
// expected to act in exactly the org it was made for.
func TestAdminNamespace_onboardingCredential(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")
	resp, env := onboardAs(t, app, portalSession(t, app, "hanzo", "alice"), "First-Start")
	if resp.StatusCode != 200 {
		t.Fatalf("onboard: %d %v", resp.StatusCode, env)
	}
	guard(t, db, "I19 onboarding", "first-start", "first-start-default", invariants.Expect{Program: true, Org: "first-start"})
}

// A password reset creates nothing and changes neither where the account lives,
// its admin flag, nor the orgs it holds.
func TestAdminNamespace_passwordReset(t *testing.T) {
	app, db := recoveryServer(t)
	ctx := context.Background()
	before, _ := store.GetUserByName(ctx, db, "hanzo", "alice")
	beforeOrgs := store.MemberOrgRefs(ctx, db, before)
	users := countRows[schema.User](t, db)
	code := deliveredCode(t, app, db, "alice@hanzo.ai", "email")
	if status, env := putPassword(t, app, "", `{"organization":"hanzo","username":"alice@hanzo.ai",`+
		`"code":"`+code+`","password":"new correct horse"}`); status != 200 || env["status"] != "ok" {
		t.Fatalf("reset: %d %v", status, env)
	}
	after, _ := store.GetUserByName(ctx, db, "hanzo", "alice")
	var found []string
	if after == nil || after.Owner != before.Owner || after.Id != before.Id {
		found = append(found, "moved")
	}
	if after != nil && after.IsAdmin != before.IsAdmin {
		found = append(found, "admin-flag")
	}
	if after != nil && !sameRefs(beforeOrgs, store.MemberOrgRefs(ctx, db, after)) {
		found = append(found, "orgs-changed")
	}
	if countRows[schema.User](t, db) != users {
		found = append(found, "created")
	}
	invariants.Report(t, "I19 password-reset", found)
}

func countRows[T any](t *testing.T, db orm.DB) int {
	t.Helper()
	rows, err := orm.TypedQuery[T](db).GetAll(context.Background())
	if err != nil && err != orm.ErrNotFound {
		t.Fatal(err)
	}
	return len(rows)
}

func sameRefs(a, b []schema.OrgRef) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
