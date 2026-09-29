// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"errors"
	"net/http"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func as(p *principal.Principal) context.Context { return principal.Bind(context.Background(), p) }

func forbidden(err error) bool {
	var he *zip.HTTPError
	return errors.As(err, &he) && he.Status == http.StatusForbidden
}

// An account in the admin org is written only by a SuperAdmin. An org admin, an
// org admin holding an admin-org membership, and an application are all refused
// it — including a name nobody holds yet — while every other account is left to
// the ordinary gates.
func TestAuthorizeKeepsTheAdminOrgToSuperAdmins(t *testing.T) {
	db := consentTestDB(t)
	boss := as(&principal.Principal{Org: "hanzo", User: "boss", Admin: true})
	member := as(&principal.Principal{Org: "hanzo", User: "z", Admin: true, Orgs: map[string]policy.Role{policy.AdminOrg: policy.Admin}})
	app := as(&principal.Principal{Org: "hanzo", App: &policy.App{Name: "hanzo-visor", Owner: policy.AdminOrg}})
	super := as(&principal.Principal{Org: policy.AdminOrg, User: "z", Sudo: true})

	for name, ctx := range map[string]context.Context{"org admin": boss, "admin-org member": member, "application": app} {
		if err := Authorize(ctx, db, policy.AdminOrg, "z"); !forbidden(err) {
			t.Errorf("%s writing an admin-org account: %v, want 403", name, err)
		}
		if err := Authorize(ctx, db, "hanzo", "ann"); err != nil {
			t.Errorf("%s writing a hanzo account: %v, want the ordinary gates to decide", name, err)
		}
	}
	if err := Authorize(super, db, policy.AdminOrg, "z"); err != nil {
		t.Errorf("a SuperAdmin writing an admin-org account: %v", err)
	}
	if err := Authorize(context.Background(), db, "Admin", "z"); err != nil {
		t.Errorf("a look-alike org read as the admin org: %v", err)
	}
}

// An owner's account is written by the owner and by a SuperAdmin, never by
// another person: an admin who could reset it could sign in as the owner, of
// this org or of any other it owns. An application keeps its allowlisted reach,
// which is how the platform writes a person's own profile for them.
func TestAuthorizeKeepsAnOwnersAccountFromOtherPeople(t *testing.T) {
	db := consentTestDB(t)
	api := New(db)
	seedMember(t, api, "ann", nil)
	seedMember(t, api, "bob", nil)
	ctx := context.Background()
	if _, err := store.SetRole(ctx, db, "hanzo/ann", "acme", store.RoleOwner, ""); err != nil {
		t.Fatal(err)
	}

	boss := as(&principal.Principal{Org: "hanzo", User: "boss", Admin: true})
	coowner := as(&principal.Principal{Org: "acme", User: "cy", Orgs: map[string]policy.Role{"acme": policy.Owner}})
	self := as(&principal.Principal{Org: "hanzo", User: "Ann"})
	app := as(&principal.Principal{Org: "hanzo", App: &policy.App{Name: "hanzo-console", Owner: policy.AdminOrg}})
	super := as(&principal.Principal{Org: policy.AdminOrg, User: "z", Sudo: true})

	for name, c := range map[string]context.Context{"home org admin": boss, "co-owner": coowner} {
		if err := Authorize(c, db, "hanzo", "ann"); !forbidden(err) {
			t.Errorf("%s writing an owner's account: %v, want 403", name, err)
		}
		if err := Authorize(c, db, "hanzo", "ANN"); !forbidden(err) {
			t.Errorf("%s writing an owner's account by a folded name: %v, want 403", name, err)
		}
	}
	for name, c := range map[string]context.Context{"the owner": self, "an application": app, "a SuperAdmin": super} {
		if err := Authorize(c, db, "hanzo", "ann"); err != nil {
			t.Errorf("%s writing the owner's account: %v", name, err)
		}
	}
	if err := Authorize(boss, db, "hanzo", "bob"); err != nil {
		t.Errorf("an admin writing a member's account: %v", err)
	}
}

// How a person signs in is theirs and a SuperAdmin's: an org's admin reaches a
// member's profile but never their password, address, factors or keys, so
// nothing an admin files for a member signs in as them once they own the org, or
// in another org they belong to. A machine's credentials are its org admin's.
func TestCredentialIsTheHoldersOrASuperAdmins(t *testing.T) {
	db := consentTestDB(t)
	api := New(db)
	seedMember(t, api, "ann", nil)
	bot := orm.New[schema.User](db)
	bot.Owner, bot.Name, bot.Type = "hanzo", "bot", "service-account"
	bot.SetId("hanzo/bot")
	if err := bot.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	boss := as(&principal.Principal{Org: "hanzo", User: "boss", Admin: true, Orgs: map[string]policy.Role{"hanzo": policy.Admin}})
	ann := as(&principal.Principal{Org: "hanzo", User: "ann"})
	super := as(&principal.Principal{Org: policy.AdminOrg, User: "z", Sudo: true})

	if err := Credential(boss, db, "hanzo", "ann"); !forbidden(err) {
		t.Errorf("an admin writing a member's credentials: %v, want 403", err)
	}
	if err := Credential(context.Background(), db, "hanzo", "ann"); !forbidden(err) {
		t.Errorf("no caller writing a person's credentials: %v, want 403", err)
	}
	for name, ctx := range map[string]context.Context{"the holder": ann, "a SuperAdmin": super} {
		if err := Credential(ctx, db, "hanzo", "ann"); err != nil {
			t.Errorf("%s writing ann's credentials: %v", name, err)
		}
	}
	if err := Credential(boss, db, "hanzo", "bot"); err != nil {
		t.Errorf("an admin writing its org's machine credentials: %v", err)
	}

	if _, err := api.Update(boss, &UpdateInput{User: schema.User{Owner: "hanzo", Name: "ann", DisplayName: "Ann A"}}); err != nil {
		t.Errorf("an admin's profile edit: %v", err)
	}
	if _, err := api.Update(boss, &UpdateInput{User: schema.User{Owner: "hanzo", Name: "ann"}, Password: "admin-knows-this"}); !forbidden(err) {
		t.Errorf("an admin resetting a member's password: %v, want 403", err)
	}
	if _, err := api.Update(boss, &UpdateInput{User: schema.User{Owner: "hanzo", Name: "ann", Email: "boss@evil.test"}}); !forbidden(err) {
		t.Errorf("an admin moving a member's address: %v, want 403", err)
	}
}
