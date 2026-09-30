// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

import (
	"context"
	"errors"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func deleteOrg(t *testing.T, api *organizations.OrganizationAPI, name string) {
	t.Helper()
	if _, err := api.Delete(context.Background(), &organizations.DeleteOrganizationInput{Owner: policy.AdminOrg, Name: name}); err != nil {
		t.Fatalf("delete %s: %v", name, err)
	}
}

// Deleting an org never frees its name. Every service keys a tenant by that name
// (commerce's balance, KMS's /orgs/<org>/, per-org data), so whoever founded it
// next would inherit all of it. A tombstone holds the name.
func TestDelete_leavesATombstoneThatHoldsTheName(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	put(t, db, "widgets")
	seedRow(t, db, "widgets/join-1", func(r *schema.Invitation) { r.Owner, r.Name = "widgets", "join-1" })
	deleteOrg(t, api, "widgets")

	if held, err := store.OrgHeld(ctx, db, "widgets"); err != nil || !held {
		t.Fatalf("OrgHeld after delete = %v %v, want held", held, err)
	}
	if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, "widgets")))); got != 409 {
		t.Fatalf("re-found: status=%d, want 409", got)
	}
}

// Red's credential case: rows bound to an account by name (wallet, passkey,
// refresh token) go with the account, and the org's audit trail and teams can no
// longer reach a new org because its name is never founded again.
func TestDelete_credentialAndAuditRowsNeverCarryIntoANewOrg(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	put(t, db, "widgets")
	seedAccount(t, db, "widgets", "alice", "normal-user")
	seedRow(t, db, "widgets/alice/evm/0xabc", func(r *schema.Wallet) {
		r.Owner, r.User, r.Chain, r.Address = "widgets", "alice", "evm", "0xabc"
	})
	seedRow(t, db, "widgets/pk-1", func(r *schema.WebauthnCredential) {
		r.Owner, r.Name, r.User = "widgets", "pk-1", "widgets/alice"
	})
	seedRow(t, db, "admin/rt-1", func(r *schema.Token) {
		r.Owner, r.Name, r.Organization, r.User, r.Application = "admin", "rt-1", "widgets", "widgets/alice", "hanzo-console"
	})
	seedRow(t, db, "widgets/log-1", func(r *schema.AuditLog) {
		r.Owner, r.Name, r.Organization, r.Action = "widgets", "log-1", "widgets", "secret-action"
	})
	seedRow(t, db, "widgets/eng", func(r *schema.Team) { r.Owner, r.Name, r.Organization = "widgets", "eng", "widgets" })

	alice, _ := store.GetUserByName(ctx, db, "widgets", "alice")
	if err := store.DeleteUser(ctx, db, alice); err != nil {
		t.Fatalf("delete account: %v", err)
	}
	for id, gone := range map[string]error{
		"wallet":  getErr[schema.Wallet](db, "widgets/alice/evm/0xabc"),
		"passkey": getErr[schema.WebauthnCredential](db, "widgets/pk-1"),
		"token":   getErr[schema.Token](db, "admin/rt-1"),
	} {
		if !errors.Is(gone, orm.ErrNotFound) {
			t.Fatalf("the account's %s outlived it: %v", id, gone)
		}
	}
	deleteOrg(t, api, "widgets")
	if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, "widgets")))); got != 409 {
		t.Fatalf("re-found: status=%d, want 409", got)
	}
}

func getErr[T any](db orm.DB, id string) error { _, err := orm.Get[T](db, id); return err }

// Red's provider case: an application of another org that links the removed org's
// provider loses the link, so no later provider of that name is ever reached
// through it — and none can be made, because the name stays held.
func TestDelete_crossOrgProviderLinksAreRemoved(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	put(t, db, "widgets")
	put(t, db, "acme")
	seedRow(t, db, "widgets/okta", func(r *schema.Provider) {
		r.Owner, r.Name, r.Type, r.ClientId = "widgets", "okta", "Okta", "victim-client"
	})
	seedRow(t, db, "acme/portal", func(r *schema.Application) {
		r.Owner, r.Name, r.Organization = "acme", "portal", "acme"
		r.Providers = []*schema.ProviderItem{{Owner: "widgets", Name: "okta", CanSignIn: true}, {Owner: "acme", Name: "google", CanSignIn: true}}
	})
	deleteOrg(t, api, "widgets")

	app, err := orm.Get[schema.Application](db, "acme/portal")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range app.Providers {
		if p.Owner == "widgets" {
			t.Fatalf("acme/portal still links %s/%s", p.Owner, p.Name)
		}
	}
	if len(app.Providers) != 1 {
		t.Fatalf("the application's own links were touched: %v", app.Providers)
	}
	if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, "widgets")))); got != 409 {
		t.Fatalf("re-found: status=%d, want 409", got)
	}
}

// IAM's own create takes only a name no customer is refused and only in the shape
// every person-facing path produces: lowercase ASCII.
func TestCreate_refusesHeldAndNonLowercaseNames(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	for _, n := range []string{"hanzoai", "luxfi", "hanzo-apps", "built-in", "app", "OSAGE", "Hanzo", "acme corp", "acmé", "-acme"} {
		if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, n)))); got != 400 {
			t.Fatalf("Create(%q): status=%d, want 400", n, got)
		}
	}
}

// An org created and never founded, with nothing keyed by it, leaves no tombstone:
// it was never anybody's. That is the org cloud removes when its owner cannot be
// recorded, so a refused founding cannot use up a name. A founded org always
// leaves one, even when nothing else names it.
func TestDelete_tombstoneOnlyForAnOrgThatWasSomebodys(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()

	put(t, db, "unfounded")
	deleteOrg(t, api, "unfounded")
	if held, err := store.OrgHeld(ctx, db, "unfounded"); err != nil || held {
		t.Fatalf("a never-founded org held its name: %v %v", held, err)
	}
	if _, err := api.Create(ctx, createIn(policy.AdminOrg, "unfounded")); err != nil {
		t.Fatalf("a never-founded org's name must be free: %v", err)
	}

	put(t, db, "founded")
	o, _ := store.GetOrganizationByName(ctx, db, "founded")
	o.Founder = "founder-key"
	if err := o.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	deleteOrg(t, api, "founded")
	if held, _ := store.OrgHeld(ctx, db, "founded"); !held {
		t.Fatal("a founded org's name was freed")
	}
}
