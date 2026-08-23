// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// federatedApp is a founding application and its Google binding, on a fresh store.
func federatedApp(t *testing.T) (orm.DB, *schema.Application, *schema.Provider, connectorBinding) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	app := &schema.Application{Organization: "hanzo", OrgChoiceMode: "create", EnableSignUp: true}
	app.Name = "hanzo-cloud"
	prov := &schema.Provider{Type: "Google"}
	prov.Name = "google"
	binding, ok := connectorFor(prov.Type)
	if !ok {
		t.Fatalf("no connector binding for %q", prov.Type)
	}
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", "hanzo"
	o.SetId("admin/hanzo")
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	return db, app, prov, binding
}

// Signing in with a social identity founds an org too. It is the same path as the
// password signup — an account arrives from an identity provider rather than a
// form — so it must not leave people in the application's own org.
func TestFederation_FoundsItsOwnOrg(t *testing.T) {
	ctx := context.Background()
	db, app, prov, binding := federatedApp(t)

	u, err := provisionFederatedUser(ctx, db, app, prov, binding,
		federatedIdentity{subject: "idp-1", email: "social@example.com", emailVerified: true})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if u.Owner == "hanzo" {
		t.Fatal("the account was filed in the application's own org")
	}
	if u.Owner != "social" {
		t.Fatalf("owner = %q, want the personal org \"social\"", u.Owner)
	}
	// The row that comes back is the one the caller mints a token from, so it must
	// carry what the converge decided, not what it looked like before.
	if !u.IsAdmin {
		t.Error("the founder is not their own org's admin on the row returned")
	}
	org, err := store.GetOrganizationByName(ctx, db, "social")
	if err != nil || org == nil || !org.IsPersonal {
		t.Fatalf("personal org not founded: %v %v", org, err)
	}
	rows, err := store.MembershipsByOrg(ctx, db, "social")
	if err != nil {
		t.Fatalf("roster: %v", err)
	}
	if len(rows) != 1 || rows[0].User != "social/social" {
		t.Fatalf("roster = %v, want exactly social/social", rows)
	}
}

// The SAME person coming back gets the SAME account. The provider's subject is
// what says "this is them", and once founding moves them out of the application's
// org a reach that stops there answers "new" on every visit — which hands one
// human a fresh account, and a fresh org, every time they sign in.
func TestFederation_ReturningPersonKeepsTheirAccount(t *testing.T) {
	ctx := context.Background()
	db, app, prov, _ := federatedApp(t)

	id := federatedIdentity{subject: "idp-1", email: "social@example.com", emailVerified: true}
	first, err := linkOrProvision(ctx, db, app, prov, id)
	if err != nil {
		t.Fatalf("first sign-in: %v", err)
	}
	again, err := linkOrProvision(ctx, db, app, prov, id)
	if err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	if again.Owner != first.Owner || again.Name != first.Name {
		t.Fatalf("second sign-in resolved %s/%s, want %s/%s", again.Owner, again.Name, first.Owner, first.Name)
	}
	// And no second org was founded for the same human.
	if org, _ := store.GetOrganizationByName(ctx, db, "social2"); org != nil {
		t.Fatal("a second org was founded for a returning person")
	}
}

// The subject alone brings a returning person back, with no help from the
// address. This is what the subject match is FOR — it is immune to email churn —
// and it is the arm that has to reach across founding on its own: someone who
// changed their address at the identity provider has nothing else left in common
// with their account.
func TestFederation_ReturningPersonFoundBySubjectAlone(t *testing.T) {
	ctx := context.Background()
	db, app, prov, binding := federatedApp(t)

	first, err := provisionFederatedUser(ctx, db, app, prov, binding,
		federatedIdentity{subject: "idp-1", email: "before@example.com", emailVerified: true})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	again, err := linkOrProvision(ctx, db, app, prov,
		federatedIdentity{subject: "idp-1", email: "after@example.com", emailVerified: true})
	if err != nil {
		t.Fatalf("return with a new address: %v", err)
	}
	if again.Owner != first.Owner || again.Name != first.Name {
		t.Fatalf("resolved %s/%s, want %s/%s — the subject is the same person",
			again.Owner, again.Name, first.Owner, first.Name)
	}
	if org, _ := store.GetOrganizationByName(ctx, db, "after"); org != nil {
		t.Fatal("a second org was founded for a person who only changed their address")
	}
}

// A person returning from the SAME provider under a new subject — or arriving at
// an address a founded account already holds — is linked to that account rather
// than given a second one on the same address.
func TestFederation_AddressStaysHeldAfterFounding(t *testing.T) {
	ctx := context.Background()
	db, app, prov, binding := federatedApp(t)

	first, err := provisionFederatedUser(ctx, db, app, prov, binding,
		federatedIdentity{subject: "idp-1", email: "social@example.com", emailVerified: true})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	again, err := linkOrProvision(ctx, db, app, prov,
		federatedIdentity{subject: "idp-2", email: "social@example.com", emailVerified: true})
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	if again.Owner != first.Owner || again.Name != first.Name {
		t.Fatalf("linked to %s/%s, want the account that holds the address, %s/%s",
			again.Owner, again.Name, first.Owner, first.Name)
	}
	if org, _ := store.GetOrganizationByName(ctx, db, "social2"); org != nil {
		t.Fatal("a second org was founded on an address already held")
	}
}

// An application that does not found orgs is untouched by any of this.
func TestFederation_AppThatDoesNotFoundIsUnchanged(t *testing.T) {
	ctx := context.Background()
	db, app, prov, binding := federatedApp(t)
	app.OrgChoiceMode = ""

	u, err := provisionFederatedUser(ctx, db, app, prov, binding,
		federatedIdentity{subject: "idp-1", email: "social@example.com", emailVerified: true})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if u.Owner != "hanzo" {
		t.Fatalf("owner = %q, want hanzo — this app declares no founding", u.Owner)
	}
	if org, _ := store.GetOrganizationByName(ctx, db, "social"); org != nil {
		t.Fatal("an org was founded for an application that does not found orgs")
	}
}
