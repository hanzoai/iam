// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/model"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// addApp registers an application of org under the platform registry, the way
// every first-party client is stored.
func addApp(t *testing.T, db orm.DB, name, org string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId, a.Organization = "admin", name, name, org
	a.SetId("admin/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed app %s: %v", name, err)
	}
}

// The reach that makes a per-person tenant addressable: the org an account
// registered in finds it, in whatever org that account now works.
func TestGetSignupByEmailFindsAnAccountInItsOwnOrg(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "ada@gmail.com", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByEmail(context.Background(), db, "hanzo", "Ada@Gmail.com")
	if err != nil {
		t.Fatalf("GetSignupByEmail: %v", err)
	}
	if got == nil || got.Name != "ada" {
		t.Fatalf("got %v, want ada — org hanzo registered this address", got)
	}
}

// Every application of the org reaches the same accounts. A person who registered
// at hanzo.ai is the same person at the console and the CLI.
func TestGetSignupByEmailReadsEverySiblingApplication(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-ai", "hanzo")
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "ada@gmail.com", SignupApplication: "hanzo-ai"})

	got, err := store.GetSignupByEmail(context.Background(), db, "hanzo", "ada@gmail.com")
	if err != nil {
		t.Fatalf("GetSignupByEmail: %v", err)
	}
	if got == nil || got.Name != "ada" {
		t.Fatalf("got %v, want ada — hanzo-ai is an application of hanzo", got)
	}
}

// It reads ONLY the rows the org's applications registered. Another org's
// registration, a row no application registered (seeded, imported), and a row
// naming an application that no longer exists stay unreachable — this is not a
// cross-org lookup by address.
func TestGetSignupByEmailReadsOnlyItsOrgsAccounts(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "lux-cloud", "lux")
	addUser(t, db, &model.User{Owner: "bob", Name: "bob", Email: "bob@gmail.com", SignupApplication: "lux-cloud"})
	addUser(t, db, &model.User{Owner: "carol", Name: "carol", Email: "carol@gmail.com"})
	addUser(t, db, &model.User{Owner: "dan", Name: "dan", Email: "dan@gmail.com", SignupApplication: "retired"})

	for _, addr := range []string{"bob@gmail.com", "carol@gmail.com", "dan@gmail.com"} {
		got, err := store.GetSignupByEmail(context.Background(), db, "hanzo", addr)
		if err != nil {
			t.Fatalf("GetSignupByEmail(%q): %v", addr, err)
		}
		if got != nil {
			t.Fatalf("%q reached %s — an account org hanzo did not register", addr, got.Name)
		}
	}
}

// An unnamed org matches nothing rather than everything: an application with no
// org would otherwise match every row an org-less application registered.
func TestGetSignupByEmailIgnoresBlankInput(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "loose", "")
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "ada@gmail.com", SignupApplication: "loose"})
	addUser(t, db, &model.User{Owner: "eve", Name: "eve", SignupApplication: "hanzo-cloud"})

	for _, c := range []struct{ org, email string }{
		{"", "ada@gmail.com"},
		{"hanzo", ""},
		{"hanzo", "   "},
	} {
		got, err := store.GetSignupByEmail(context.Background(), db, c.org, c.email)
		if err != nil {
			t.Fatalf("GetSignupByEmail(%q, %q): %v", c.org, c.email, err)
		}
		if got != nil {
			t.Fatalf("GetSignupByEmail(%q, %q) resolved %s", c.org, c.email, got.Name)
		}
	}
}

// Ambiguity fails closed, as it does on every other identifier: two of one org's
// registrations carrying one address name nobody, whichever applications made them.
func TestGetSignupByEmailRefusesAnAmbiguousAddress(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-ai", "hanzo")
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "shared@gmail.com", SignupApplication: "hanzo-ai"})
	addUser(t, db, &model.User{Owner: "grace", Name: "grace", Email: "shared@gmail.com", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByEmail(context.Background(), db, "hanzo", "shared@gmail.com")
	if !errors.Is(err, store.ErrEmailAmbiguous) {
		t.Fatalf("err = %v, want ErrEmailAmbiguous", err)
	}
	if got != nil {
		t.Fatalf("a user was returned for an ambiguous address: %s", got.Name)
	}
}

// Another org registering the same address is not ambiguity: it is a different
// registration, and each org finds its own.
func TestGetSignupByEmailKeepsEachOrgsRegistrationApart(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-cloud", "hanzo")
	addApp(t, db, "lux-cloud", "lux")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "ada@gmail.com", SignupApplication: "hanzo-cloud"})
	addUser(t, db, &model.User{Owner: "ada2", Name: "ada", Email: "ada@gmail.com", SignupApplication: "lux-cloud"})

	for org, want := range map[string]string{"hanzo": "ada", "lux": "ada2"} {
		got, err := store.GetSignupByEmail(context.Background(), db, org, "ada@gmail.com")
		if err != nil {
			t.Fatalf("GetSignupByEmail(%q): %v", org, err)
		}
		if got == nil || got.Owner != want {
			t.Fatalf("org %s resolved %v, want the account in %s", org, got, want)
		}
	}
}

// The subject is what says "this is the same person" on a return visit, so the
// org has to find them wherever founding put them, whichever of its applications
// they first signed in through.
func TestGetSignupByConnectorFindsAReturningPerson(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-ai", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Google: "idp-1", SignupApplication: "hanzo-ai"})

	got, err := store.GetSignupByConnector(context.Background(), db, "hanzo", "google", "idp-1")
	if err != nil {
		t.Fatalf("GetSignupByConnector: %v", err)
	}
	if got == nil || got.Name != "ada" {
		t.Fatalf("got %v, want ada", got)
	}
}

// Another org's link, an empty subject and an unnamed org all resolve nobody: an
// empty filter would match every unlinked row in the store.
func TestGetSignupByConnectorReadsOnlyItsOrgsAccounts(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "lux-cloud", "lux")
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "bob", Name: "bob", Google: "idp-2", SignupApplication: "lux-cloud"})
	addUser(t, db, &model.User{Owner: "eve", Name: "eve", SignupApplication: "hanzo-cloud"})

	for _, c := range []struct{ org, field, subject string }{
		{"hanzo", "google", "idp-2"},
		{"hanzo", "google", ""},
		{"", "google", "idp-2"},
		{"hanzo", "", "idp-2"},
	} {
		got, err := store.GetSignupByConnector(context.Background(), db, c.org, c.field, c.subject)
		if err != nil {
			t.Fatalf("GetSignupByConnector(%q,%q,%q): %v", c.org, c.field, c.subject, err)
		}
		if got != nil {
			t.Fatalf("GetSignupByConnector(%q,%q,%q) resolved %s", c.org, c.field, c.subject, got.Name)
		}
	}
}

// One subject on two of an org's registrations names nobody.
func TestGetSignupByConnectorRefusesADuplicatedSubject(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-ai", "hanzo")
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Google: "idp-1", SignupApplication: "hanzo-ai"})
	addUser(t, db, &model.User{Owner: "ada2", Name: "ada", Google: "idp-1", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByConnector(context.Background(), db, "hanzo", "google", "idp-1")
	if err == nil {
		t.Fatalf("a duplicated subject resolved %v", got)
	}
	if got != nil {
		t.Fatalf("a user was returned for a duplicated subject: %s", got.Name)
	}
}

// A reserved owner is unreachable by subject too, for the reason it is by address.
func TestGetSignupByConnectorNeverReachesAReservedOrg(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "admin", Name: "super", Google: "idp-1", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByConnector(context.Background(), db, "hanzo", "google", "idp-1")
	if err != nil {
		t.Fatalf("GetSignupByConnector: %v", err)
	}
	if got != nil {
		t.Fatalf("resolved %s/%s — a reserved org", got.Owner, got.Name)
	}
}

// A reserved owner is never reachable here. The admin org holds the SuperAdmin,
// and nothing should file one of its rows under an application's signup — if
// something does, this must not be the lookup that authenticates it.
func TestGetSignupByEmailNeverReachesAReservedOrg(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "admin", Name: "super", Email: "super@example.com", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByEmail(context.Background(), db, "hanzo", "super@example.com")
	if err != nil {
		t.Fatalf("GetSignupByEmail: %v", err)
	}
	if got != nil {
		t.Fatalf("resolved %s/%s — a reserved org", got.Owner, got.Name)
	}
}
