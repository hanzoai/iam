// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/hanzoai/iam/pkg/model"
	"github.com/hanzoai/iam/pkg/store"
)

// A founding application moves each account it registers into an org of its own
// and the account keeps its username there, so the registration org finds it by
// that name in whatever org it now works in, as it does by address.
func TestSignupByNameFindsAnAccountInItsOwnOrg(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-app", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "ada@gmail.com", SignupApplication: "hanzo-app"})

	for _, typed := range []string{"ada", "Ada", " ADA "} {
		got, held, err := store.SignupByName(context.Background(), db, "hanzo", typed)
		if err != nil {
			t.Fatalf("SignupByName(%q): %v", typed, err)
		}
		if held != 1 || got == nil || got.Owner != "ada" || got.Name != "ada" {
			t.Fatalf("SignupByName(%q) = %v, %d; want ada/ada once — org hanzo registered this account", typed, got, held)
		}
	}
}

// Every application of the org reaches the same accounts by name.
func TestSignupByNameReadsEverySiblingApplication(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-ai", "hanzo")
	addApp(t, db, "hanzo-app", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", SignupApplication: "hanzo-ai"})

	got, held, err := store.SignupByName(context.Background(), db, "hanzo", "ada")
	if err != nil {
		t.Fatalf("SignupByName: %v", err)
	}
	if held != 1 || got == nil || got.Owner != "ada" {
		t.Fatalf("got %v, %d; want ada/ada — hanzo-ai is an application of hanzo", got, held)
	}
}

// It reads only the rows the org's applications registered: another org's
// registration, a row nothing registered, and a row naming a retired application
// stay unreachable. This is not a cross-org lookup by name.
func TestSignupByNameReadsOnlyItsOrgsAccounts(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "lux-cloud", "lux")
	addUser(t, db, &model.User{Owner: "bob", Name: "bob", SignupApplication: "lux-cloud"})
	addUser(t, db, &model.User{Owner: "carol", Name: "carol"})
	addUser(t, db, &model.User{Owner: "dan", Name: "dan", SignupApplication: "retired"})

	for _, name := range []string{"bob", "carol", "dan"} {
		got, held, err := store.SignupByName(context.Background(), db, "hanzo", name)
		if err != nil {
			t.Fatalf("SignupByName(%q): %v", name, err)
		}
		if got != nil || held != 0 {
			t.Fatalf("%q reached %v (%d) — an account org hanzo did not register", name, got, held)
		}
	}
}

// Two of one org's registrations holding a name (written before names were unique
// across a registration org) name nobody, and the count says so.
func TestSignupByNameNamesNobodyWhenTwoAccountsHoldIt(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-app", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "ada@one.com", SignupApplication: "hanzo-app"})
	addUser(t, db, &model.User{Owner: "ada2", Name: "ada", Email: "ada@two.com", SignupApplication: "hanzo-app"})

	got, held, err := store.SignupByName(context.Background(), db, "hanzo", "ada")
	if err != nil {
		t.Fatalf("SignupByName: %v", err)
	}
	if got != nil || held != 2 {
		t.Fatalf("a name two accounts hold answered %v, %d; want nobody, 2", got, held)
	}
}

// A name many orgs hold is read again through org's own applications, so other
// orgs' registrations neither hide org's account nor make it ambiguous.
func TestSignupByNameReadsACrowdedNameExactly(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-app", "hanzo")
	addApp(t, db, "other-app", "other")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", SignupApplication: "hanzo-app"})
	for i := 0; i < 64; i++ {
		addUser(t, db, &model.User{Owner: fmt.Sprintf("o%d", i), Name: "ada", SignupApplication: "other-app"})
	}

	got, held, err := store.SignupByName(context.Background(), db, "hanzo", "ada")
	if err != nil {
		t.Fatalf("SignupByName: %v", err)
	}
	if held != 1 || got == nil || got.Owner != "ada" {
		t.Fatalf("a crowded name answered %v, %d; want ada/ada once", got, held)
	}

	addUser(t, db, &model.User{Owner: "ada2", Name: "ada", SignupApplication: "hanzo-app"})
	if got, held, err = store.SignupByName(context.Background(), db, "hanzo", "ada"); err != nil || got != nil || held != 2 {
		t.Fatalf("a crowded name two of org's accounts hold answered %v, %d, %v; want nobody, 2", got, held, err)
	}
}

// A reserved owner is never reachable here, for the reason it is not by address.
func TestSignupByNameNeverReachesAReservedOrg(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-app", "hanzo")
	addUser(t, db, &model.User{Owner: "admin", Name: "super", SignupApplication: "hanzo-app"})

	got, held, err := store.SignupByName(context.Background(), db, "hanzo", "super")
	if err != nil {
		t.Fatalf("SignupByName: %v", err)
	}
	if got != nil || held != 0 {
		t.Fatalf("resolved %v (%d) — a reserved org", got, held)
	}
}

// An unnamed org or a blank name matches nothing rather than everything.
func TestSignupByNameIgnoresBlankInput(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "loose", "")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", SignupApplication: "loose"})

	for _, c := range []struct{ org, name string }{{"", "ada"}, {"hanzo", ""}, {"hanzo", "   "}} {
		got, held, err := store.SignupByName(context.Background(), db, c.org, c.name)
		if err != nil {
			t.Fatalf("SignupByName(%q, %q): %v", c.org, c.name, err)
		}
		if got != nil || held != 0 {
			t.Fatalf("SignupByName(%q, %q) resolved %v (%d)", c.org, c.name, got, held)
		}
	}
}
