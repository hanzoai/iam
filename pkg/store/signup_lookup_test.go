// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/iam/pkg/model"
	"github.com/hanzoai/iam/pkg/store"
)

// The reach that makes a per-person tenant addressable: an application finds the
// account it registered, in whatever org that account now works in.
func TestGetSignupByEmailFindsAnAccountInItsOwnOrg(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "ada@gmail.com", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByEmail(context.Background(), db, "hanzo-cloud", "Ada@Gmail.com")
	if err != nil {
		t.Fatalf("GetSignupByEmail: %v", err)
	}
	if got == nil || got.Name != "ada" {
		t.Fatalf("got %v, want ada — the application registered this address", got)
	}
}

// It reads ONLY the rows the named application created. Another application's
// account, and a row no application created (seeded, imported), stay unreachable —
// this is not a cross-org lookup by address.
func TestGetSignupByEmailReadsOnlyItsOwnAccounts(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "bob", Name: "bob", Email: "bob@gmail.com", SignupApplication: "other"})
	addUser(t, db, &model.User{Owner: "carol", Name: "carol", Email: "carol@gmail.com"})

	for _, addr := range []string{"bob@gmail.com", "carol@gmail.com"} {
		got, err := store.GetSignupByEmail(context.Background(), db, "hanzo-cloud", addr)
		if err != nil {
			t.Fatalf("GetSignupByEmail(%q): %v", addr, err)
		}
		if got != nil {
			t.Fatalf("%q reached %s — an account this application did not register", addr, got.Name)
		}
	}
}

// An unnamed application matches nothing rather than everything: the field is
// empty on every seeded and imported row, so an empty filter would resolve them
// all and hand the caller an arbitrary one.
func TestGetSignupByEmailIgnoresBlankInput(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "ada@gmail.com"})
	addUser(t, db, &model.User{Owner: "eve", Name: "eve", SignupApplication: "hanzo-cloud"})

	for _, c := range []struct{ application, email string }{
		{"", "ada@gmail.com"},
		{"hanzo-cloud", ""},
		{"hanzo-cloud", "   "},
	} {
		got, err := store.GetSignupByEmail(context.Background(), db, c.application, c.email)
		if err != nil {
			t.Fatalf("GetSignupByEmail(%q, %q): %v", c.application, c.email, err)
		}
		if got != nil {
			t.Fatalf("GetSignupByEmail(%q, %q) resolved %s", c.application, c.email, got.Name)
		}
	}
}

// Ambiguity fails closed, as it does on every other identifier: two of one
// application's accounts carrying one address name nobody.
func TestGetSignupByEmailRefusesAnAmbiguousAddress(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Email: "shared@gmail.com", SignupApplication: "hanzo-cloud"})
	addUser(t, db, &model.User{Owner: "grace", Name: "grace", Email: "shared@gmail.com", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByEmail(context.Background(), db, "hanzo-cloud", "shared@gmail.com")
	if !errors.Is(err, store.ErrEmailAmbiguous) {
		t.Fatalf("err = %v, want ErrEmailAmbiguous", err)
	}
	if got != nil {
		t.Fatalf("a user was returned for an ambiguous address: %s", got.Name)
	}
}

// The subject is what says "this is the same person" on a return visit, so the
// application has to find them wherever founding put them.
func TestGetSignupByConnectorFindsAReturningPerson(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Google: "idp-1", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByConnector(context.Background(), db, "hanzo-cloud", "google", "idp-1")
	if err != nil {
		t.Fatalf("GetSignupByConnector: %v", err)
	}
	if got == nil || got.Name != "ada" {
		t.Fatalf("got %v, want ada", got)
	}
}

// Another application's link, an empty subject and an unnamed application all
// resolve nobody: an empty filter would match every unlinked row in the store.
func TestGetSignupByConnectorReadsOnlyItsOwnAccounts(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "bob", Name: "bob", Google: "idp-2", SignupApplication: "other"})
	addUser(t, db, &model.User{Owner: "eve", Name: "eve", SignupApplication: "hanzo-cloud"})

	for _, c := range []struct{ application, field, subject string }{
		{"hanzo-cloud", "google", "idp-2"},
		{"hanzo-cloud", "google", ""},
		{"", "google", "idp-2"},
		{"hanzo-cloud", "", "idp-2"},
	} {
		got, err := store.GetSignupByConnector(context.Background(), db, c.application, c.field, c.subject)
		if err != nil {
			t.Fatalf("GetSignupByConnector(%q,%q,%q): %v", c.application, c.field, c.subject, err)
		}
		if got != nil {
			t.Fatalf("GetSignupByConnector(%q,%q,%q) resolved %s", c.application, c.field, c.subject, got.Name)
		}
	}
}

// A reserved owner is unreachable by subject too, for the reason it is by address.
func TestGetSignupByConnectorNeverReachesAReservedOrg(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "admin", Name: "super", Google: "idp-1", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByConnector(context.Background(), db, "hanzo-cloud", "google", "idp-1")
	if err != nil {
		t.Fatalf("GetSignupByConnector: %v", err)
	}
	if got != nil {
		t.Fatalf("resolved %s/%s — a reserved org", got.Owner, got.Name)
	}
}

// A reserved owner is never reachable here. The admin org holds the SuperAdmin,
// and nothing should file one of its rows under an application's signup — if
// something does, this must not be the door that authenticates it.
func TestGetSignupByEmailNeverReachesAReservedOrg(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "admin", Name: "super", Email: "super@example.com", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByEmail(context.Background(), db, "hanzo-cloud", "super@example.com")
	if err != nil {
		t.Fatalf("GetSignupByEmail: %v", err)
	}
	if got != nil {
		t.Fatalf("resolved %s/%s — a reserved org", got.Owner, got.Name)
	}
}
