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

// The address reaches its owner, however the person typed it. Every write site
// stored the lowered form while this lookup compared the raw spelling, so anyone
// who capitalized a letter of their own address created an account and was then
// told their password was wrong — for the password they had just chosen.
func TestGetUserByEmailMatchesAnySpelling(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "hanzo", Name: "ada", Email: "ada.lovelace@gmail.com"})

	for _, typed := range []string{
		"ada.lovelace@gmail.com",
		"Ada.Lovelace@Gmail.com",
		"ADA.LOVELACE@GMAIL.COM",
		"  ada.lovelace@gmail.com  ",
	} {
		got, err := store.GetUserByEmail(context.Background(), db, "hanzo", typed)
		if err != nil {
			t.Fatalf("GetUserByEmail(%q): %v", typed, err)
		}
		if got == nil || got.Name != "ada" {
			t.Errorf("GetUserByEmail(%q) = %v, want ada", typed, got)
		}
	}
}

// THE security property, and it is the phone rule read on the other identifier.
// The document store hangs no per-field UNIQUE constraint, so two rows in one org
// can carry one address; returning either of them would authenticate a person
// against somebody else's account. The live table already holds three such
// addresses, so this is not hypothetical.
func TestGetUserByEmailRefusesAnAmbiguousAddress(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "hanzo", Name: "ada", Email: "shared@gmail.com"})
	addUser(t, db, &model.User{Owner: "hanzo", Name: "grace", Email: "shared@gmail.com"})

	got, err := store.GetUserByEmail(context.Background(), db, "hanzo", "shared@gmail.com")
	if !errors.Is(err, store.ErrEmailAmbiguous) {
		t.Fatalf("err = %v, want ErrEmailAmbiguous — an address naming two accounts must name none", err)
	}
	if got != nil {
		t.Fatalf("a user was returned for an ambiguous address: %s", got.Name)
	}
}

// A blank address must never match the many rows that legitimately store none.
// Without the guard this is an authentication oracle: an empty identifier would
// resolve to an arbitrary account.
func TestGetUserByEmailIgnoresBlankInput(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "hanzo", Name: "ada"})
	addUser(t, db, &model.User{Owner: "hanzo", Name: "grace"})

	for _, blank := range []string{"", "   "} {
		got, err := store.GetUserByEmail(context.Background(), db, "hanzo", blank)
		if err != nil {
			t.Fatalf("GetUserByEmail(%q): %v", blank, err)
		}
		if got != nil {
			t.Fatalf("blank address %q resolved to %s — an empty identifier must match nobody", blank, got.Name)
		}
	}
}

// The lookup is org-scoped: one tenant's address never reaches another's account.
func TestGetUserByEmailIsOrgScoped(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "hanzo", Name: "ada", Email: "ada@gmail.com"})

	got, err := store.GetUserByEmail(context.Background(), db, "lux", "ada@gmail.com")
	if err != nil {
		t.Fatalf("GetUserByEmail: %v", err)
	}
	if got != nil {
		t.Fatalf("cross-tenant resolve: org lux reached %s", got.Name)
	}
}
