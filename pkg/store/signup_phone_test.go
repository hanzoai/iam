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

// The number on an account an org registered reaches it, in whatever org it works
// and however the number is punctuated.
func TestGetSignupByPhoneFindsAnAccountInItsOwnOrg(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Phone: "+14155550134", SignupApplication: "hanzo-cloud"})

	for _, typed := range []string{"+14155550134", "+1 (415) 555-0134", " +1 415 555 0134 "} {
		got, err := store.GetSignupByPhone(context.Background(), db, "hanzo", typed)
		if err != nil {
			t.Fatalf("GetSignupByPhone(%q): %v", typed, err)
		}
		if got == nil || got.Owner != "ada" || got.Name != "ada" {
			t.Fatalf("GetSignupByPhone(%q) = %v, want ada/ada", typed, got)
		}
	}
}

// Only the org's registrations: another org's, a seeded row and a reserved owner
// stay unreachable, and blank input matches nothing.
func TestGetSignupByPhoneReadsOnlyItsOrgsAccounts(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-cloud", "hanzo")
	addApp(t, db, "lux-cloud", "lux")
	addUser(t, db, &model.User{Owner: "bob", Name: "bob", Phone: "+15550000001", SignupApplication: "lux-cloud"})
	addUser(t, db, &model.User{Owner: "carol", Name: "carol", Phone: "+15550000002"})
	addUser(t, db, &model.User{Owner: "admin", Name: "super", Phone: "+15550000003", SignupApplication: "hanzo-cloud"})
	addUser(t, db, &model.User{Owner: "eve", Name: "eve", SignupApplication: "hanzo-cloud"})

	for _, c := range []struct{ org, phone string }{
		{"hanzo", "+15550000001"},
		{"hanzo", "+15550000002"},
		{"hanzo", "+15550000003"},
		{"hanzo", ""},
		{"hanzo", " - "},
		{"", "+15550000001"},
	} {
		got, err := store.GetSignupByPhone(context.Background(), db, c.org, c.phone)
		if err != nil {
			t.Fatalf("GetSignupByPhone(%q, %q): %v", c.org, c.phone, err)
		}
		if got != nil {
			t.Fatalf("GetSignupByPhone(%q, %q) resolved %s/%s", c.org, c.phone, got.Owner, got.Name)
		}
	}
}

// Two of one org's registrations carrying one number name nobody.
func TestGetSignupByPhoneRefusesAnAmbiguousNumber(t *testing.T) {
	db := userDB(t)
	addApp(t, db, "hanzo-ai", "hanzo")
	addApp(t, db, "hanzo-cloud", "hanzo")
	addUser(t, db, &model.User{Owner: "ada", Name: "ada", Phone: "+14155550134", SignupApplication: "hanzo-ai"})
	addUser(t, db, &model.User{Owner: "grace", Name: "grace", Phone: "+14155550134", SignupApplication: "hanzo-cloud"})

	got, err := store.GetSignupByPhone(context.Background(), db, "hanzo", "+14155550134")
	if !errors.Is(err, store.ErrPhoneAmbiguous) {
		t.Fatalf("err = %v, want ErrPhoneAmbiguous", err)
	}
	if got != nil {
		t.Fatalf("a user was returned for an ambiguous number: %s", got.Name)
	}
}
