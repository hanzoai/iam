// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/model"
	"github.com/hanzoai/iam/pkg/store"
	"github.com/hanzoai/iam/server"
)

// userDB is the store both identifier-lookup suites run against.
func userDB(t *testing.T) orm.DB {
	t.Helper()
	sdb, err := server.OpenSQLite(filepath.Join(t.TempDir(), "lookup.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = sdb.Close() })
	return sdb
}

// The number reaches its owner, however the person typed it — the whole point of
// normalizing on both sides of the comparison.
func TestGetUserByPhoneMatchesAnyFormatting(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "hanzo", Name: "ada", Phone: "+14155550134"})

	for _, typed := range []string{"+14155550134", "+1 (415) 555-0134", "+1-415-555-0134"} {
		got, err := store.GetUserByPhone(context.Background(), db, "hanzo", typed)
		if err != nil {
			t.Fatalf("GetUserByPhone(%q): %v", typed, err)
		}
		if got == nil || got.Name != "ada" {
			t.Errorf("GetUserByPhone(%q) = %v, want ada", typed, got)
		}
	}
}

// THE security property. Phone is indexed but NOT unique, so two rows in one org
// can carry one number. Returning either of them would authenticate a person
// against somebody else's account, so the lookup must refuse instead of choose.
func TestGetUserByPhoneRefusesAnAmbiguousNumber(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "hanzo", Name: "ada", Phone: "+14155550134"})
	addUser(t, db, &model.User{Owner: "hanzo", Name: "grace", Phone: "+14155550134"})

	got, err := store.GetUserByPhone(context.Background(), db, "hanzo", "+14155550134")
	if !errors.Is(err, store.ErrPhoneAmbiguous) {
		t.Fatalf("err = %v, want ErrPhoneAmbiguous — a number naming two accounts must name none", err)
	}
	if got != nil {
		t.Fatalf("a user was returned for an ambiguous number: %s", got.Name)
	}
}

// A blank phone must never match the many rows that legitimately store none.
// Without the guard this is an authentication oracle: an empty identifier would
// resolve to an arbitrary account.
func TestGetUserByPhoneIgnoresBlankInput(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "hanzo", Name: "ada"})
	addUser(t, db, &model.User{Owner: "hanzo", Name: "grace"})

	for _, blank := range []string{"", "   ", "+", "()- ."} {
		got, err := store.GetUserByPhone(context.Background(), db, "hanzo", blank)
		if err != nil {
			t.Fatalf("GetUserByPhone(%q): %v", blank, err)
		}
		if got != nil {
			t.Fatalf("blank phone %q resolved to %s — an empty identifier must match nobody", blank, got.Name)
		}
	}
}

// The lookup is org-scoped: one tenant's number never reaches another's account.
func TestGetUserByPhoneIsOrgScoped(t *testing.T) {
	db := userDB(t)
	addUser(t, db, &model.User{Owner: "hanzo", Name: "ada", Phone: "+14155550134"})

	got, err := store.GetUserByPhone(context.Background(), db, "lux", "+14155550134")
	if err != nil {
		t.Fatalf("GetUserByPhone: %v", err)
	}
	if got != nil {
		t.Fatalf("cross-tenant resolve: org lux reached %s", got.Name)
	}
}

// LooksLikePhone must not swallow ordinary usernames, and must not miss the shapes
// people actually type. It is a SHAPE test — whether the number names anyone is the
// lookup's business, not this function's. Sign-in's identifier resolution and the
// verification code's receiver key both ask it, which is why there is one copy.
func TestLooksLikePhone(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{"+14155550134", true},
		{"+1 (415) 555-0134", true},
		{"415-555-0134", true},
		{"4155550134", true},

		// Not phones: a username, an email, and a short numeric handle that a
		// seven-digit floor deliberately keeps out of the phone arm.
		{"zeekay", false},
		{"someone@example.com", false},
		{"12345", false},
		{"", false},
		{"user123456789", false},
		// A "+" is only meaningful leading; mid-string it is not phone punctuation.
		{"415+555+0134", false},
	} {
		if got := store.LooksLikePhone(tc.in); got != tc.want {
			t.Errorf("LooksLikePhone(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
