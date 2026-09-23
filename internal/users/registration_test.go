// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

// SignupApplication says which application REGISTERED an account, and sign-in,
// signup and federation read it as authority: an account an application
// registered is found by that application's org wherever the account now works.
// So it is stated by the code that registered the account — signup, federation,
// the wallet — and never by a body. An org admin who could write it onto a row in
// their own org could plant a stranger's address as an account some application
// registered, and the stranger's own sign-up would then be refused as taken.

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// A create body cannot name the registering application.
func TestCreate_BodyCannotStateTheRegistration(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	created, err := api.Create(ctx, &CreateInput{
		User: schema.User{
			Owner: "evil", Name: "plant", Email: "victim@corp.com",
			SignupApplication: "hanzo-cloud", // the body claims hanzo-cloud registered it
		},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.SignupApplication != "" {
		t.Fatalf("a request named the registering application and the row believed it: %q", created.SignupApplication)
	}
	stored, err := api.lookup(ctx, "evil", "plant")
	if err != nil || stored == nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.SignupApplication != "" {
		t.Fatalf("the stored row carries the body's registration: %q", stored.SignupApplication)
	}
}

// An update body cannot name it either, and an ordinary edit keeps the one the
// registering code stated.
func TestUpdate_CarriesTheRegistration(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	if _, err := api.Create(ctx, &CreateInput{
		User: schema.User{Owner: "evil", Name: "member", Email: "member@evil.test"},
	}); err != nil {
		t.Fatalf("create unregistered: %v", err)
	}
	got, err := api.Update(ctx, &UpdateInput{
		Owner: "evil", Name: "member",
		User: schema.User{Owner: "evil", Name: "member", Email: "member@evil.test", SignupApplication: "hanzo-cloud"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.SignupApplication != "" {
		t.Fatalf("an update body named the registering application: %q", got.SignupApplication)
	}

	if _, err := api.Create(ctx, &CreateInput{
		User:        schema.User{Owner: "ada", Name: "ada", Email: "ada@example.com"},
		Application: "hanzo-cloud",
	}); err != nil {
		t.Fatalf("create registered: %v", err)
	}
	got, err = api.Update(ctx, &UpdateInput{
		Owner: "ada", Name: "ada",
		User: schema.User{Owner: "ada", Name: "ada", Email: "ada@example.com", DisplayName: "Ada"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.SignupApplication != "hanzo-cloud" {
		t.Fatalf("an ordinary edit dropped the registration: %q", got.SignupApplication)
	}
}

// The positive control: the registering code states it beside the create, and it
// is read back.
func TestRegistrationIsStatedByTheCallingCode(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	created, err := api.Create(ctx, &CreateInput{
		User:        schema.User{Owner: "hanzo", Name: "bob", Email: "bob@example.com"},
		Type:        "normal-user",
		Application: "hanzo-cloud",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.SignupApplication != "hanzo-cloud" {
		t.Fatalf("signup could not record the application that registered the account: %q", created.SignupApplication)
	}
}
