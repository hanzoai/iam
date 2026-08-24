// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

// EmailVerified is a proof the SERVER recorded. The federation broker asks it
// before linking a social identity onto an existing local account: it adopts a row
// only when that row's own address was proven, or when the row carries no password
// anybody could already sign in with. A body that could state it would answer that
// question for the broker — a row carrying a chosen password AND a stated proof
// passes a gate that exists to say no.

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// A request stating the proof does not get it, and an ordinary edit does not
// un-prove an address the server did prove.
func TestUpdate_CarriesEmailVerified(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	unproven, err := api.Create(ctx, &CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "alice", Email: "alice@hanzo.ai"},
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if unproven.EmailVerified {
		t.Fatal("a password signup must not record the address as proven")
	}

	got, err := api.Update(ctx, &UpdateInput{
		Owner: "hanzo", Name: "alice",
		User: schema.User{Owner: "hanzo", Name: "alice", Email: "alice@hanzo.ai", EmailVerified: true},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.EmailVerified {
		t.Fatal("a request stated the address was proven and the row believed it")
	}
}

// The proof a federated sign-in DID record survives an ordinary edit that omits the
// field — a full-row write must not un-prove an address either.
func TestUpdate_KeepsAProvenAddress(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	// This is the shape the federation broker provisions: no password, address
	// proven by the identity provider.
	proven, err := api.Create(ctx, &CreateInput{
		User: schema.User{Owner: "hanzo", Name: "bob", Email: "bob@hanzo.ai", EmailVerified: true},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !proven.EmailVerified {
		t.Fatal("a federated provision must be able to record the proof it has")
	}

	got, err := api.Update(ctx, &UpdateInput{
		Owner: "hanzo", Name: "bob",
		User: schema.User{Owner: "hanzo", Name: "bob", Email: "bob@hanzo.ai", DisplayName: "Bob"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !got.EmailVerified {
		t.Fatal("an ordinary edit un-proved a verified address")
	}
}
