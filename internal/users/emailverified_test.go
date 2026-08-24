// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

// EmailVerified is a proof the SERVER recorded. The federation broker asks it
// before linking a social identity onto an existing local account: it adopts a row
// only when that row's own address was proven, or when the row carries no password
// anybody could already sign in with. A body that could state it would answer that
// question for the broker — a row carrying a chosen password AND a stated proof
// passes a check that exists to say no.
//
// So the bit is not settable from the body on EITHER write, and on both it is
// stated by the calling code instead: Create takes CreateInput.EmailVerified,
// which the federation broker sets and nothing else does; Update carries the
// stored value. internal/oidc/federation_proof_test.go runs the whole chain.

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
)

// A create body cannot state the proof. This is the half a request reaches:
// the sender writes the row, so a settable bit lets the sender both choose the
// password on an account and declare its address proven.
func TestCreate_BodyCannotStateTheProof(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	created, err := api.Create(ctx, &CreateInput{
		User: schema.User{
			Owner: "hanzo", Name: "trap", Email: "victim@corp.com",
			EmailVerified: true, // the body says the address was proven
		},
		Password: "the sender's own passphrase",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.EmailVerified {
		t.Fatal("a request stated the address was proven and the row believed it")
	}
	// And the stored row, not just the response.
	stored, err := api.lookup(ctx, "hanzo", "trap")
	if err != nil || stored == nil {
		t.Fatalf("read back: %v", err)
	}
	if stored.EmailVerified {
		t.Fatal("the response hid the bit but the row carries it")
	}
	if stored.PasswordHash == "" {
		t.Fatal("premise: the row must carry the sender's digest")
	}
}

// An update body cannot state it either, and an ordinary edit does not un-prove
// an address the server did prove.
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

// The positive control, and the reason refusing the body is not the same as
// refusing everyone. The federation broker states its provider's proof through
// the create's own field, the bit is READABLE on the way back, and an ordinary
// edit that omits it does not un-prove the address. Without this, "ignore the
// bit" could be satisfied by ignoring it always — which would make every
// federated account unlinkable on its second sign-in.
func TestProofIsStatedByTheCallingCode(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	// This is the shape the federation broker provisions: no password, address
	// proven by the identity provider, stated beside the create.
	proven, err := api.Create(ctx, &CreateInput{
		User:          schema.User{Owner: "hanzo", Name: "bob", Email: "bob@hanzo.ai"},
		Type:          "normal-user",
		EmailVerified: true,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !proven.EmailVerified {
		t.Fatal("a federated provision could not record the proof it has")
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
	if got.DisplayName != "Bob" {
		t.Fatalf("the profile edit was lost: %q", got.DisplayName)
	}
}
