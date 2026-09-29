// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A profile write links no sign-in to an account: an org admin's update that sets
// a member's federated subject or a raw passkey row lands neither. Federation and
// the WebAuthn ceremony are those columns' only writers.
func TestRedAdminPlantsConnector(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	created, err := api.Create(ctx, &CreateInput{
		User:     schema.User{Owner: "acme", Name: "bob", Email: "bob@acme.example", Phone: "+15550001"},
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("create bob: %v", err)
	}

	admin := principal.Bind(ctx, &principal.Principal{Org: "acme", User: "alice", Admin: true})

	upd := *created.Mask() // exactly what a profile screen reads back and re-posts
	upd.Google = "attacker-google-subject-1234"
	upd.WebauthnCredentials = []json.RawMessage{json.RawMessage(`{"id":"attacker-passkey"}`)}

	if _, err := api.Update(admin, &UpdateInput{Owner: "acme", Name: "bob", User: upd}); err != nil {
		t.Fatalf("admin profile update refused: %v", err)
	}

	stored, _ := store.GetUserByName(ctx, api.db, "acme", "bob")
	if stored.Google == "attacker-google-subject-1234" {
		t.Errorf("CREDENTIAL BYPASS (connector): org admin set bob.Google=%q via profile update; a Google login with that subject lands on bob", stored.Google)
	}
	if len(stored.WebauthnCredentials) == 1 && string(stored.WebauthnCredentials[0]) == `{"id":"attacker-passkey"}` {
		t.Errorf("CREDENTIAL BYPASS (passkey): org admin planted a WebAuthn credential on bob via profile update")
	}
}
