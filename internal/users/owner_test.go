// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// An account's owner is the org it lives in, and that org is the first entry of
// every token minted from it — the value platform authority is decided on. So the
// owner a create writes is held to the shape every organization is created with
// (schema.OrgName): lowercase, nothing to fold. Measured live on 2026-10-19: no
// person could found an org spelled "Admin", but a SuperAdmin's POST
// /v1/iam/users with owner "Admin" was STORED, an account in an org that does not
// exist whose tokens a case-folding consumer read as SuperAdmin.
func TestCreate_RefusesAnOwnerThatIsNotAnOrgName(t *testing.T) {
	for _, owner := range []string{"Admin", "ADMIN", "aDmin", "Hanzo", "acme_x", "a", "ac/me", "admin\u200b"} {
		t.Run(owner, func(t *testing.T) {
			ctx := context.Background()
			api, closeDB := openUsersTestDB(t)
			defer closeDB()
			if out, err := api.Create(ctx, &CreateInput{User: schema.User{Owner: owner, Name: "alice"}}); err == nil {
				t.Fatalf("Create in owner %q stored %s/%s; want refusal", owner, out.Owner, out.Name)
			}
			if u, _ := store.GetUserByName(ctx, api.db, owner, "alice"); u != nil {
				t.Fatalf("an account exists in %q after the refusal", owner)
			}
		})
	}
	for _, owner := range []string{"admin", "built-in", "hanzo", "acme-1", "z24"} {
		t.Run(owner, func(t *testing.T) {
			api, closeDB := openUsersTestDB(t)
			defer closeDB()
			if _, err := api.Create(context.Background(), &CreateInput{User: schema.User{Owner: owner, Name: "alice"}}); err != nil {
				t.Fatalf("Create in owner %q: %v", owner, err)
			}
		})
	}
}
