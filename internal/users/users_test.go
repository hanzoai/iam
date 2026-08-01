// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package users

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A user minted natively in v2 gets a stable opaque UUID `sub` on create, ALWAYS
// server-side. Id is the token subject AND the authz principal key, so it must be
// non-forgeable: a client-supplied Id is discarded on create, and Id is immutable
// on update. Otherwise an org-admin could pin their Id to a victim's UUID and, once
// two rows shared it, be resolved AS the victim (F-A1: tenant-admin → SuperAdmin).

func openUsersTestDB(t *testing.T) (*API, func()) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	return New(db), func() { db.Close() }
}

func TestCreate_GeneratesUUIDSubject(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	out, err := api.Create(ctx, &CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "newbie", Email: "newbie@hanzo.ai"},
		Password: "correct horse battery staple",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.Id == "" {
		t.Fatal("Create did not assign a subject Id")
	}
	if _, err := uuid.Parse(out.Id); err != nil {
		t.Errorf("assigned Id %q is not a UUID: %v", out.Id, err)
	}
	// The generated Id persisted and resolves as the subject.
	got, err := store.GetUserBySubject(ctx, api.db, out.Id)
	if err != nil || got == nil {
		t.Fatalf("GetUserBySubject(generated id) = %v, %v; want the created user", got, err)
	}
	if got.Owner != "hanzo" || got.Name != "newbie" {
		t.Errorf("resolved %s/%s, want hanzo/newbie", got.Owner, got.Name)
	}
}

// F-A1 #1: a client-supplied Id is IGNORED on create — the server always mints a
// fresh UUID, so a caller can never point a new row at a chosen (victim's) subject.
func TestCreate_IgnoresClientSuppliedId(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	// Victim carries a known UUID (a public OIDC identifier).
	const victimSub = "e7d7fda0-4c53-4508-9d35-7ec892b7e5d7"
	if _, err := api.Create(ctx, &CreateInput{
		User: schema.User{Id: victimSub, Owner: "hanzo", Name: "victim"}, Password: "pw1",
	}); err != nil {
		t.Fatalf("seed victim: %v", err)
	}
	// The victim's OWN generated Id must NOT be the value it tried to pin.
	victim, _ := store.GetUserByName(ctx, api.db, "hanzo", "victim")
	if victim.Id == victimSub {
		t.Fatal("client-supplied Id was honored on create — must be discarded")
	}

	// An attacker in another tenant tries to pin the victim's (real) UUID.
	attacker, err := api.Create(ctx, &CreateInput{
		User: schema.User{Id: victim.Id, Owner: "zoo", Name: "eve"}, Password: "pw2",
	})
	if err != nil {
		t.Fatalf("create attacker: %v", err)
	}
	if attacker.Id == victim.Id {
		t.Fatal("F-A1: attacker create adopted the victim's Id — sub collision")
	}
	// The subject still resolves to exactly ONE, correct user (fail-closed read intact).
	got, err := store.GetUserBySubject(ctx, api.db, victim.Id)
	if err != nil || got == nil || got.Name != "victim" {
		t.Fatalf("GetUserBySubject(victim) = %v, %v; want the sole victim row", got, err)
	}
}

// F-A1 #2 / F-A2: Id is immutable on update — a body-supplied Id is ignored, and an
// update that omits Id preserves the existing subject (never wipes it to "").
func TestUpdate_IdIsImmutable(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	created, err := api.Create(ctx, &CreateInput{
		User: schema.User{Owner: "zoo", Name: "eve", Email: "eve@zoo.ai"}, Password: "pw",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	original := created.Id

	// Attempt to move Id to a victim's UUID.
	moved, err := api.Update(ctx, &UpdateInput{
		User: schema.User{Id: "victim-uuid-9999", Owner: "zoo", Name: "eve", DisplayName: "Eve"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if moved.Id != original {
		t.Fatalf("F-A1: Update changed Id %q -> %q; must be immutable", original, moved.Id)
	}

	// F-A2: an update that OMITS id must preserve the existing subject, not erase it.
	edited, err := api.Update(ctx, &UpdateInput{
		User: schema.User{Owner: "zoo", Name: "eve", DisplayName: "Eve Edited"},
	})
	if err != nil {
		t.Fatalf("update (no id): %v", err)
	}
	if edited.Id != original {
		t.Fatalf("F-A2: benign edit erased the subject: Id = %q, want %q", edited.Id, original)
	}
	if edited.DisplayName != "Eve Edited" {
		t.Errorf("profile edit not applied: %q", edited.DisplayName)
	}
}

// A user's credential is not a profile field. hk- resolves a user by exact match on
// AccessKey (store.UserByAccessKey), so a body that carries one plants a credential
// the sender already knows and can then present AS that user. It is also what would
// let a retired prefix be re-introduced at will, which makes any census of the legacy
// population meaningless. Minting is the only writer.
func TestUsers_CredentialIsNotAProfileField(t *testing.T) {
	ctx := context.Background()
	api, closeDB := openUsersTestDB(t)
	defer closeDB()

	made, err := api.Create(ctx, &CreateInput{
		User: schema.User{Owner: "hanzo", Name: "ada", Email: "ada@hanzo.ai",
			AccessKey: "hk-live-planted-at-create"},
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if made.AccessKey != "" {
		t.Fatalf("create persisted a caller-supplied credential: %q", made.AccessKey)
	}

	// Give the row a credential the way the system actually does, then try to
	// overwrite it through the profile write.
	made.AccessKey = "sk-live-minted-legitimately"
	if err := made.UpdateCtx(ctx); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	got, err := api.Update(ctx, &UpdateInput{
		User: schema.User{Owner: "hanzo", Name: "ada", Email: "ada@hanzo.ai",
			DisplayName: "Ada L", AccessKey: "hk-live-planted-by-admin"},
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if got.AccessKey != "sk-live-minted-legitimately" {
		t.Fatalf("update overwrote the credential with a caller-supplied value: %q", got.AccessKey)
	}
	if got.DisplayName != "Ada L" {
		t.Fatalf("update failed to apply a legitimately mutable field: %q", got.DisplayName)
	}
}
