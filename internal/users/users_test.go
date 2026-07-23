// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package users

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/google/uuid"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// A user minted natively in v2 gets a stable opaque UUID `sub` on create, so its
// identity is never the mutable (owner,name) pair. A caller-supplied Id is honored
// (the migrator relies on writing it directly), but the common path generates one.

func TestCreate_GeneratesUUIDSubject(t *testing.T) {
	ctx := context.Background()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam2.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	defer db.Close()

	api := New(db)
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
	got, err := store.GetUserBySubject(ctx, db, out.Id)
	if err != nil || got == nil {
		t.Fatalf("GetUserBySubject(generated id) = %v, %v; want the created user", got, err)
	}
	if got.Owner != "hanzo" || got.Name != "newbie" {
		t.Errorf("resolved %s/%s, want hanzo/newbie", got.Owner, got.Name)
	}

	// A caller-supplied Id is preserved (the migration write path).
	pinned, err := api.Create(ctx, &CreateInput{
		User:     schema.User{Id: "uuid-pinned-0001", Owner: "hanzo", Name: "migrated"},
		Password: "pw",
	})
	if err != nil {
		t.Fatalf("create pinned: %v", err)
	}
	if pinned.Id != "uuid-pinned-0001" {
		t.Errorf("pinned Id = %q, want uuid-pinned-0001 (a supplied Id is kept)", pinned.Id)
	}
}
