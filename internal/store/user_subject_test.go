// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// The subject→user decoder is the ONE place `sub` is resolved. A UUID subject (no
// "/") resolves by the domain Id; an owner/name subject resolves by the natural
// key. The persisted "id" is the domain UUID, yet the storage PK stays (owner,name)
// — a round-trip must preserve both.

func openStoreTestDB(t *testing.T) orm.DB {
	t.Helper()
	db, err := Open("sqlite", filepath.Join(t.TempDir(), "iam2.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func seedRow(t *testing.T, db orm.DB, id, owner, name string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Id = id
	u.Owner, u.Name = owner, name
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

func TestGetUserBySubject_ResolvesUUIDAndNaturalKey(t *testing.T) {
	ctx := context.Background()
	db := openStoreTestDB(t)
	const uuid = "e7d7fda0-4c53-4508-9d35-7ec892b7e5d7"
	seedRow(t, db, uuid, "hanzo", "z")     // migrated: carries a UUID
	seedRow(t, db, "", "hanzo", "legacy")  // pre-cutover: no Id

	// A UUID subject resolves by Id.
	u, err := GetUserBySubject(ctx, db, uuid)
	if err != nil || u == nil {
		t.Fatalf("GetUserBySubject(uuid) = %v, %v; want the row", u, err)
	}
	if u.Owner != "hanzo" || u.Name != "z" {
		t.Errorf("resolved %s/%s, want hanzo/z", u.Owner, u.Name)
	}
	// The storage PK stayed (owner,name) despite the domain "id" being the UUID.
	if got := u.Model.Id(); got != "hanzo/z" {
		t.Errorf("storage key = %q, want hanzo/z (the natural key, not the UUID)", got)
	}

	// GetUserById is the direct UUID lookup.
	if byId, _ := GetUserById(ctx, db, uuid); byId == nil || byId.Name != "z" {
		t.Errorf("GetUserById(uuid) did not resolve the migrated user")
	}

	// An owner/name subject resolves by the natural key.
	leg, err := GetUserBySubject(ctx, db, "hanzo/legacy")
	if err != nil || leg == nil || leg.Name != "legacy" {
		t.Fatalf("GetUserBySubject(owner/name) = %v, %v; want the legacy row", leg, err)
	}

	// A UUID that no row carries, an empty subject, and a machine-token app id all
	// resolve to no user (callers fail closed).
	if got, _ := GetUserBySubject(ctx, db, "00000000-0000-0000-0000-000000000000"); got != nil {
		t.Errorf("unknown UUID resolved to %v, want nil", got)
	}
	if got, _ := GetUserBySubject(ctx, db, ""); got != nil {
		t.Errorf("empty subject resolved to %v, want nil", got)
	}
	if got, _ := GetUserBySubject(ctx, db, "admin/some-app"); got != nil {
		t.Errorf("machine-token app subject resolved to %v, want nil", got)
	}
}
