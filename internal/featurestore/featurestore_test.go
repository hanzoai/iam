// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package featurestore

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/hanzoai/iam/feature"
	"github.com/hanzoai/iam/pkg/model"
	"github.com/hanzoai/iam/pkg/store"
)

func openFeatureStore(t *testing.T) feature.Store {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db)
}

// The seam's user id is the stable opaque subject: AddUser mints it server-side,
// and the id a module reads back MUST be the one GetUserByID resolves. A module
// hands that id to a client as the user's handle and gets it back on the next
// request, so a mismatch here means every lookup by id misses.
func TestAddUserThenGetUserByID(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)

	in := &model.User{Owner: "acme", Name: "alice", Email: "alice@acme.example"}
	ok, err := s.AddUser(ctx, in)
	if err != nil || !ok {
		t.Fatalf("AddUser = %v, %v", ok, err)
	}
	// AddUser takes the user by value: the caller's struct is never stamped, so the
	// id is learned by re-reading the row.
	if in.Id != "" {
		t.Fatalf("AddUser stamped the caller's struct with %q; callers must re-read", in.Id)
	}

	row, err := s.GetUser(ctx, "acme", "alice")
	if err != nil || row == nil {
		t.Fatalf("GetUser = %v, %v", row, err)
	}
	if _, err := uuid.Parse(row.Id); err != nil {
		t.Fatalf("assigned id %q is not the opaque UUID subject: %v", row.Id, err)
	}
	if strings.Contains(row.Id, "/") {
		t.Fatalf("id %q carries a slash; unusable as a /Users/{id} path segment", row.Id)
	}

	got, err := s.GetUserByID(ctx, row.Id)
	if err != nil {
		t.Fatalf("GetUserByID(%q): %v", row.Id, err)
	}
	if got == nil {
		t.Fatalf("GetUserByID(%q) found nothing — the id AddUser assigned does not resolve", row.Id)
	}
	if got.Owner != "acme" || got.Name != "alice" {
		t.Fatalf("GetUserByID resolved %s/%s, want acme/alice", got.Owner, got.Name)
	}
}

// The id survives an update unchanged, so a module's stored resource id stays
// valid: UpdateUser carries Id (and CreatedTime) forward and ignores a body value.
func TestUpdateUserPreservesTheSubject(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)

	if _, err := s.AddUser(ctx, &model.User{Owner: "acme", Name: "bob"}); err != nil {
		t.Fatalf("AddUser: %v", err)
	}
	before, _ := s.GetUser(ctx, "acme", "bob")
	if before == nil {
		t.Fatal("GetUser after AddUser: nil")
	}

	// A body that tries to move the subject must be ignored.
	edit := *before
	edit.Id = uuid.NewString()
	edit.DisplayName = "Bob"
	if _, err := s.UpdateUser(ctx, &edit); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}

	after, _ := s.GetUser(ctx, "acme", "bob")
	if after == nil {
		t.Fatal("GetUser after UpdateUser: nil")
	}
	if after.Id != before.Id {
		t.Fatalf("update moved the subject: %q -> %q", before.Id, after.Id)
	}
	if after.DisplayName != "Bob" {
		t.Fatalf("DisplayName = %q, want Bob", after.DisplayName)
	}
	if got, err := s.GetUserByID(ctx, before.Id); err != nil || got == nil {
		t.Fatalf("GetUserByID after update = %v, %v; the original id must still resolve", got, err)
	}
}

// An unmatched id is (nil, nil), not an error — callers turn it into a 404.
func TestGetUserByIDUnknown(t *testing.T) {
	ctx := context.Background()
	s := openFeatureStore(t)
	got, err := s.GetUserByID(ctx, uuid.NewString())
	if err != nil {
		t.Fatalf("GetUserByID(unknown) errored: %v", err)
	}
	if got != nil {
		t.Fatalf("GetUserByID(unknown) = %v, want nil", got)
	}
}
