// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package permission

// The permission CRUD surface, driven at the handler seam: every handler is a
// plain func(ctx, *In) (*Out, error) over a real embedded-sqlite store, so the
// tests call them directly the way the router does. Nothing is mocked — the
// store the handlers write is the store the assertions read back.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// newHandlers opens a fresh embedded store and returns the handlers bound to it
// alongside the raw handle, so a test that wants to observe a store fault can
// close it out from under the handlers.
func newHandlers(t *testing.T) (*Handlers, orm.DB) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Handlers{db: db}, db
}

// mustAdd seeds one permission through the real Add path, as an admin of the org
// the grant is filed in — the only caller shape the guarded route admits, and the
// one whose subjects the write authorizes.
func mustAdd(t *testing.T, h *Handlers, p *schema.Permission) *schema.Permission {
	t.Helper()
	out, err := h.Add(asAdmin(p.Owner), p)
	if err != nil {
		t.Fatalf("seed %s/%s: %v", p.Owner, p.Name, err)
	}
	return out
}

// wantStatus asserts err is a *zip.HTTPError carrying the given HTTP status.
func wantStatus(t *testing.T, err error, code int) {
	t.Helper()
	if err == nil {
		t.Fatalf("want *zip.HTTPError with status %d, got nil error", code)
	}
	var he *zip.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("want *zip.HTTPError, got %T: %v", err, err)
	}
	if he.Status != code {
		t.Fatalf("status = %d (%q), want %d", he.Status, he.Msg, code)
	}
}

func TestPermissionID(t *testing.T) {
	for _, tc := range []struct {
		owner, name, want string
	}{
		{"hanzo", "editor", "hanzo/editor"},
		{"", "", "/"},
		{"a", "", "a/"},
	} {
		if got := permissionID(tc.owner, tc.name); got != tc.want {
			t.Errorf("permissionID(%q,%q) = %q, want %q", tc.owner, tc.name, got, tc.want)
		}
	}
}

// Identity is the (owner, name) key. Every handler refuses a request that omits
// either half before it touches the store — that guard is the first line of all
// five.
func TestMissingKeyIsBadRequest(t *testing.T) {
	h, _ := newHandlers(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"List/no-owner", func() error { _, err := h.List(ctx, &ListRequest{}); return err }},
		{"Get/no-owner", func() error { _, err := h.Get(ctx, &Ref{Name: "x"}); return err }},
		{"Get/no-name", func() error { _, err := h.Get(ctx, &Ref{Owner: "hanzo"}); return err }},
		{"Add/no-owner", func() error { _, err := h.Add(ctx, &schema.Permission{Name: "x"}); return err }},
		{"Add/no-name", func() error { _, err := h.Add(ctx, &schema.Permission{Owner: "hanzo"}); return err }},
		{"Update/no-owner", func() error { _, err := h.Update(ctx, &schema.Permission{Name: "x"}); return err }},
		{"Update/no-name", func() error { _, err := h.Update(ctx, &schema.Permission{Owner: "hanzo"}); return err }},
		{"Delete/no-owner", func() error { _, err := h.Delete(ctx, &Ref{Name: "x"}); return err }},
		{"Delete/no-name", func() error { _, err := h.Delete(ctx, &Ref{Owner: "hanzo"}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantStatus(t, tc.call(), 400)
		})
	}
}

// Add creates the grant, stamps its id, and Get reads back exactly what was
// written.
func TestAddThenGet(t *testing.T) {
	h, _ := newHandlers(t)
	ctx := context.Background()

	in := &schema.Permission{
		Owner: "hanzo", Name: "editor",
		DisplayName: "Editors", Effect: "allow",
		Users: []string{"hanzo/alice"}, Actions: []string{"read", "write"},
	}
	out := mustAdd(t, h, in)
	if out.Id() != "hanzo/editor" {
		t.Fatalf("Add id = %q, want hanzo/editor", out.Id())
	}
	if out.CreatedAt.IsZero() {
		t.Fatal("Add did not stamp CreatedAt")
	}

	got, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "editor"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.DisplayName != "Editors" || got.Effect != "allow" {
		t.Errorf("Get returned %+v, want DisplayName=Editors Effect=allow", got)
	}
	if len(got.Actions) != 2 || got.Actions[0] != "read" || got.Actions[1] != "write" {
		t.Errorf("Get actions = %v, want [read write]", got.Actions)
	}
	if len(got.Users) != 1 || got.Users[0] != "hanzo/alice" {
		t.Errorf("Get users = %v, want [hanzo/alice]", got.Users)
	}
}

// Adding refuses to overwrite a grant that already exists — widening is an
// update, never an accident.
func TestAddRejectsDuplicate(t *testing.T) {
	h, _ := newHandlers(t)
	ctx := context.Background()
	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "editor"})
	_, err := h.Add(ctx, &schema.Permission{Owner: "hanzo", Name: "editor"})
	wantStatus(t, err, 409)
}

func TestGetMissingIsNotFound(t *testing.T) {
	h, _ := newHandlers(t)
	_, err := h.Get(context.Background(), &Ref{Owner: "hanzo", Name: "ghost"})
	wantStatus(t, err, 404)
}

func TestUpdateMissingIsNotFound(t *testing.T) {
	h, _ := newHandlers(t)
	_, err := h.Update(context.Background(), &schema.Permission{Owner: "hanzo", Name: "ghost"})
	wantStatus(t, err, 404)
}

func TestDeleteMissingIsNotFound(t *testing.T) {
	h, _ := newHandlers(t)
	_, err := h.Delete(context.Background(), &Ref{Owner: "hanzo", Name: "ghost"})
	wantStatus(t, err, 404)
}

// Update changes what the grant allows and lands immediately, but the instant it
// was created does not move.
func TestUpdateChangesFieldsPreservesCreatedAt(t *testing.T) {
	h, _ := newHandlers(t)
	ctx := context.Background()

	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "editor", Effect: "allow"})
	afterAdd, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "editor"})
	if err != nil {
		t.Fatalf("Get after add: %v", err)
	}

	updated, err := h.Update(ctx, &schema.Permission{
		Owner: "hanzo", Name: "editor",
		Effect: "deny", Actions: []string{"read"},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if !updated.CreatedAt.Equal(afterAdd.CreatedAt) {
		t.Errorf("Update CreatedAt = %v, want preserved %v", updated.CreatedAt, afterAdd.CreatedAt)
	}

	got, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "editor"})
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	if got.Effect != "deny" {
		t.Errorf("Effect = %q, want deny (the change did not land)", got.Effect)
	}
	if len(got.Actions) != 1 || got.Actions[0] != "read" {
		t.Errorf("Actions = %v, want [read]", got.Actions)
	}
	if !got.CreatedAt.Equal(afterAdd.CreatedAt) {
		t.Errorf("persisted CreatedAt = %v, want %v", got.CreatedAt, afterAdd.CreatedAt)
	}
}

// Delete revokes the grant; the row is gone and a second delete finds nothing.
func TestDeleteRemoves(t *testing.T) {
	h, _ := newHandlers(t)
	ctx := context.Background()
	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "editor"})

	out, err := h.Delete(ctx, &Ref{Owner: "hanzo", Name: "editor"})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if !out.Deleted {
		t.Fatal("Delete reported Deleted=false")
	}
	if _, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "editor"}); err == nil {
		t.Fatal("permission still readable after delete")
	}
	_, err = h.Delete(ctx, &Ref{Owner: "hanzo", Name: "editor"})
	wantStatus(t, err, 404)
}

// List is owner-scoped and newest first, ordered by the CreatedTime the caller
// stamped — a grant in another organization never appears.
func TestListScopesToOwnerNewestFirst(t *testing.T) {
	h, _ := newHandlers(t)

	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "a", CreatedTime: "2026-01-01T00:00:00Z"})
	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "b", CreatedTime: "2026-03-01T00:00:00Z"})
	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "c", CreatedTime: "2026-02-01T00:00:00Z"})
	mustAdd(t, h, &schema.Permission{Owner: "zoo", Name: "z", CreatedTime: "2026-09-01T00:00:00Z"})

	out, err := h.List(asTenant("hanzo"), &ListRequest{Owner: "hanzo"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var names []string
	for _, p := range out.Permissions {
		if p.Owner != "hanzo" {
			t.Fatalf("List leaked a %q grant across the owner scope", p.Owner)
		}
		names = append(names, p.Name)
	}
	want := []string{"b", "c", "a"}
	if len(names) != len(want) {
		t.Fatalf("List returned %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("List order = %v, want %v (newest CreatedTime first)", names, want)
		}
	}
}

func TestListEmptyOwnerHasNoRows(t *testing.T) {
	h, _ := newHandlers(t)
	out, err := h.List(asTenant("nobody"), &ListRequest{Owner: "nobody"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out.Permissions) != 0 {
		t.Errorf("List returned %d rows for an empty owner, want 0", len(out.Permissions))
	}
}

// A store fault (here: the handle closed under the handler) surfaces as a 500,
// not as a nil result or a swallowed error.
func TestStoreFaultIsInternal(t *testing.T) {
	h, db := newHandlers(t)
	// A principal, because List scopes by the caller before it reaches the store —
	// without one the refusal would be the scope's 403 and the store fault this
	// case exists to observe would never be reached.
	ctx := asTenant("hanzo")
	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "editor"})
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"List", func() error { _, err := h.List(ctx, &ListRequest{Owner: "hanzo"}); return err }},
		{"Get", func() error { _, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "editor"}); return err }},
		{"Add", func() error { _, err := h.Add(ctx, &schema.Permission{Owner: "hanzo", Name: "new"}); return err }},
		{"Update", func() error { _, err := h.Update(ctx, &schema.Permission{Owner: "hanzo", Name: "editor"}); return err }},
		{"Delete", func() error { _, err := h.Delete(ctx, &Ref{Owner: "hanzo", Name: "editor"}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantStatus(t, tc.call(), 500)
		})
	}
}

// writeFailDB is a store whose reads pass through to a real backend but whose
// writes always fail — the shape of a store that goes bad after the handler has
// already read the row it means to change.
type writeFailDB struct{ orm.DB }

var errWrite = errors.New("write path down")

func (writeFailDB) Put(context.Context, orm.Key, interface{}) (orm.Key, error) {
	return nil, errWrite
}
func (writeFailDB) Delete(context.Context, orm.Key) error { return errWrite }

// A write that fails after a clean read surfaces as a 500 on every mutating
// verb: Add's create, Update's write-back, and Delete's removal.
func TestWriteFaultIsInternal(t *testing.T) {
	h, db := newHandlers(t)
	ctx := context.Background()
	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "editor"})

	hf := &Handlers{db: writeFailDB{DB: db}}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Add", func() error { _, err := hf.Add(ctx, &schema.Permission{Owner: "hanzo", Name: "fresh"}); return err }},
		{"Update", func() error { _, err := hf.Update(ctx, &schema.Permission{Owner: "hanzo", Name: "editor"}); return err }},
		{"Delete", func() error { _, err := hf.Delete(ctx, &Ref{Owner: "hanzo", Name: "editor"}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wantStatus(t, tc.call(), 500)
		})
	}
}

// Route wires all five verbs onto the app without a registration clash.
func TestRouteBuilds(t *testing.T) {
	_, db := newHandlers(t)
	app := zip.New(zip.Config{AppName: "permission-test", DisableStartupMessage: true})
	Route(app, db)
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
}
