// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package projects

// The projects CRUD surface driven at the handler seam: Get, Create, Update and
// Delete are plain func(ctx, *In) (*Out, error) over a real embedded-sqlite store,
// so the tests call them directly the way the router does. List is the one op that
// authorizes on the query rather than a decoded body — it rides principal.ScopeRead
// behind the Guard — so its store-fault arm is pinned through the registered router
// in list_fault_test.go; every op that authorizes on its own value is pinned here.
// Nothing is mocked but the two deliberate faults — a handle closed under the
// handler, and a write path that fails after a clean read — each the shape of a
// store that goes bad mid-operation, which must surface as a 500 and not a swallowed
// error.

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

// newHandler opens a fresh embedded store and returns the handler bound to it
// alongside the raw handle, so a test that wants to observe a store fault can close
// it out from under the handler.
func newHandler(t *testing.T) (*Handler, orm.DB) {
	t.Helper()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &Handler{db: db}, db
}

// mustCreate seeds one project through the real Create path and returns it.
func mustCreate(t *testing.T, h *Handler, owner, name string) *schema.Project {
	t.Helper()
	out, err := h.Create(context.Background(), &Input{Owner: owner, Name: name, Organization: owner})
	if err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
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

// TestKeyIsRequired: every op that names its target refuses a blank owner or name
// with 400 before it touches the store.
func TestKeyIsRequired(t *testing.T) {
	h, _ := newHandler(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Get/no-owner", func() error { _, err := h.Get(ctx, &Ref{Name: "x"}); return err }},
		{"Get/no-name", func() error { _, err := h.Get(ctx, &Ref{Owner: "hanzo"}); return err }},
		{"Create/no-owner", func() error { _, err := h.Create(ctx, &Input{Name: "x"}); return err }},
		{"Create/no-name", func() error { _, err := h.Create(ctx, &Input{Owner: "hanzo"}); return err }},
		{"Update/no-owner", func() error { _, err := h.Update(ctx, &Input{Name: "x"}); return err }},
		{"Update/no-name", func() error { _, err := h.Update(ctx, &Input{Owner: "hanzo"}); return err }},
		{"Delete/no-owner", func() error { _, err := h.Delete(ctx, &Ref{Name: "x"}); return err }},
		{"Delete/no-name", func() error { _, err := h.Delete(ctx, &Ref{Owner: "hanzo"}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) { wantStatus(t, tc.call(), 400) })
	}
}

// TestCreateRejectsDuplicate: a second Create on a live (owner,name) is a 409.
func TestCreateRejectsDuplicate(t *testing.T) {
	h, _ := newHandler(t)
	mustCreate(t, h, "hanzo", "alpha")
	_, err := h.Create(context.Background(), &Input{Owner: "hanzo", Name: "alpha", Organization: "hanzo"})
	wantStatus(t, err, 409)
}

// TestMissingTargetIsNotFound: Get/Update/Delete on an absent (owner,name) map the
// orm miss to 404 — not a 500, and not a silent empty result.
func TestMissingTargetIsNotFound(t *testing.T) {
	h, _ := newHandler(t)
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Get", func() error { _, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "ghost"}); return err }},
		{"Update", func() error { _, err := h.Update(ctx, &Input{Owner: "hanzo", Name: "ghost"}); return err }},
		{"Delete", func() error { _, err := h.Delete(ctx, &Ref{Owner: "hanzo", Name: "ghost"}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) { wantStatus(t, tc.call(), 404) })
	}
}

// TestGetReadsBackWhatCreateWrote: the created row round-trips by its (owner,name)
// key, and an Update rewrites the mutable fields while identity and the created
// stamp hold.
func TestGetReadsBackWhatCreateWrote(t *testing.T) {
	h, _ := newHandler(t)
	ctx := context.Background()
	created := mustCreate(t, h, "hanzo", "alpha")

	got, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "alpha"})
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Owner != "hanzo" || got.Name != "alpha" {
		t.Fatalf("read the wrong key: %+v", got)
	}

	up, err := h.Update(ctx, &Input{Owner: "hanzo", Name: "alpha", Organization: "hanzo", DisplayName: "Alpha II"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if up.DisplayName != "Alpha II" {
		t.Fatalf("update did not take: %+v", up)
	}
	if up.CreatedTime != created.CreatedTime {
		t.Fatalf("update moved the created stamp: %q -> %q", created.CreatedTime, up.CreatedTime)
	}
}

// TestCreateDefaultsOrganizationToOwner: an add that names no organization is filed
// under its owner — the org a project belongs to defaults to the org that owns it.
func TestCreateDefaultsOrganizationToOwner(t *testing.T) {
	h, _ := newHandler(t)
	out, err := h.Create(context.Background(), &Input{Owner: "hanzo", Name: "beta"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if out.Organization != "hanzo" {
		t.Fatalf("organization = %q, want %q (defaulted to owner)", out.Organization, "hanzo")
	}
}

// TestStoreFaultIsInternal: a store fault (here the handle closed under the handler)
// surfaces as a 500 on every verb whose first act is a read — including the two
// non-NotFound orm errors that Create's existence probe and mapErr must forward
// rather than mistake for "already exists" or "not found".
func TestStoreFaultIsInternal(t *testing.T) {
	h, db := newHandler(t)
	ctx := context.Background()
	mustCreate(t, h, "hanzo", "alpha")
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Get", func() error { _, err := h.Get(ctx, &Ref{Owner: "hanzo", Name: "alpha"}); return err }},
		{"Create", func() error {
			_, err := h.Create(ctx, &Input{Owner: "hanzo", Name: "gamma", Organization: "hanzo"})
			return err
		}},
		{"Update", func() error {
			_, err := h.Update(ctx, &Input{Owner: "hanzo", Name: "alpha", Organization: "hanzo"})
			return err
		}},
		{"Delete", func() error { _, err := h.Delete(ctx, &Ref{Owner: "hanzo", Name: "alpha"}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) { wantStatus(t, tc.call(), 500) })
	}
}

// writeFailDB is a store whose reads pass through to a real backend but whose writes
// always fail — the shape of a store that goes bad after the handler has already
// read the row it means to change.
type writeFailDB struct{ orm.DB }

var errWrite = errors.New("write path down")

func (writeFailDB) Put(context.Context, orm.Key, interface{}) (orm.Key, error) {
	return nil, errWrite
}
func (writeFailDB) Delete(context.Context, orm.Key) error { return errWrite }

// TestWriteFaultIsInternal: a write that fails after a clean read surfaces as a 500
// on Create's insert, Update's write-back and Delete's removal.
func TestWriteFaultIsInternal(t *testing.T) {
	h, db := newHandler(t)
	ctx := context.Background()
	mustCreate(t, h, "hanzo", "alpha")

	hf := &Handler{db: writeFailDB{DB: db}}
	for _, tc := range []struct {
		name string
		call func() error
	}{
		{"Create", func() error {
			_, err := hf.Create(ctx, &Input{Owner: "hanzo", Name: "fresh", Organization: "hanzo"})
			return err
		}},
		{"Update", func() error {
			_, err := hf.Update(ctx, &Input{Owner: "hanzo", Name: "alpha", Organization: "hanzo"})
			return err
		}},
		{"Delete", func() error { _, err := hf.Delete(ctx, &Ref{Owner: "hanzo", Name: "alpha"}); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) { wantStatus(t, tc.call(), 500) })
	}
}
