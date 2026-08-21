// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package workspaces serves the IAM v2 CRUD surface for the `workspaces` entity:
// an organization-scoped container that sits between the organization and its
// projects (Organization → Workspace → Project), owner-scoped by (owner, name),
// where Owner is the owning organization. Every operation is a typed zip handler
// over hanzoai/orm; the orm string key is "owner/name". Reads scope to one owner
// (organization); writes address one workspace by its (owner, name) key. This is
// the ONE workspace CRUD path — the the legacy surface get-organization-workspaces /
// add-workspace / delete-workspace verb aliases (internal/compat) reuse it via
// New.
package workspaces

import (
	"context"
	"errors"
	"github.com/hanzoai/iam/internal/authz"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// Handler binds the workspaces operations to one orm store.
type Handler struct {
	db orm.DB
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the workspaces CRUD routes on app against db.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/workspaces", h.List, zip.WithTags("workspaces"))
	zip.Post(app, "/v1/iam/workspaces", h.Create, zip.WithTags("workspaces"))
	zip.Get(app, "/v1/iam/workspaces/get", h.Get, zip.WithTags("workspaces"))
	zip.Post(app, "/v1/iam/workspaces/update", h.Update, zip.WithTags("workspaces"))
	zip.Post(app, "/v1/iam/workspaces/delete", h.Delete, zip.WithTags("workspaces"))
}

// New exposes a workspace Handler so the the legacy surface add-/delete-workspace verb
// aliases (internal/compat) reuse the ONE workspace CRUD path, wrapped in the
// compat envelope.
func New(db orm.DB) *Handler { return &Handler{db: db} }

// Ref addresses one workspace by its owner-scoped natural key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Input is the writable projection of a workspace (the add/update-workspace body).
// It keeps the HTTP contract clean of the orm.Model bookkeeping fields.
type Input struct {
	Owner        string   `json:"owner"`
	Name         string   `json:"name"`
	CreatedTime  string   `json:"createdTime"`
	DisplayName  string   `json:"displayName"`
	Description  string   `json:"description"`
	Organization string   `json:"organization"`
	Bucket       string   `json:"bucket"`
	Tags         []string `json:"tags"`
	Metadata     string   `json:"metadata"`
	IsDefault    bool     `json:"isDefault"`
}

// ListInput scopes a listing to one owner (organization).
type ListInput struct {
	Owner string `json:"owner"`
}

// ListOutput is the owner-scoped page of workspaces.
type ListOutput struct {
	Workspaces []*schema.Workspace `json:"workspaces"`
	Total      int                 `json:"total"`
}

// DeleteOutput reports the delete result.
type DeleteOutput struct {
	Deleted bool `json:"deleted"`
}

func key(owner, name string) string { return owner + "/" + name }

// apply copies the mutable domain fields of an Input onto a workspace. The
// identity fields (owner, name) and the created stamp are set only on Create,
// never overwritten by an update.
func apply(dst *schema.Workspace, in *Input) {
	dst.DisplayName = in.DisplayName
	dst.Description = in.Description
	dst.Organization = pick(in.Organization, in.Owner)
	dst.Bucket = in.Bucket
	dst.Tags = in.Tags
	dst.Metadata = in.Metadata
	dst.IsDefault = in.IsDefault
}

// List returns your organization's workspaces, newest first — the scope a
// team works in, alongside projects rather than instead of them.
//
// You see your own organization's workspaces and no one else's; which organization that
// is comes from your credentials, not from the request.
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	// The owner is resolved by authz.ScopeRead from the authenticated principal,
	// never taken from the input: a person reads any org they BELONG to, a
	// SuperAdmin reads the owner it asks for. ScopeRead rather than Scope because
	// this is a listing and a human's account lives in ONE tenant while the orgs
	// they work in are a set — keying it on p.Org alone refused an org's own admin
	// the org they administer, which is the switcher that lists an org and then
	// will not open it. Filtering on in.Owner instead was a confused
	// deputy — the Guard authorizes on the query string, then a typed GET binds
	// NOTHING from it (zip typed.go reads a body only for non-GET), so in.Owner
	// arrived empty on every REST call and the "empty owner lists everything"
	// branch returned every tenant.
	owner, err := authz.ScopeRead(ctx, in.Owner)
	if err != nil {
		return nil, err
	}
	q := orm.TypedQuery[schema.Workspace](h.db)
	if owner != "" {
		q = q.Filter("owner", owner)
	}
	rows, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListOutput{Workspaces: rows, Total: len(rows)}, nil
}

// Get returns one workspace: what it is called and how it is set up.
func (h *Handler) Get(ctx context.Context, in *Ref) (*schema.Workspace, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	w, err := orm.Get[schema.Workspace](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	return w, nil
}

// Create makes a workspace inside your organization — the scope a team works in,
// alongside projects rather than instead of them. A name already used in the
// organization is refused.
func (h *Handler) Create(ctx context.Context, in *Input) (*schema.Workspace, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	switch _, err := orm.Get[schema.Workspace](h.db, key(in.Owner, in.Name)); {
	case err == nil:
		return nil, zip.ErrConflict("workspace already exists")
	case !errors.Is(err, orm.ErrNotFound):
		return nil, zip.ErrInternal(err.Error())
	}

	w := orm.New[schema.Workspace](h.db)
	w.Owner = in.Owner
	w.Name = in.Name
	w.CreatedTime = in.CreatedTime
	if w.CreatedTime == "" {
		w.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	apply(w, in)
	w.SetId(key(in.Owner, in.Name))

	if err := w.CreateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return w, nil
}

// Update changes a workspace's settings. What it is called does not change, and
// neither does when it was created.
func (h *Handler) Update(ctx context.Context, in *Input) (*schema.Workspace, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	w, err := orm.Get[schema.Workspace](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	apply(w, in)
	if err := w.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return w, nil
}

// Delete removes a workspace. The people and roles in your organization are
// unchanged; what goes is the scope itself.
func (h *Handler) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	w, err := orm.Get[schema.Workspace](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	if err := w.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// mapErr translates an orm lookup error into the matching HTTP status.
func mapErr(err error) error {
	if errors.Is(err, orm.ErrNotFound) {
		return zip.ErrNotFound("workspace not found")
	}
	return zip.ErrInternal(err.Error())
}

// pick returns a if non-empty, else b.
func pick(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
