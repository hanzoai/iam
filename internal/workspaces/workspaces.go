// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package workspaces serves the IAM v2 CRUD surface for the `workspaces` entity:
// an organization-scoped container that sits between the organization and its
// projects (Organization → Workspace → Project), owner-scoped by (owner, name),
// where Owner is the owning organization. Every operation is a typed zip handler
// over hanzoai/orm; the orm string key is "owner/name". Reads scope to one owner
// (organization); writes address one workspace by its (owner, name) key. This is
// the ONE workspace CRUD path — the Casdoor get-organization-workspaces /
// add-workspace / delete-workspace verb aliases (internal/compat) reuse it via
// New.
package workspaces

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
)

// Handler binds the workspaces operations to one orm store.
type Handler struct {
	db orm.DB
}

// Route registers the workspaces CRUD routes on app against db.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/workspaces", h.List, zip.WithSummary("List workspaces for an owner"), zip.WithTags("workspaces"))
	zip.Post(app, "/v1/iam/workspaces", h.Create, zip.WithSummary("Create a workspace"), zip.WithTags("workspaces"))
	zip.Post(app, "/v1/iam/workspaces/get", h.Get, zip.WithSummary("Get one workspace"), zip.WithTags("workspaces"))
	zip.Post(app, "/v1/iam/workspaces/update", h.Update, zip.WithSummary("Update a workspace"), zip.WithTags("workspaces"))
	zip.Post(app, "/v1/iam/workspaces/delete", h.Delete, zip.WithSummary("Delete a workspace"), zip.WithTags("workspaces"))
}

// New exposes a workspace Handler so the Casdoor add-/delete-workspace verb
// aliases (internal/compat) reuse the ONE workspace CRUD path, wrapped in the
// compat envelope.
func New(db orm.DB) *Handler { return &Handler{db: db} }

// Ref addresses one workspace by its owner-scoped natural key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Input is the writable projection of a workspace (the add/update-workspace body).
// It keeps the wire contract clean of the orm.Model bookkeeping fields.
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

// List returns the workspaces for one owner, newest first. An empty owner lists
// every workspace (the unscoped admin view).
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	q := orm.TypedQuery[schema.Workspace](h.db)
	if in.Owner != "" {
		q = q.Filter("owner", in.Owner)
	}
	rows, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListOutput{Workspaces: rows, Total: len(rows)}, nil
}

// Get returns one workspace addressed by (owner, name).
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

// Create persists a new workspace. It rejects a duplicate (owner, name).
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

// Update mutates an existing workspace. Identity and created stamp are immutable;
// a missing workspace is a 404.
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

// Delete removes one workspace addressed by (owner, name).
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
