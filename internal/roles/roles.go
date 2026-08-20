// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package roles serves the IAM v2 CRUD surface for the `roles` entity: a named
// grant bundle owner-scoped by (owner, name). Every operation is a typed zip
// handler over hanzoai/orm; the orm string key is "owner/name". Reads scope to
// one owner (organization); writes address one role by its (owner, name) key.
package roles

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
)

// Handler binds the roles operations to one orm store.
type Handler struct {
	db orm.DB
}

// Route registers the roles CRUD routes on app against db.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/roles", h.List, zip.WithSummary("List roles for an owner"), zip.WithTags("roles"))
	zip.Post(app, "/v1/iam/roles", h.Create, zip.WithSummary("Create a role"), zip.WithTags("roles"))
	zip.Post(app, "/v1/iam/roles/get", h.Get, zip.WithSummary("Get one role"), zip.WithTags("roles"))
	zip.Post(app, "/v1/iam/roles/update", h.Update, zip.WithSummary("Update a role"), zip.WithTags("roles"))
	zip.Post(app, "/v1/iam/roles/delete", h.Delete, zip.WithSummary("Delete a role"), zip.WithTags("roles"))
}

// Ref addresses one role by its owner-scoped natural key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Input is the writable projection of a role (the v1 add/update-role body). It
// keeps the wire contract clean of the orm.Model bookkeeping fields.
type Input struct {
	Owner       string   `json:"owner"`
	Name        string   `json:"name"`
	CreatedTime string   `json:"createdTime"`
	DisplayName string   `json:"displayName"`
	Description string   `json:"description"`
	Users       []string `json:"users"`
	Groups      []string `json:"groups"`
	Roles       []string `json:"roles"`
	Domains     []string `json:"domains"`
	IsEnabled   bool     `json:"isEnabled"`
}

// ListInput scopes a listing to one owner (organization).
type ListInput struct {
	Owner string `json:"owner"`
}

// ListOutput is the owner-scoped page of roles.
type ListOutput struct {
	Roles []*schema.Role `json:"roles"`
	Total int            `json:"total"`
}

// DeleteOutput reports the delete result.
type DeleteOutput struct {
	Deleted bool `json:"deleted"`
}

// key builds the orm string key from the (owner, name) natural key.
// New exposes a role Handler so the Casdoor add-/update-/delete-role verb aliases
// (internal/compat) reuse the ONE role CRUD path, wrapped in the compat envelope.
func New(db orm.DB) *Handler { return &Handler{db: db} }

func key(owner, name string) string { return owner + "/" + name }

// apply copies the mutable domain fields of an Input onto a role. The identity
// fields (owner, name) and the created stamp are set only on Create, never
// overwritten by an update.
func apply(dst *schema.Role, in *Input) {
	dst.DisplayName = in.DisplayName
	dst.Description = in.Description
	dst.Users = in.Users
	dst.Groups = in.Groups
	dst.Roles = in.Roles
	dst.Domains = in.Domains
	dst.IsEnabled = in.IsEnabled
}

// List returns the roles for one owner, newest first. An empty owner lists
// every role (the unscoped admin view).
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	q := orm.TypedQuery[schema.Role](h.db)
	if in.Owner != "" {
		q = q.Filter("owner", in.Owner)
	}
	roles, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListOutput{Roles: roles, Total: len(roles)}, nil
}

// Get returns one role addressed by (owner, name).
func (h *Handler) Get(ctx context.Context, in *Ref) (*schema.Role, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	role, err := orm.Get[schema.Role](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	return role, nil
}

// Create persists a new role. It rejects a duplicate (owner, name).
func (h *Handler) Create(ctx context.Context, in *Input) (*schema.Role, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	switch _, err := orm.Get[schema.Role](h.db, key(in.Owner, in.Name)); {
	case err == nil:
		return nil, zip.ErrConflict("role already exists")
	case !errors.Is(err, orm.ErrNotFound):
		return nil, zip.ErrInternal(err.Error())
	}

	role := orm.New[schema.Role](h.db)
	role.Owner = in.Owner
	role.Name = in.Name
	role.CreatedTime = in.CreatedTime
	if role.CreatedTime == "" {
		role.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	apply(role, in)
	role.SetId(key(in.Owner, in.Name))

	if err := role.CreateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return role, nil
}

// Update mutates an existing role's grant set. Identity and created stamp are
// immutable; a missing role is a 404.
func (h *Handler) Update(ctx context.Context, in *Input) (*schema.Role, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	role, err := orm.Get[schema.Role](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	apply(role, in)
	if err := role.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return role, nil
}

// Delete removes one role addressed by (owner, name).
func (h *Handler) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	role, err := orm.Get[schema.Role](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	if err := role.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// mapErr translates an orm lookup error into the matching HTTP status.
func mapErr(err error) error {
	if errors.Is(err, orm.ErrNotFound) {
		return zip.ErrNotFound("role not found")
	}
	return zip.ErrInternal(err.Error())
}
