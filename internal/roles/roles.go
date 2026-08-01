// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package roles serves the IAM v2 CRUD surface for the `roles` entity: a named
// grant bundle owner-scoped by (owner, name). Every operation is a typed zip
// handler over hanzoai/orm; the orm string key is "owner/name". Reads scope to
// one owner (organization); writes address one role by its (owner, name) key.
package roles

import (
	"context"
	"errors"
	"github.com/hanzoai/iam/internal/authz"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
)

// Handler binds the roles operations to one orm store.
type Handler struct {
	db orm.DB
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the roles CRUD routes on app against db.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/roles", h.List, zip.WithTags("roles"))
	zip.Post(app, "/v1/iam/roles", h.Create, zip.WithTags("roles"))
	zip.Post(app, "/v1/iam/roles/get", h.Get, zip.WithTags("roles"))
	zip.Post(app, "/v1/iam/roles/update", h.Update, zip.WithTags("roles"))
	zip.Post(app, "/v1/iam/roles/delete", h.Delete, zip.WithTags("roles"))
}

// Ref addresses one role by its owner-scoped natural key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Input is the writable projection of a role (the v1 add/update-role body). It
// keeps the HTTP contract clean of the orm.Model bookkeeping fields.
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
// New exposes a role Handler so the the legacy surface add-/update-/delete-role verb aliases
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

// List returns your organization's roles, newest first — each a named group of
// people that permissions are granted to.
//
// You see your own organization's roles and no one else's; which organization
// that is comes from your credentials, not from the request.
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	// The owner is resolved by authz.Scope from the authenticated principal,
	// never taken from the input: a tenant reads only its own org, a SuperAdmin
	// reads the owner it asks for. Filtering on in.Owner instead was a confused
	// deputy — the Guard authorizes on the query string, then a typed GET binds
	// NOTHING from it (zip typed.go reads a body only for non-GET), so in.Owner
	// arrived empty on every REST call and the "empty owner lists everything"
	// branch returned every tenant.
	owner, err := authz.Scope(ctx, in.Owner)
	if err != nil {
		return nil, err
	}
	q := orm.TypedQuery[schema.Role](h.db)
	if owner != "" {
		q = q.Filter("owner", owner)
	}
	roles, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListOutput{Roles: roles, Total: len(roles)}, nil
}

// Get returns one role: who is in it, and the roles it includes.
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

// Create makes a role — a named group of people that permissions are granted to.
// Granting to a role rather than to each person is what keeps access correct as
// your team changes: add someone to the role and they inherit everything it can
// do. A name already used in your organization is refused.
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

// Update changes who is in a role, or which roles it includes. Access changes for
// everyone in it as soon as the write lands. What the role is called does not
// change, and neither does when it was created.
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

// Delete removes a role. Everyone in it loses the access it carried; their
// accounts, and any other role they hold, are untouched.
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
