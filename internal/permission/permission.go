// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package permission serves the IAM v2 permission CRUD surface as typed zip
// handlers over hanzoai/orm. Every permission is owner-scoped: its identity is
// the (owner, name) pair, stored under the orm key "owner/name". Reads are
// GET, writes are POST; the DB is captured on the handler receiver so each
// handler keeps the plain TypedHandler shape func(ctx, *In) (*Out, error).
package permission

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
)

// Handlers holds the storage handle shared by every permission handler.
type Handlers struct {
	db orm.DB
}

// Mount registers the permission routes on app, backed by db. It is called
// from routes.Mount once the store is open.
func Mount(app *zip.App, db orm.DB) {
	h := &Handlers{db: db}
	zip.Get(app, "/v1/iam/v2/permissions", h.List,
		zip.WithSummary("List permissions for an owner"), zip.WithTags("permissions"))
	zip.Post(app, "/v1/iam/v2/permissions", h.Add,
		zip.WithSummary("Create a permission"), zip.WithTags("permissions"))
	zip.Get(app, "/v1/iam/v2/permissions/get", h.Get,
		zip.WithSummary("Get one permission by owner and name"), zip.WithTags("permissions"))
	zip.Post(app, "/v1/iam/v2/permissions/update", h.Update,
		zip.WithSummary("Update a permission"), zip.WithTags("permissions"))
	zip.Post(app, "/v1/iam/v2/permissions/delete", h.Delete,
		zip.WithSummary("Delete a permission"), zip.WithTags("permissions"))
}

// permissionID is the owner-scoped orm key: "owner/name".
func permissionID(owner, name string) string { return owner + "/" + name }

// ListRequest scopes a list to one owner (organization).
type ListRequest struct {
	Owner string `json:"owner"`
}

// ListResponse is the owner's permissions, newest first.
type ListResponse struct {
	Permissions []*schema.Permission `json:"permissions"`
}

// Ref identifies a single permission by its (owner, name) key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// DeleteResponse reports the outcome of a delete.
type DeleteResponse struct {
	Deleted bool `json:"deleted"`
}

// List returns every permission owned by in.Owner, ordered newest first,
// mirroring v1 GetPermissions (Desc created_time).
func (h *Handlers) List(ctx context.Context, in *ListRequest) (*ListResponse, error) {
	if in.Owner == "" {
		return nil, zip.ErrBadRequest("owner is required")
	}
	items, err := orm.TypedQuery[schema.Permission](h.db).
		Filter("Owner=", in.Owner).
		Order("-CreatedTime").
		GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListResponse{Permissions: items}, nil
}

// Get returns one permission by its (owner, name) key.
func (h *Handlers) Get(ctx context.Context, in *Ref) (*schema.Permission, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	p, err := orm.Get[schema.Permission](h.db, permissionID(in.Owner, in.Name))
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("permission not found")
		}
		return nil, zip.ErrInternal(err.Error())
	}
	return p, nil
}

// Add creates a permission under the (owner, name) key. It refuses to
// overwrite an existing grant — updates go through Update.
func (h *Handlers) Add(ctx context.Context, in *schema.Permission) (*schema.Permission, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	id := permissionID(in.Owner, in.Name)
	if _, err := orm.Get[schema.Permission](h.db, id); err == nil {
		return nil, zip.ErrConflict("permission already exists")
	} else if !errors.Is(err, orm.ErrNotFound) {
		return nil, zip.ErrInternal(err.Error())
	}
	in.Init(h.db)
	in.SetId(id)
	if err := in.CreateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return in, nil
}

// Update replaces the mutable state of an existing permission, preserving its
// key and creation time (v1 AllCols update semantics).
func (h *Handlers) Update(ctx context.Context, in *schema.Permission) (*schema.Permission, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	existing, err := orm.Get[schema.Permission](h.db, permissionID(in.Owner, in.Name))
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("permission not found")
		}
		return nil, zip.ErrInternal(err.Error())
	}
	in.Init(h.db)
	in.SetKey(existing.Key())
	in.CreatedAt = existing.CreatedAt
	if err := in.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return in, nil
}

// Delete removes a permission by its (owner, name) key.
func (h *Handlers) Delete(ctx context.Context, in *Ref) (*DeleteResponse, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	existing, err := orm.Get[schema.Permission](h.db, permissionID(in.Owner, in.Name))
	if err != nil {
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("permission not found")
		}
		return nil, zip.ErrInternal(err.Error())
	}
	if err := existing.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteResponse{Deleted: true}, nil
}
