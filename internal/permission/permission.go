// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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

	"github.com/hanzoai/iam/pkg/schema"
)

// Handlers holds the storage handle shared by every permission handler.
type Handlers struct {
	db orm.DB
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the permission routes on app, backed by db. It is called
// from routes.Route once the store is open.
func Route(app *zip.App, db orm.DB) {
	h := &Handlers{db: db}
	zip.Get(app, "/v1/iam/permissions", h.List, zip.WithTags("permissions"))
	zip.Post(app, "/v1/iam/permissions", h.Add, zip.WithTags("permissions"))
	zip.Get(app, "/v1/iam/permissions/get", h.Get, zip.WithTags("permissions"))
	zip.Post(app, "/v1/iam/permissions/update", h.Update, zip.WithTags("permissions"))
	zip.Post(app, "/v1/iam/permissions/delete", h.Delete, zip.WithTags("permissions"))
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

// List returns the permissions in one organization, newest first — each one a
// grant saying which people or roles may do what, and to which resources.
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

// Get returns one permission: who it grants to, what it allows, and the
// resources it covers.
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

// Add grants a permission — the call that gives a person or a role the ability to
// do something. Adding refuses to overwrite a grant that already exists, so
// widening an existing one is an update, never an accident.
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

// Update changes who a permission grants to, what it allows, or the resources it
// covers. Access changes as soon as the write lands. What the permission is
// called does not change, and neither does when it was created.
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

// Delete revokes a permission. Everyone who held access only through it loses
// that access immediately; grants they hold by another route are untouched.
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
