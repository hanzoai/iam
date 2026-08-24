// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package projects serves the IAM v2 CRUD surface for the `projects` entity: an
// organization-scoped work container owner-scoped by (owner, name), where Owner
// is the owning organization. Every operation is a typed zip handler over
// hanzoai/orm; the orm string key is "owner/name". Reads scope to one owner
// (organization); writes address one project by its (owner, name) key.
package projects

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// Handler binds the projects operations to one orm store.
type Handler struct {
	db orm.DB
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the projects CRUD routes on app against db.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/projects", h.List, zip.WithTags("projects"))
	zip.Post(app, "/v1/iam/projects", h.Create, zip.WithTags("projects"))
	zip.Get(app, "/v1/iam/projects/:owner/:name", h.Get, zip.WithTags("projects"))
	zip.Put(app, "/v1/iam/projects/:owner/:name", h.Update, zip.WithTags("projects"))
	zip.Delete(app, "/v1/iam/projects/:owner/:name", h.Delete, zip.WithTags("projects"))
}

// Ref addresses one project by its owner-scoped natural key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Input is the writable projection of a project (the v1 add/update-project body).
// It keeps the HTTP contract clean of the orm.Model bookkeeping fields.
type Input struct {
	Owner        string   `json:"owner"`
	Name         string   `json:"name"`
	CreatedTime  string   `json:"createdTime"`
	DisplayName  string   `json:"displayName"`
	Description  string   `json:"description"`
	Organization string   `json:"organization"`
	Workspace    string   `json:"workspace"`
	Tags         []string `json:"tags"`
	Metadata     string   `json:"metadata"`
	IsDefault    bool     `json:"isDefault"`
}

// ListInput scopes a listing to one owner (organization).
type ListInput struct {
	Owner string `json:"owner"`
}

// ListOutput is the owner-scoped page of projects.
type ListOutput struct {
	Projects []*schema.Project `json:"projects"`
	Total    int               `json:"total"`
}

// DeleteOutput reports the delete result.
type DeleteOutput struct {
	Deleted bool `json:"deleted"`
}

func key(owner, name string) string { return owner + "/" + name }

// apply copies the mutable domain fields of an Input onto a project. The identity
// fields (owner, name) and the created stamp are set only on Create, never
// overwritten by an update.
func apply(dst *schema.Project, in *Input) {
	dst.DisplayName = in.DisplayName
	dst.Description = in.Description
	dst.Organization = pick(in.Organization, in.Owner)
	dst.Workspace = in.Workspace
	dst.Tags = in.Tags
	dst.Metadata = in.Metadata
	dst.IsDefault = in.IsDefault
}

// List returns your organization's projects, newest first — the scope
// people pick between when their work is separated by product or client rather
// than by team.
//
// You see your own organization's projects and no one else's; which organization that
// is comes from your credentials, not from the request.
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	// The owner is resolved from the authenticated principal, never taken from the
	// input: in.Owner is whatever the CALLER wrote in the URL, since zip binds a
	// typed op's scalar fields from the query string on every method. Filtering on
	// it would let a request name the tenant it reads.
	//
	// ScopeRead, not Scope, because BELONGING opens a project list: an operator's
	// account lives in one org while the orgs they work in are a set, and a
	// switcher that lists them has to be able to read them. A stranger is refused
	// exactly as Scope would refuse.
	owner, err := principal.ScopeRead(ctx, in.Owner)
	if err != nil {
		return nil, err
	}
	q := orm.TypedQuery[schema.Project](h.db)
	if owner != "" {
		q = q.Filter("owner", owner)
	}
	rows, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListOutput{Projects: rows, Total: len(rows)}, nil
}

// Get returns one project: what it is called and how it is set up.
func (h *Handler) Get(ctx context.Context, in *Ref) (*schema.Project, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	p, err := orm.Get[schema.Project](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	return p, nil
}

// Create makes a project inside your organization — the scope people pick
// between when their work is separated by product or client rather than by team.
// A name already used in the organization is refused.
func (h *Handler) Create(ctx context.Context, in *Input) (*schema.Project, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	switch _, err := orm.Get[schema.Project](h.db, key(in.Owner, in.Name)); {
	case err == nil:
		return nil, zip.ErrConflict("project already exists")
	case !errors.Is(err, orm.ErrNotFound):
		return nil, zip.ErrInternal(err.Error())
	}

	p := orm.New[schema.Project](h.db)
	p.Owner = in.Owner
	p.Name = in.Name
	p.CreatedTime = in.CreatedTime
	if p.CreatedTime == "" {
		p.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	apply(p, in)
	p.SetId(key(in.Owner, in.Name))

	if err := p.CreateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return p, nil
}

// Update changes a project's settings. What it is called does not change, and
// neither does when it was created.
func (h *Handler) Update(ctx context.Context, in *Input) (*schema.Project, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	p, err := orm.Get[schema.Project](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	apply(p, in)
	if err := p.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return p, nil
}

// Delete removes a project. The people and roles in your organization are
// unchanged; what goes is the scope itself, so move anything addressed by it
// first.
func (h *Handler) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	p, err := orm.Get[schema.Project](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	if err := p.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// mapErr translates an orm lookup error into the matching HTTP status.
func mapErr(err error) error {
	if errors.Is(err, orm.ErrNotFound) {
		return zip.ErrNotFound("project not found")
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
