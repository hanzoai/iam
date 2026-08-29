// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package teams serves the IAM v2 CRUD surface for the `teams` entity: a named
// set of people, owner-scoped by (owner, name). Every operation is a typed zip
// handler over hanzoai/orm; the orm string key is "owner/name". Reads scope to
// one owner (organization); writes address one team by its (owner, name) key.
//
// Where a team has privilege is a Membership, not a field here: the same team
// holds different roles in an org, a workspace and a project.
package teams

import (
	"context"
	"errors"
	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/principal"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

// Handler binds the teams operations to one orm store.
type Handler struct {
	db orm.DB
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the teams CRUD routes on app against db.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/teams", h.List, zip.WithTags("teams"))
	zip.Post(app, "/v1/iam/teams", h.Create, zip.WithTags("teams"))
	zip.Get(app, "/v1/iam/teams/:name", h.Get, zip.WithTags("teams"))
	zip.Put(app, "/v1/iam/teams/:name", h.Update, zip.WithTags("teams"))
	zip.Delete(app, "/v1/iam/teams/:name", h.Delete, zip.WithTags("teams"))
}

// Ref addresses one team by name. The owner is the caller's organization,
// resolved from the credential — a URL carries what it addresses, and a tenant
// is not something a request may name.
type Ref struct {
	Name string `json:"name"`
}

// Input is the writable projection of a team (the v1 add/update-team body). It
// keeps the HTTP contract clean of the orm.Model bookkeeping fields.
type Input struct {
	// Name addresses the team on update and names it on create; every other
	// field is content and binds from the BODY, never the URL.
	Name         string   `json:"name"`
	CreatedTime  string   `json:"createdTime" url:"-"`
	DisplayName  string   `json:"displayName" url:"-"`
	Description  string   `json:"description" url:"-"`
	Organization string   `json:"organization" url:"-"`
	Parent       string   `json:"parent" url:"-"`
	Users        []string `json:"users" url:"-"`
	IsEnabled    bool     `json:"isEnabled" url:"-"`
}

// ListInput carries nothing: the organization is the caller's, resolved from the
// credential.
type ListInput struct{}

// ListOutput is the owner-scoped page of teams.
type ListOutput struct {
	Teams []*schema.Team `json:"teams"`
	Total int            `json:"total"`
}

// DeleteOutput reports the delete result.
type DeleteOutput struct {
	Deleted bool `json:"deleted"`
}

// key builds the orm string key from the (owner, name) natural key.
// New exposes a team Handler for callers that hold the store directly.
func New(db orm.DB) *Handler { return &Handler{db: db} }

func key(owner, name string) string { return owner + "/" + name }

// principalGuard refuses a member ref outside the team's own organization.
func principalGuard(ctx context.Context, method, owner string, users []string) error {
	return authz.AuthorizeGrant(ctx, method, owner, users, nil, nil)
}

// apply copies the mutable domain fields of an Input onto a team. The identity
// fields (owner, name) and the created stamp are set only on Create, never
// overwritten by an update.
func apply(dst *schema.Team, in *Input) {
	dst.DisplayName = in.DisplayName
	dst.Description = in.Description
	dst.Organization = in.Organization
	dst.Parent = in.Parent
	dst.Users = in.Users
	dst.IsEnabled = in.IsEnabled
}

// List returns your organization's teams, newest first — each a named set of
// people that roles and permissions are granted to.
//
// You see your own organization's teams and no one else's; which organization
// that is comes from your credentials, not from the request.
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	// The owner is resolved by principal.Scope from the authenticated principal,
	// never taken from the input: a tenant reads only its own org, a SuperAdmin
	// reads the owner it asks for. Filtering on in.Owner instead was a confused
	// deputy — the Guard authorizes on the query string, then a typed GET binds
	// NOTHING from it (zip typed.go reads a body only for non-GET), so in.Owner
	// arrived empty on every REST call and the "empty owner lists everything"
	// branch returned every tenant.
	owner, err := principal.Scope(ctx, "")
	if err != nil {
		return nil, err
	}
	q := orm.TypedQuery[schema.Team](h.db)
	if owner != "" {
		q = q.Filter("owner", owner)
	}
	teams, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListOutput{Teams: teams, Total: len(teams)}, nil
}

// Get returns one team: who is in it.
func (h *Handler) Get(ctx context.Context, in *Ref) (*schema.Team, error) {
	owner, err := principal.Scope(ctx, "")
	if err != nil {
		return nil, err
	}
	if owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("a name is required")
	}
	team, err := orm.Get[schema.Team](h.db, key(owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	return team, nil
}

// Create makes a team — a named set of people that roles and permissions grant
// to. Granting to a team rather than to each person keeps access correct as
// people come and go: add someone and they inherit what the team can do. A name
// already used in your organization is refused.
func (h *Handler) Create(ctx context.Context, in *Input) (*schema.Team, error) {
	owner, err := principal.Scope(ctx, "")
	if err != nil {
		return nil, err
	}
	if owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("a name is required")
	}
	// A team may only name people of its own organization: the refs are the
	// caller's input and carry no tenancy of their own.
	if err := principalGuard(ctx, "POST", owner, in.Users); err != nil {
		return nil, err
	}
	switch _, err := orm.Get[schema.Team](h.db, key(owner, in.Name)); {
	case err == nil:
		return nil, zip.ErrConflict("team already exists")
	case !errors.Is(err, orm.ErrNotFound):
		return nil, zip.ErrInternal(err.Error())
	}

	team := orm.New[schema.Team](h.db)
	team.Owner = owner
	team.Name = in.Name
	team.CreatedTime = in.CreatedTime
	if team.CreatedTime == "" {
		team.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	apply(team, in)
	team.SetId(key(owner, in.Name))

	if err := team.CreateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return team, nil
}

// Update changes who is in a team. Access changes for
// everyone in it as soon as the write lands. The name and the created stamp do
// not change.
func (h *Handler) Update(ctx context.Context, in *Input) (*schema.Team, error) {
	owner, err := principal.Scope(ctx, "")
	if err != nil {
		return nil, err
	}
	if owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("a name is required")
	}
	// A team may only name people of its own organization: the refs are the
	// caller's input and carry no tenancy of their own.
	if err := principalGuard(ctx, "PUT", owner, in.Users); err != nil {
		return nil, err
	}
	team, err := orm.Get[schema.Team](h.db, key(owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	apply(team, in)
	if err := team.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return team, nil
}

// Delete removes a team. Everyone in it loses the access it carried; their
// accounts, and any other team they are in, are untouched.
func (h *Handler) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	owner, err := principal.Scope(ctx, "")
	if err != nil {
		return nil, err
	}
	if owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("a name is required")
	}
	team, err := orm.Get[schema.Team](h.db, key(owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	if err := team.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// mapErr translates an orm lookup error into the matching HTTP status.
func mapErr(err error) error {
	if errors.Is(err, orm.ErrNotFound) {
		return zip.ErrNotFound("team not found")
	}
	return zip.ErrInternal(err.Error())
}
