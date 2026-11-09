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
	"time"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/principal"

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
func Route(app *zip.Group, db orm.DB) {
	h := &Handler{db: db}
	app.Get("/v1/iam/teams", h.List, zip.WithTags("teams"))
	app.Post("/v1/iam/teams", h.Create, zip.WithTags("teams"))
	app.Get("/v1/iam/teams/:name", h.Get, zip.WithTags("teams"))
	app.Put("/v1/iam/teams/:name", h.Update, zip.WithTags("teams"))
	app.Delete("/v1/iam/teams/:name", h.Delete, zip.WithTags("teams"))
}

// Ref addresses one team by name. The owner is the caller's organization,
// resolved from the credential, unless the request names one: principal.Scope
// honours an org the caller may act in and refuses any other, so naming one never
// reaches a tenant the credential could not.
type Ref struct {
	// Owner is the organization the team belongs to: yours when left out.
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// AuthzScope is the team a delete addresses, resolved as authz.Authorize resolves
// it, so the org the seam authorized is the org the handler deletes from.
func (in *Ref) AuthzScope(ctx context.Context) (owner, name string, err error) {
	owner, err = principal.Scope(ctx, in.Owner)
	return owner, in.Name, err
}

// Input is the writable projection of a team (the v1 add/update-team body). It
// keeps the HTTP contract clean of the orm.Model bookkeeping fields.
type Input struct {
	// Owner is the organization the team belongs to. Leave it out and it is
	// yours, from your credentials; name another only if you administer it.
	Owner string `json:"owner"`
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

// AuthzScope is the team a create or update addresses, resolved as authz.Authorize
// resolves it, so the org the seam authorized is the org the handler writes.
func (in *Input) AuthzScope(ctx context.Context) (owner, name string, err error) {
	owner, err = principal.Scope(ctx, in.Owner)
	return owner, in.Name, err
}

// ListInput scopes a listing to one organization, the caller's when it names none.
type ListInput struct {
	// Owner is the organization whose teams to list: yours when left out.
	Owner string `json:"owner"`
}

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
// Name no organization and it is yours, from your credentials. Name one you
// belong to and you see its teams; any other is refused.
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	// The owner is resolved by principal.ScopeRead, never taken from the input
	// unchecked: in.Owner is what the CALLER wrote in the query, and ScopeRead
	// honours it only for an org the caller belongs to (a SuperAdmin, any org;
	// naming none, the caller's own). The Guard does not pre-authorize this read
	// (authz.handlerAuthorizedExact), because belonging opens it, which is wider
	// than the Guard's tenant rule — the clause the workspace list asks.
	owner, err := principal.ScopeRead(ctx, in.Owner)
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
	// The Guard and the op seam leave a team read to the handler (the item's org
	// is in no path), so this is its whole authorization: the list's clause, one
	// team at a time.
	owner, err := principal.ScopeRead(ctx, in.Owner)
	if err != nil {
		return nil, err
	}
	if err := required(owner, in.Name); err != nil {
		return nil, err
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
	owner, _, err := in.AuthzScope(ctx)
	if err != nil {
		return nil, err
	}
	if err := required(owner, in.Name); err != nil {
		return nil, err
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
	owner, _, err := in.AuthzScope(ctx)
	if err != nil {
		return nil, err
	}
	if err := required(owner, in.Name); err != nil {
		return nil, err
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
	owner, _, err := in.AuthzScope(ctx)
	if err != nil {
		return nil, err
	}
	if err := required(owner, in.Name); err != nil {
		return nil, err
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

// required refuses a team address missing either half of its (owner, name) key.
// The owner is empty only for a SuperAdmin naming no org: it has none of its own
// to file a team under, so it names one rather than writing somewhere unintended.
func required(owner, name string) error {
	if owner == "" {
		return zip.ErrBadRequest("an owner is required: name the organization the team belongs to")
	}
	if name == "" {
		return zip.ErrBadRequest("a name is required")
	}
	return nil
}

// mapErr translates an orm lookup error into the matching HTTP status.
func mapErr(err error) error {
	if errors.Is(err, orm.ErrNotFound) {
		return zip.ErrNotFound("team not found")
	}
	return zip.ErrInternal(err.Error())
}
