// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package store is the IN-PROCESS entity store surface for a host binary that
// EMBEDS iam (hanzoai/cloud) rather than talking to it over HTTP. It exposes the
// ONE project CRUD path (internal/projects) and the read-only user ROSTER
// (users.go) as plain functions over an explicit orm.DB — there is NO
// package-global engine in v2, so the db a host opened with server.OpenSQLite
// (or bound from its own orm.DB) is passed on every call.
//
// The functions reproduce the exact orm calls internal/projects uses (the ONE
// query path — Filter/Order/GetAll for reads, orm.New+CreateCtx for a write,
// orm.Get+DeleteCtx for a delete) and preserve the "owner/name" id semantics, so
// an embedder reads and writes the SAME `projects` rows the registered /v1/iam/projects
// HTTP surface serves — one store, no drift. Reads return the shared model.Project
// (an alias of the core schema.Project), so the host never clones a project struct.
//
// Not-found convention differs from the HTTP handler on purpose: an embedder
// pre-checks existence (Get→nil means "create is safe"), so GetProject returns
// (nil, nil) for a missing project — the same convention the retired iam-v1 object
// store used, which is what the host's pre-check logic expects.
package store

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/model"
)

// key is the orm string key for a project: "owner/name".
func key(owner, name string) string { return owner + "/" + name }

// GetProjects lists the projects owned by owner, newest first. An empty owner
// lists EVERY project — the unscoped admin (all-orgs) view, matching the registered
// /v1/iam/projects listing an empty owner serves.
func GetProjects(db orm.DB, owner string) ([]*model.Project, error) {
	return listByOwner(db, owner)
}

// GetOrganizationProjects lists the projects of one organization. Owner IS the
// owning organization in v2 (schema.Project doc), so this is the owner-scoped
// listing — the org-scoped reflection a tenant sees.
func GetOrganizationProjects(db orm.DB, org string) ([]*model.Project, error) {
	return listByOwner(db, org)
}

// listByOwner is the ONE list path both public readers share. It reproduces the
// internal projects List query verbatim: filter by owner (skipped when empty →
// all owners), ordered by newest createdTime.
func listByOwner(db orm.DB, owner string) ([]*model.Project, error) {
	q := orm.TypedQuery[model.Project](db)
	if owner != "" {
		q = q.Filter("owner", owner)
	}
	return q.Order("-createdTime").GetAll(context.Background())
}

// GetProject returns one project addressed by its "owner/name" id, or (nil, nil)
// when it does not exist (the embedder pre-check convention). Any other orm error
// is returned as-is.
func GetProject(db orm.DB, id string) (*model.Project, error) {
	p, err := orm.Get[model.Project](db, id)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// AddProject persists a new project from the caller-built value, reproducing the
// internal Create: a fresh orm-bound record (so defaults + db binding are applied),
// the mutable domain fields copied over, Organization defaulted to Owner, the
// created stamp filled if absent, and the "owner/name" id set. Returns true when
// the row was written. The caller pre-checks existence, so a duplicate surfaces as
// the orm insert error rather than being silently coalesced.
func AddProject(db orm.DB, in *model.Project) (bool, error) {
	if in == nil || in.Owner == "" || in.Name == "" {
		return false, errors.New("iam store: project owner and name are required")
	}
	p := orm.New[model.Project](db)
	p.Owner = in.Owner
	p.Name = in.Name
	p.CreatedTime = in.CreatedTime
	if p.CreatedTime == "" {
		p.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	p.DisplayName = in.DisplayName
	p.Description = in.Description
	p.Organization = in.Organization
	if p.Organization == "" {
		p.Organization = in.Owner
	}
	p.Workspace = in.Workspace
	p.Tags = in.Tags
	p.Metadata = in.Metadata
	p.IsDefault = in.IsDefault
	p.SetId(key(in.Owner, in.Name))
	if err := p.CreateCtx(context.Background()); err != nil {
		return false, err
	}
	return true, nil
}

// DeleteProject removes the project keyed by (Owner, Name) on the passed value.
// A missing project is not an error — it reports (false, nil), matching the
// affected-rows semantics the embedder expects; a real orm error is returned.
func DeleteProject(db orm.DB, in *model.Project) (bool, error) {
	if in == nil || in.Owner == "" || in.Name == "" {
		return false, errors.New("iam store: project owner and name are required")
	}
	p, err := orm.Get[model.Project](db, key(in.Owner, in.Name))
	if errors.Is(err, orm.ErrNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if err := p.DeleteCtx(context.Background()); err != nil {
		return false, err
	}
	return true, nil
}
