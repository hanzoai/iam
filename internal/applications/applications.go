// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package applications is the Phase-1 typed CRUD surface for the `applications`
// entity. Every operation is a zip typed handler (decode In -> run -> encode
// Out) over hanzoai/orm and is owner-scoped by the (owner, name) natural key,
// materialized as the orm id "<owner>/<name>". The same In/Out types back both
// the REST route and the MCP tools/call projection zip derives from them, so
// identity arguments travel in the typed request, not in ad-hoc path parsing.
package applications

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/schema"
)

// authorizeOrganization gates the Organization an application will SERVE (the
// tenant a credential minted through it lands in), not just its registry Owner:
// the op-invoke authz hook authorizes the top-level Owner, but Organization is a
// separate field that a tenant admin could otherwise set to the reserved admin
// org (a SuperAdmin-minting app) or to a victim tenant. On a gated HTTP request
// the Guard attached a Principal; a non-super may point an app only at its OWN
// org. A server-internal call (bootstrap/seed) carries no Principal and is
// trusted, so an unauthenticated context is left to the surrounding trust
// boundary rather than blocked here.
func authorizeOrganization(ctx context.Context, in *schema.Application) error {
	if in.Organization == "" {
		return nil // an org-less app mints no cross-tenant/SuperAdmin identity
	}
	p, ok := authz.From(ctx)
	if !ok {
		return nil // server-internal (no principal) — trusted caller
	}
	if !authz.CanSetOrg(p, in.Organization) {
		return zip.ErrForbidden("not authorized to set the application organization to " + in.Organization)
	}
	return nil
}

// appID is the owner-scoped natural key "<owner>/<name>" — the single source
// of an application's orm id. Every handler routes through it so reads and
// writes address the exact same row.
func appID(owner, name string) string { return owner + "/" + name }

// ApplicationRef identifies one application by its owner-scoped natural key.
// It is the input for the get and delete operations.
type ApplicationRef struct {
	Owner string `json:"owner" validate:"required"`
	Name  string `json:"name" validate:"required"`
}

// ApplicationQuery filters applications by owner for the list operation.
type ApplicationQuery struct {
	Owner string `json:"owner" validate:"required"`
}

// ApplicationListResult wraps the applications owned by one owner, newest
// first.
type ApplicationListResult struct {
	Applications []*schema.Application `json:"applications"`
}

// DeleteResult reports the outcome of a delete operation.
type DeleteResult struct {
	Deleted bool `json:"deleted"`
}

// Route registers the applications CRUD surface on app, closing over db. Reads
// use GET, create POST, update PUT, delete DELETE — every one a zip typed
// handler.
func Route(app *zip.App, db orm.DB) {
	zip.Get(app, "/v1/iam/applications", listApplications(db),
		zip.WithSummary("List applications for an owner"), zip.WithTags("applications"))
	zip.Get(app, "/v1/iam/application", getApplication(db),
		zip.WithSummary("Get one application by owner and name"), zip.WithTags("applications"))
	zip.Post(app, "/v1/iam/application", Create(db),
		zip.WithSummary("Create an application"), zip.WithTags("applications"))
	zip.Put(app, "/v1/iam/application", Update(db),
		zip.WithSummary("Update an application"), zip.WithTags("applications"))
	zip.Delete(app, "/v1/iam/application", deleteApplication(db),
		zip.WithSummary("Delete an application"), zip.WithTags("applications"))
}

// listApplications returns every application owned by in.Owner, ordered by
// creation time descending.
func listApplications(db orm.DB) zip.TypedHandler[ApplicationQuery, ApplicationListResult] {
	return func(ctx context.Context, in *ApplicationQuery) (*ApplicationListResult, error) {
		if in.Owner == "" {
			return nil, zip.ErrBadRequest("owner is required")
		}
		apps, err := orm.TypedQuery[schema.Application](db).
			Filter("Owner=", in.Owner).
			Order("-CreatedTime").
			GetAll(ctx)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		for i, app := range apps {
			apps[i] = app.Mask() // never emit clientSecret in a list response
		}
		return &ApplicationListResult{Applications: apps}, nil
	}
}

// getApplication returns the application at (in.Owner, in.Name).
func getApplication(db orm.DB) zip.TypedHandler[ApplicationRef, schema.Application] {
	return func(ctx context.Context, in *ApplicationRef) (*schema.Application, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		id := appID(in.Owner, in.Name)
		app, err := orm.Get[schema.Application](db, id)
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("application not found: " + id)
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return app.Mask(), nil
	}
}

// Create persists a new application under (in.Owner, in.Name), rejecting a
// collision on that owner-scoped key. Exported so the Casdoor add-application
// alias reuses this exact logic (no duplication); the REST route and the alias
// share the one create path.
func Create(db orm.DB) zip.TypedHandler[schema.Application, schema.Application] {
	return func(ctx context.Context, in *schema.Application) (*schema.Application, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		if err := authorizeOrganization(ctx, in); err != nil {
			return nil, err
		}
		id := appID(in.Owner, in.Name)

		// Owner-scoped uniqueness: (owner, name) must be free.
		if _, err := orm.Get[schema.Application](db, id); err == nil {
			return nil, zip.ErrConflict("application already exists: " + id)
		} else if !errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrInternal(err.Error())
		}

		// Wire the decoded entity to db under its natural key and persist.
		in.Init(db)
		in.SetId(id)
		if err := in.Create(); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return in.Mask(), nil
	}
}

// Update overwrites the application at (in.Owner, in.Name), preserving its
// immutable creation metadata. The (owner, name) identity is fixed by the record,
// not editable through the body. Exported so the Casdoor update-application alias
// reuses this exact logic (no duplication).
func Update(db orm.DB) zip.TypedHandler[schema.Application, schema.Application] {
	return func(ctx context.Context, in *schema.Application) (*schema.Application, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		if err := authorizeOrganization(ctx, in); err != nil {
			return nil, err
		}
		id := appID(in.Owner, in.Name)

		existing, err := orm.Get[schema.Application](db, id)
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("application not found: " + id)
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}

		in.Init(db)
		in.SetId(id)
		in.CreatedTime = existing.CreatedTime
		in.CreatedAt = existing.CreatedAt
		if err := in.Update(); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return in.Mask(), nil
	}
}

// deleteApplication removes the application at (in.Owner, in.Name).
// Delete exposes the delete handler so the Casdoor `delete-application` verb alias
// (internal/compat) can reuse it — one delete path, wrapped in the compat envelope.
func Delete(db orm.DB) zip.TypedHandler[ApplicationRef, DeleteResult] { return deleteApplication(db) }

func deleteApplication(db orm.DB) zip.TypedHandler[ApplicationRef, DeleteResult] {
	return func(ctx context.Context, in *ApplicationRef) (*DeleteResult, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		id := appID(in.Owner, in.Name)

		app, err := orm.Get[schema.Application](db, id)
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("application not found: " + id)
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if err := app.Delete(); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &DeleteResult{Deleted: true}, nil
	}
}
