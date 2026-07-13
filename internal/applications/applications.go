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

	"github.com/hanzoai/iam2/internal/schema"
)

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

// Mount registers the applications CRUD surface on app, closing over db. Reads
// use GET, create POST, update PUT, delete DELETE — every one a zip typed
// handler.
func Mount(app *zip.App, db orm.DB) {
	zip.Get(app, "/v1/iam/v2/applications", listApplications(db),
		zip.WithSummary("List applications for an owner"), zip.WithTags("applications"))
	zip.Get(app, "/v1/iam/v2/application", getApplication(db),
		zip.WithSummary("Get one application by owner and name"), zip.WithTags("applications"))
	zip.Post(app, "/v1/iam/v2/application", createApplication(db),
		zip.WithSummary("Create an application"), zip.WithTags("applications"))
	zip.Put(app, "/v1/iam/v2/application", updateApplication(db),
		zip.WithSummary("Update an application"), zip.WithTags("applications"))
	zip.Delete(app, "/v1/iam/v2/application", deleteApplication(db),
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
		return app, nil
	}
}

// createApplication persists a new application under (in.Owner, in.Name),
// rejecting a collision on that owner-scoped key.
func createApplication(db orm.DB) zip.TypedHandler[schema.Application, schema.Application] {
	return func(ctx context.Context, in *schema.Application) (*schema.Application, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
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
		return in, nil
	}
}

// updateApplication overwrites the application at (in.Owner, in.Name),
// preserving its immutable creation metadata. The (owner, name) identity is
// fixed by the URL of the record, not editable through the body.
func updateApplication(db orm.DB) zip.TypedHandler[schema.Application, schema.Application] {
	return func(ctx context.Context, in *schema.Application) (*schema.Application, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
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
		return in, nil
	}
}

// deleteApplication removes the application at (in.Owner, in.Name).
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
