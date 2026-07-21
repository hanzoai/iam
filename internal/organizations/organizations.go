// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package organizations implements the IAM v2 organization resource as typed
// zip handlers over hanzoai/orm. The entity is owner-scoped: the (owner, name)
// pair is the natural key, so reads, updates, and deletes resolve a row by that
// pair rather than by the orm surrogate id.
package organizations

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/schema"
)

const orgBase = "/v1/iam/organizations"

// Route registers the organization CRUD surface on app, backed by db.
func Route(app *zip.App, db orm.DB) {
	NewOrganizationAPI(db).route(app)
}

// OrganizationAPI serves CRUD for the organization entity over a single
// orm.DB. It is transport-only: credential hashing, password-type
// sanitisation, and signin-throttle clamping are policy concerns applied by the
// caller before Create/Update — never braided into persistence here.
type OrganizationAPI struct {
	DB orm.DB
}

// NewOrganizationAPI binds the handlers to a store.
func NewOrganizationAPI(db orm.DB) *OrganizationAPI {
	return &OrganizationAPI{DB: db}
}

// mount registers the five organization routes on app. Writes are POST with a
// JSON body; reads are GET whose (owner, name, paging) selector binds from the
// request. Every handler validates its key and fails 400 if it is absent, so a
// missing selector is loud, never a silent full-table action.
func (h *OrganizationAPI) route(app *zip.App) {
	zip.Post[CreateOrganizationInput, schema.Organization](app, orgBase, h.Create,
		zip.WithOperationID("createOrganization"), zip.WithSummary("Create an organization"), zip.WithTags("organizations"))
	zip.Get[ListOrganizationsInput, ListOrganizationsOutput](app, orgBase, h.List,
		zip.WithOperationID("listOrganizations"), zip.WithSummary("List organizations"), zip.WithTags("organizations"))
	zip.Get[GetOrganizationInput, schema.Organization](app, orgBase+"/get", h.Get,
		zip.WithOperationID("getOrganization"), zip.WithSummary("Get one organization by owner and name"), zip.WithTags("organizations"))
	zip.Post[UpdateOrganizationInput, schema.Organization](app, orgBase+"/update", h.Update,
		zip.WithOperationID("updateOrganization"), zip.WithSummary("Update an organization"), zip.WithTags("organizations"))
	zip.Post[DeleteOrganizationInput, DeleteOrganizationOutput](app, orgBase+"/delete", h.Delete,
		zip.WithOperationID("deleteOrganization"), zip.WithSummary("Delete an organization"), zip.WithTags("organizations"))
}

// CreateOrganizationInput carries the full organization as the request body.
type CreateOrganizationInput struct {
	schema.Organization
}

// UpdateOrganizationInput carries the desired organization state; its Owner and
// Name select the row to overwrite.
type UpdateOrganizationInput struct {
	schema.Organization
}

// GetOrganizationInput selects a single organization by natural key.
type GetOrganizationInput struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// DeleteOrganizationInput selects the organization to remove by natural key.
type DeleteOrganizationInput struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// ListOrganizationsInput scopes and pages a listing. All fields are optional.
type ListOrganizationsInput struct {
	Owner  string `json:"owner"`
	Limit  int    `json:"limit"`
	Offset int    `json:"offset"`
}

// ListOrganizationsOutput is one page of organizations.
type ListOrganizationsOutput struct {
	Organizations []*schema.Organization `json:"organizations"`
	Count         int                    `json:"count"`
}

// DeleteOrganizationOutput reports whether a row was removed.
type DeleteOrganizationOutput struct {
	Affected bool `json:"affected"`
}

// Create inserts a new organization, refusing a duplicate (owner, name).
func (h *OrganizationAPI) Create(ctx context.Context, in *CreateOrganizationInput) (*schema.Organization, error) {
	org := in.Organization
	if org.Owner == "" || org.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	switch _, err := h.find(org.Owner, org.Name); {
	case err == nil:
		return nil, zip.ErrConflict("organization already exists")
	case errors.Is(err, orm.ErrNotFound):
		// free to create
	default:
		return nil, zip.ErrInternal(err.Error())
	}

	entity := orm.New[schema.Organization](h.DB)
	model := entity.Model // keep orm wiring (db handle, key) across the overlay
	*entity = org
	entity.Model = model
	if entity.CreatedTime == "" {
		entity.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	if err := entity.CreateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return entity.Mask(), nil
}

// Get resolves one organization by (owner, name).
func (h *OrganizationAPI) Get(ctx context.Context, in *GetOrganizationInput) (*schema.Organization, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	org, err := h.find(in.Owner, in.Name)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, zip.ErrNotFound("organization not found")
	}
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return org.Mask(), nil
}

// List returns organizations newest-first, optionally scoped by owner and paged.
func (h *OrganizationAPI) List(ctx context.Context, in *ListOrganizationsInput) (*ListOrganizationsOutput, error) {
	q := orm.TypedQuery[schema.Organization](h.DB)
	if in.Owner != "" {
		q = q.Filter("Owner=", in.Owner)
	}
	if in.Limit > 0 {
		q = q.Limit(in.Limit)
	}
	if in.Offset > 0 {
		q = q.Offset(in.Offset)
	}
	orgs, err := q.Order("-CreatedTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	for i, o := range orgs {
		orgs[i] = o.Mask()
	}
	return &ListOrganizationsOutput{Organizations: orgs, Count: len(orgs)}, nil
}

// Update overwrites an existing organization, preserving its storage identity
// (orm key, id, audit timestamps) and its original creation time.
func (h *OrganizationAPI) Update(ctx context.Context, in *UpdateOrganizationInput) (*schema.Organization, error) {
	desired := in.Organization
	if desired.Owner == "" || desired.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	existing, err := h.find(desired.Owner, desired.Name)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, zip.ErrNotFound("organization not found")
	}
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}

	model := existing.Model // orm key + pre-update snapshot for the diff hooks
	created := existing.CreatedTime
	*existing = desired
	existing.Model = model
	if existing.CreatedTime == "" {
		existing.CreatedTime = created
	}
	if err := existing.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return existing.Mask(), nil
}

// Delete removes an organization. The built-in admin organization is protected.
func (h *OrganizationAPI) Delete(ctx context.Context, in *DeleteOrganizationInput) (*DeleteOrganizationOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	if in.Name == "admin" {
		return nil, zip.ErrForbidden("the built-in admin organization cannot be deleted")
	}
	existing, err := h.find(in.Owner, in.Name)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, zip.ErrNotFound("organization not found")
	}
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	if err := existing.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOrganizationOutput{Affected: true}, nil
}

// find resolves an organization by its (owner, name) natural key. The error is
// orm.ErrNotFound when no row matches.
func (h *OrganizationAPI) find(owner, name string) (*schema.Organization, error) {
	return orm.TypedQuery[schema.Organization](h.DB).
		Filter("Owner=", owner).
		Filter("Name=", name).
		First()
}
