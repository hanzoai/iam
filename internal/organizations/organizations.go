// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package organizations implements the IAM v2 organization resource as typed
// zip handlers over hanzoai/orm. The entity is owner-scoped: the (owner, name)
// pair is the natural key, so reads, updates, and deletes resolve a row by that
// pair rather than by the orm surrogate id.
package organizations

import (
	"context"
	"errors"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

const orgBase = "/v1/iam/organizations"

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

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

// route registers the organization routes on app. The collection is orgBase and
// one organization is orgBase/{owner}/{name} — the natural key IS the address,
// so the method carries the verb and the URL says which row. Every handler
// validates its key and fails 400 if it is absent, so a missing selector is
// loud, never a silent full-table action.
func (h *OrganizationAPI) route(app *zip.App) {
	zip.Post[CreateOrganizationInput, schema.Organization](app, orgBase, h.Create,
		zip.WithOperationID("createOrganization"), zip.WithTags("organizations"))
	zip.Get[ListOrganizationsInput, ListOrganizationsOutput](app, orgBase, h.List,
		zip.WithOperationID("listOrganizations"), zip.WithTags("organizations"))
	zip.Post[SetAvatarInput, schema.Organization](app, orgBase+"/avatar", h.SetAvatar,
		zip.WithOperationID("setOrganizationAvatar"), zip.WithTags("organizations"))
	zip.Get[GetOrganizationInput, schema.Organization](app, orgBase+"/:owner/:name", h.Get,
		zip.WithOperationID("getOrganization"), zip.WithTags("organizations"))
	zip.Put[UpdateOrganizationInput, schema.Organization](app, orgBase+"/:owner/:name", h.Update,
		zip.WithOperationID("updateOrganization"), zip.WithTags("organizations"))
	zip.Delete[DeleteOrganizationInput, DeleteOrganizationOutput](app, orgBase+"/:owner/:name", h.Delete,
		zip.WithOperationID("deleteOrganization"), zip.WithTags("organizations"))
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

// SetAvatarInput selects an organization by natural key and carries how it is to
// appear. Sending both halves empty clears the mark.
type SetAvatarInput struct {
	Owner  string `json:"owner"`
	Name   string `json:"name"`
	Avatar string `json:"avatar"`
	Emoji  string `json:"emoji"`
}

// DeleteOrganizationInput selects the organization to remove by natural key.
type DeleteOrganizationInput struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// DeleteOrganizationOutput reports whether a row was removed.
type DeleteOrganizationOutput struct {
	Affected bool `json:"affected"`
}

// Create makes a new organization — the account your users, applications, roles,
// projects and workspaces are all named inside. It is the first write in a new
// tenant, and a name already in use is refused rather than taken over.
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
	model := entity.Model // keep orm binding (db handle, key) across the overlay
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

// Get returns one organization: its display, its defaults and the sign-in rules
// everyone in it inherits.
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

// Update changes an organization's display, its defaults and the sign-in rules
// everyone in it inherits. Which organization it is does not change, and neither
// does when it was created.
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

// SetAvatar changes how an organization appears across Hanzo: the square mark
// beside its name, as an uploaded image or as a single emoji. Sending an image
// clears the emoji and sending an emoji clears the image — an organization has
// one mark, not a preference order — and sending neither clears both, which is
// how it goes back to being drawn as its initial.
//
// An image is an https link or the bytes inline as a data URL, up to 96 KiB.
// Anyone who administers the organization may set this; it is not reserved to
// the platform.
//
// It writes the two fields onto the stored row and touches nothing else, which
// update cannot do: update replaces the whole record, and a record read back
// first arrives masked, so a read-modify-write through it would persist the mask
// over the organization's own credential settings.
func (h *OrganizationAPI) SetAvatar(ctx context.Context, in *SetAvatarInput) (*schema.Organization, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	mark, err := schema.MarkOf(in.Avatar, in.Emoji)
	if err != nil {
		return nil, zip.ErrBadRequest(err.Error())
	}
	org, err := h.find(in.Owner, in.Name)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, zip.ErrNotFound("organization not found")
	}
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	org.Avatar, org.Emoji = mark.Avatar, mark.Emoji
	if err := org.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return org.Mask(), nil
}

// Delete removes an organization and everything named inside it. There is no
// undo, and every session issued under it stops working.
//
// The built-in admin organization cannot be deleted — losing it would leave the
// account with no way back in.
func (h *OrganizationAPI) Delete(ctx context.Context, in *DeleteOrganizationInput) (*DeleteOrganizationOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	if in.Name == policy.AdminOrg {
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
