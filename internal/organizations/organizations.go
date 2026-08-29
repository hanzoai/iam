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
	zip.Post[SetProfileInput, schema.Organization](app, orgBase+"/profile", h.SetProfile,
		zip.WithOperationID("setOrganizationProfile"), zip.WithTags("organizations"))
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
	Avatar string `json:"avatar" url:"-"`
	Emoji  string `json:"emoji" url:"-"`
}

// SetProfileInput selects an organization by natural key and carries the fields
// a person edits on a profile form. Every one is a POINTER: absent means leave
// it alone, and "" means clear it — a distinction the plain string cannot make,
// and the whole reason a partial write needs its own shape.
type SetProfileInput struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`

	DisplayName *string `json:"displayName"`
	WebsiteUrl  *string `json:"websiteUrl"`
	Favicon     *string `json:"favicon"`
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
	// An organization is filed under the admin owner. The NAME is the tenant
	// identity; the owner half is the registry the row lives in, which is why the
	// signup converge writes it, the list here reads it, store.GetOrganizationByName
	// resolves a name within it, and authz decides an organization write on its
	// reserved-owner branch. Filed anywhere else, a row would carry a name the rest
	// of the system already answers with another row — so the owner is a value with
	// one legal setting rather than a choice.
	//
	// It is REFUSED rather than quietly corrected: the authorizer decides on this
	// same decoded value, so the row written has to be the row authorized. Pinning
	// it after that decision would authorize one owner and write another.
	if org.Owner != policy.AdminOrg {
		return nil, zip.ErrBadRequest("an organization is filed under the " + policy.AdminOrg + " owner")
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
	// The natural key IS the key, the way every sibling writer states it. The store
	// keys a row by this string, so one (owner, name) is one row by construction
	// rather than by a check that has to be run first.
	entity.SetId(org.Owner + "/" + org.Name)
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

// SetProfile changes how an organization reads: its display name, its website
// and its favicon.
//
// IT EXISTS FOR THE REASON SetAvatar DOES, and the reason is worth stating
// because the obvious alternative is a trap. Update REPLACES the whole record,
// so a caller that wants to change one field has to send every other field
// back — and a record read back first arrives MASKED, so the read half of that
// read-modify-write hands you "***" for the master password and the salt, and
// the write half stores it. Renaming an organization through Update therefore
// costs it its credential settings; sending only the new name costs it
// everything else. Neither is a rename.
//
// So this writes the fields it names and touches nothing else. A nil pointer is
// not sent and not changed; an empty string is sent and clears the field.
func (h *OrganizationAPI) SetProfile(ctx context.Context, in *SetProfileInput) (*schema.Organization, error) {
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
	if in.DisplayName != nil {
		org.DisplayName = *in.DisplayName
	}
	if in.WebsiteUrl != nil {
		org.WebsiteUrl = *in.WebsiteUrl
	}
	if in.Favicon != nil {
		org.Favicon = *in.Favicon
	}
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
