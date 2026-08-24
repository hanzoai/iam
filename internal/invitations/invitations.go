// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package invitations serves the IAM v2 CRUD surface for the `invitations`
// entity: a pending org-membership invite owner-scoped by (owner, name). Every
// operation is a typed zip handler over hanzoai/orm; the orm string key is
// "owner/name". Reads scope to one owner (organization); writes address one
// invitation by its (owner, name) key.
package invitations

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Handler binds the invitations operations to one orm store.
type Handler struct {
	db orm.DB
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the invitations CRUD routes on app against db.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/invitations", h.List, zip.WithTags("invitations"))
	zip.Post(app, "/v1/iam/invitations", h.Create, zip.WithTags("invitations"))
	zip.Get(app, "/v1/iam/invitations/:owner/:name", h.Get, zip.WithTags("invitations"))
	zip.Put(app, "/v1/iam/invitations/:owner/:name", h.Update, zip.WithTags("invitations"))
	zip.Delete(app, "/v1/iam/invitations/:owner/:name", h.Delete, zip.WithTags("invitations"))
}

// Ref addresses one invitation by its owner-scoped natural key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Input is the writable projection of an invitation (the v1 add/update-invitation
// body). It keeps the HTTP contract clean of the orm.Model bookkeeping fields.
type Input struct {
	Owner       string `json:"owner"`
	Name        string `json:"name"`
	CreatedTime string `json:"createdTime"`
	UpdatedTime string `json:"updatedTime"`
	DisplayName string `json:"displayName"`
	Code        string `json:"code"`
	IsRegexp    bool   `json:"isRegexp"`
	Quota       int    `json:"quota"`
	UsedCount   int    `json:"usedCount"`
	Application string `json:"application"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	Phone       string `json:"phone"`
	SignupGroup string `json:"signupGroup"`
	DefaultCode string `json:"defaultCode"`
	State       string `json:"state"`
}

// ListInput scopes a listing to one owner (organization).
type ListInput struct {
	Owner string `json:"owner"`
}

// ListOutput is the owner-scoped page of invitations.
type ListOutput struct {
	Invitations []*schema.Invitation `json:"invitations"`
	Total       int                  `json:"total"`
}

// DeleteOutput reports the delete result.
type DeleteOutput struct {
	Deleted bool `json:"deleted"`
}

// key builds the orm string key from the (owner, name) natural key.
func key(owner, name string) string { return owner + "/" + name }

// apply copies the mutable domain fields of an Input onto an invitation. The
// identity fields (owner, name) and the created stamp are set only on Create,
// never overwritten by an update.
func apply(dst *schema.Invitation, in *Input) {
	dst.UpdatedTime = in.UpdatedTime
	dst.DisplayName = in.DisplayName
	dst.Code = in.Code
	dst.IsRegexp = in.IsRegexp
	dst.Quota = in.Quota
	dst.UsedCount = in.UsedCount
	dst.Application = in.Application
	dst.Username = in.Username
	dst.Email = in.Email
	dst.Phone = store.NormalizePhone(in.Phone)
	dst.SignupGroup = in.SignupGroup
	dst.DefaultCode = in.DefaultCode
	dst.State = in.State
}

// List returns your organization's invitations, newest first — who has
// been asked to join, on what terms, and how many seats each invitation still
// has left.
//
// You see your own organization's invitations and no one else's; which organization that
// is comes from your credentials, not from the request.
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	// The owner is resolved by principal.Scope from the authenticated principal,
	// never taken from the input: a tenant reads only its own org, a SuperAdmin
	// reads the owner it asks for. in.Owner is whatever the CALLER wrote in the URL,
	// since zip binds a typed op's scalar fields from the query string on every
	// method, so filtering on it would let a request name the tenant it reads.
	owner, err := principal.Scope(ctx, in.Owner)
	if err != nil {
		return nil, err
	}
	q := orm.TypedQuery[schema.Invitation](h.db)
	if owner != "" {
		q = q.Filter("owner", owner)
	}
	invitations, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &ListOutput{Invitations: invitations, Total: len(invitations)}, nil
}

// Get returns one invitation: who it is for, what it grants on acceptance, and
// when it expires.
func (h *Handler) Get(ctx context.Context, in *Ref) (*schema.Invitation, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	invitation, err := orm.Get[schema.Invitation](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	return invitation, nil
}

// Create issues an invitation to join your organization — the code or link a new
// member redeems, with the role they arrive holding and the date it stops
// working. A name already used in the organization is refused.
func (h *Handler) Create(ctx context.Context, in *Input) (*schema.Invitation, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	switch _, err := orm.Get[schema.Invitation](h.db, key(in.Owner, in.Name)); {
	case err == nil:
		return nil, zip.ErrConflict("invitation already exists")
	case !errors.Is(err, orm.ErrNotFound):
		return nil, zip.ErrInternal(err.Error())
	}

	invitation := orm.New[schema.Invitation](h.db)
	invitation.Owner = in.Owner
	invitation.Name = in.Name
	invitation.CreatedTime = in.CreatedTime
	if invitation.CreatedTime == "" {
		invitation.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	apply(invitation, in)
	invitation.SetId(key(in.Owner, in.Name))

	if err := invitation.CreateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return invitation, nil
}

// Update changes an invitation's terms — the role it grants, how many may redeem
// it, or when it expires. What it is called does not change.
func (h *Handler) Update(ctx context.Context, in *Input) (*schema.Invitation, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	invitation, err := orm.Get[schema.Invitation](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	apply(invitation, in)
	if err := invitation.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return invitation, nil
}

// Delete withdraws an invitation. It stops being redeemable at once; anyone who
// already joined through it keeps their account.
func (h *Handler) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	invitation, err := orm.Get[schema.Invitation](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	if err := invitation.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// mapErr translates an orm lookup error into the matching HTTP status.
func mapErr(err error) error {
	if errors.Is(err, orm.ErrNotFound) {
		return zip.ErrNotFound("invitation not found")
	}
	return zip.ErrInternal(err.Error())
}
