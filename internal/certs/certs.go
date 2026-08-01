// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package certs serves the IAM v2 CRUD surface for the `certs` entity: a
// signing / TLS certificate owner-scoped by (owner, name). Every operation is a
// typed zip handler over hanzoai/orm; the orm string key is "owner/name". Reads
// scope to one owner (organization); writes address one cert by its (owner,
// name) key.
package certs

import (
	"context"
	"errors"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/internal/schema"
)

// Handler binds the certs operations to one orm store.
type Handler struct {
	db orm.DB
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the certs CRUD routes on app against db. Reads are zip.Get,
// writes are zip.Post; the create/update body is the schema.Cert row itself, so
// the HTTP contract and the stored entity never drift.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/certs", h.List, zip.WithTags("certs"))
	zip.Post(app, "/v1/iam/certs", h.Create, zip.WithTags("certs"))
	zip.Post(app, "/v1/iam/certs/get", h.Get, zip.WithTags("certs"))
	zip.Post(app, "/v1/iam/certs/update", h.Update, zip.WithTags("certs"))
	zip.Post(app, "/v1/iam/certs/delete", h.Delete, zip.WithTags("certs"))
}

// Ref addresses one cert by its owner-scoped natural key.
type Ref struct {
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// ListInput scopes a listing to one owner (organization).
type ListInput struct {
	Owner string `json:"owner"`
}

// ListOutput is the owner-scoped page of certs.
type ListOutput struct {
	Certs []*schema.Cert `json:"certs"`
	Total int            `json:"total"`
}

// DeleteOutput reports the delete result.
type DeleteOutput struct {
	Deleted bool `json:"deleted"`
}

// key builds the orm string key from the (owner, name) natural key.
func key(owner, name string) string { return owner + "/" + name }

// List returns your organization's signing certificates, newest first — the keys
// the tokens your applications verify are signed with. Private key material is
// masked.
//
// You see your own organization's certificates and no one else's; which
// organization that is comes from your credentials, not from the request, so a
// query parameter can never widen the listing.
func (h *Handler) List(ctx context.Context, in *ListInput) (*ListOutput, error) {
	owner, err := authz.Scope(ctx, in.Owner)
	if err != nil {
		return nil, err
	}
	q := orm.TypedQuery[schema.Cert](h.db)
	if owner != "" {
		q = q.Filter("owner", owner)
	}
	certs, err := q.Order("-createdTime").GetAll(ctx)
	if err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	out := make([]*schema.Cert, len(certs))
	for i, c := range certs {
		out[i] = c.Mask()
	}
	return &ListOutput{Certs: out, Total: len(out)}, nil
}

// Get returns one signing certificate — its algorithm, its validity window and
// its public half. The private key is masked.
func (h *Handler) Get(_ context.Context, in *Ref) (*schema.Cert, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	cert, err := orm.Get[schema.Cert](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	return cert.Mask(), nil
}

// Create adds a signing certificate your applications can verify tokens against
// — the call you make to bring your own key, or to stage the next one before a
// rotation. A name already used in your organization is refused.
func (h *Handler) Create(ctx context.Context, in *schema.Cert) (*schema.Cert, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	switch _, err := orm.Get[schema.Cert](h.db, key(in.Owner, in.Name)); {
	case err == nil:
		return nil, zip.ErrConflict("cert already exists")
	case !errors.Is(err, orm.ErrNotFound):
		return nil, zip.ErrInternal(err.Error())
	}

	// orm.New binds the store and applies defaults; overlay the decoded row,
	// then restore the bound Model so its db handle survives the assignment.
	cert := orm.New[schema.Cert](h.db)
	model := cert.Model
	*cert = *in
	cert.Model = model
	if cert.CreatedTime == "" {
		cert.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	}
	cert.SetId(key(in.Owner, in.Name))

	if err := cert.CreateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return cert, nil
}

// Update changes a signing certificate's settings. What it is called does not
// change, and neither does when it was added.
func (h *Handler) Update(ctx context.Context, in *schema.Cert) (*schema.Cert, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	cert, err := orm.Get[schema.Cert](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	// Keep the loaded Model (id, createdAt, key, snapshot) and the original
	// creation stamp; overlay the decoded domain fields onto them.
	model := cert.Model
	created := cert.CreatedTime
	*cert = *in
	cert.Model = model
	cert.Owner, cert.Name = in.Owner, in.Name
	if created != "" {
		cert.CreatedTime = created
	}
	if err := cert.UpdateCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return cert, nil
}

// Delete removes a signing certificate. Tokens signed with it can no longer be
// verified, so retire it only once nothing is still presenting them.
func (h *Handler) Delete(ctx context.Context, in *Ref) (*DeleteOutput, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	cert, err := orm.Get[schema.Cert](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	if err := cert.DeleteCtx(ctx); err != nil {
		return nil, zip.ErrInternal(err.Error())
	}
	return &DeleteOutput{Deleted: true}, nil
}

// mapErr translates an orm lookup error into the matching HTTP status.
func mapErr(err error) error {
	if errors.Is(err, orm.ErrNotFound) {
		return zip.ErrNotFound("cert not found")
	}
	return zip.ErrInternal(err.Error())
}
