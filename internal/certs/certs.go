// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package certs serves the IAM v2 CRUD surface for the `certs` entity: a
// signing / TLS certificate owner-scoped by (owner, name). Every operation is a
// typed zip handler over hanzoai/orm; the orm string key is "owner/name". Reads
// scope to one owner (organization); writes address one cert by its (owner,
// name) key.
package certs

import (
	"context"
	"errors"
	"reflect"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// Handler binds the certs operations to one orm store.
type Handler struct {
	db orm.DB
}

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the certs CRUD routes on app against db. The method carries
// the verb and the path carries the row's (owner, name) key, so the URL is what
// addresses a cert. zip binds path segments above the body, and the create/update
// body is the schema.Cert row itself — so the HTTP contract and the stored entity
// never drift, and a body naming a different cert cannot move the write off the
// one the URL named.
func Route(app *zip.App, db orm.DB) {
	h := &Handler{db: db}
	zip.Get(app, "/v1/iam/certs", h.List, zip.WithTags("certs"))
	zip.Post(app, "/v1/iam/certs", h.Create, zip.WithTags("certs"))
	zip.Get(app, "/v1/iam/certs/:owner/:name", h.Get, zip.WithTags("certs"))
	zip.Put(app, "/v1/iam/certs/:owner/:name", h.Update, zip.WithTags("certs"))
	zip.Delete(app, "/v1/iam/certs/:owner/:name", h.Delete, zip.WithTags("certs"))
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
	owner, err := principal.Scope(ctx, in.Owner)
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
func (h *Handler) Get(ctx context.Context, in *Ref) (*schema.Cert, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	cert, err := orm.Get[schema.Cert](h.db, key(in.Owner, in.Name))
	if err == nil {
		return cert.Mask(), nil
	}
	if !errors.Is(err, orm.ErrNotFound) {
		return nil, mapErr(err)
	}

	// A PLATFORM SIGNING CERT IS ADDRESSED BY NAME, and that is one rule rather
	// than two. The JWKS publishes a cert, and issueTokens signs with it, through
	// store.GetSigningCert — which searches the reserved owners in order and does
	// not care which of them holds the row. Only this read insisted on an exact
	// owner, so the two could disagree about a cert that plainly exists, and they
	// did: cert-hanzo was live in the JWKS while GET certs/get?owner=admin
	// answered 404, because the surviving row sat under the other reserved owner.
	//
	// ai bootstraps by reading its application and then that application's cert
	// (object/auth_config.go), so the miss left the process unable to establish
	// the key every bearer is validated against — api.hanzo.ai answered 503 to
	// every authenticated request while the key it needed was being served, one
	// route away, to anyone who asked.
	//
	// Scoped, not widened: this only fires for a RESERVED owner, so a tenant
	// asking for its own org's cert still gets that org's row or nothing, and a
	// tenant can no more reach a platform key than before. Masked like the exact
	// hit — Mask blanks PrivateKey — so what crosses is the public half the JWKS
	// already publishes.
	if !policy.IsSigningOwner(in.Owner) {
		return nil, mapErr(err)
	}
	signing, serr := store.GetSigningCert(ctx, h.db, in.Name)
	if serr != nil {
		return nil, mapErr(serr)
	}
	if signing == nil {
		return nil, mapErr(err)
	}
	return signing.Mask(), nil
}

// Create adds a signing certificate your applications can verify tokens against
// — the call you make to stage the next one before a rotation. A name already
// used in your organization is refused.
//
// It registers the certificate's IDENTITY: its name (which is the JWKS `kid`),
// its algorithm, its expiry. Key material does not travel this way and cannot:
// the private key is not part of the Cert's JSON, so it is neither served here
// nor accepted here. It is supplied to the process by the deployment, under the
// name registered here (internal/keyring). Staging a rotation is therefore two
// halves — this call names the key, and the deployment provides it.
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
//
// A PUT here is a METADATA edit — display name, expiry, provider. It overlays
// only the fields the request actually SET onto the loaded row: a field the JSON
// omits (or leaves at its zero value) keeps what the row holds, rather than
// blanking it. That is load-bearing, not a nicety. A read serves the public
// Certificate (Mask hides only PrivateKey and AccessSecret), so a client that
// reads a cert, changes one field, and writes it back sends the masked halves
// empty and every other field it did not touch at its zero value — and the old
// full-struct overlay wrote all of those blanks back. Blanking CryptoAlgorithm
// alone drops the cert from the JWKS (oidc.Publishes turns false), so every
// token under its `kid` stops verifying; blanking Provider/Account/ExpireTime
// breaks ACME renewal and expiry — all from a request that only meant to rename
// it. Absent-or-zero means "unchanged", so the deployment (key) and a rotation
// (cert) remain the only way key or published material changes; the metadata API
// cannot clear it.
//
// The overlay is generic — it copies every set field, so a field nobody has added
// yet is carried without a line here — and leaves three things the request may
// not move: the bound Model (id, createdAt, key, snapshot), the natural key
// (owner/name address the row, they do not mutate it), and the creation stamp.
func (h *Handler) Update(ctx context.Context, in *schema.Cert) (*schema.Cert, error) {
	if in.Owner == "" || in.Name == "" {
		return nil, zip.ErrBadRequest("owner and name are required")
	}
	cert, err := orm.Get[schema.Cert](h.db, key(in.Owner, in.Name))
	if err != nil {
		return nil, mapErr(err)
	}
	dst := reflect.ValueOf(cert).Elem()
	src := reflect.ValueOf(in).Elem()
	fields := src.Type()
	for i := 0; i < fields.NumField(); i++ {
		f := fields.Field(i)
		// The embedded Model and the creation stamp are the row's identity, not its
		// settings; the addressing key is set explicitly below. Everything else is
		// overlaid only when the request set it.
		if f.Anonymous || f.Name == "CreatedTime" || f.Name == "Owner" || f.Name == "Name" {
			continue
		}
		if v := src.Field(i); !v.IsZero() && dst.Field(i).CanSet() {
			dst.Field(i).Set(v)
		}
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
