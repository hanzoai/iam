// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
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

// ensureClientIdUnique rejects a create/update whose clientId is already held by a
// DIFFERENT application (any owner). clientId is the GLOBAL key the mint and Basic-auth
// resolvers authenticate against, so it must be unique across every owner, not merely
// within one — otherwise a tenant could register a row whose clientId collides with a
// platform console's and (on a backend whose duplicate-row order is unspecified) shadow
// it. A JSON-document store has no per-field column to carry a DB UNIQUE index, so the
// invariant is enforced here at the write, exactly as the (owner,name) natural key is.
// An empty clientId cannot collide (a public app authenticates no confidential grant);
// the self-row (same owner,name) is skipped so an update that keeps its own clientId is
// never a self-collision.
func ensureClientIdUnique(ctx context.Context, db orm.DB, clientId, owner, name string) error {
	if clientId == "" {
		return nil
	}
	existing, err := store.ListApplicationsByClientId(ctx, db, clientId)
	if err != nil {
		return zip.ErrInternal(err.Error())
	}
	for _, a := range existing {
		if a.Owner != owner || a.Name != name {
			return zip.ErrConflict("clientId already in use: " + clientId)
		}
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

//go:generate go run github.com/zap-proto/zip/cmd/zipdoc

// Route registers the applications CRUD surface on app, closing over db.
//
// The kind is addressed in the PLURAL, like every other kind in this service —
// users, certs, roles, invitations, keys, projects, workspaces, permissions,
// providers, tokens, sessions, organizations, audit-logs,
// webauthn-credentials — with `/get`, `/update` and `/delete` under it. This was
// the only singular, so `/v1/iam/application` and `/v1/iam/applications` both
// answered and which spelling a reader wanted depended on the operation.
// Fourteen kinds against one is not a matter of taste; the odd one moved.
//
// The singular address stays reachable on the SAME typed handlers, tagged
// `compat` — which is what keeps it out of the published document and therefore
// out of every SDK, docs page and CLI command. It is deleted when the last
// pinned consumer moves.
func Route(app *zip.App, db orm.DB) {
	zip.Get(app, "/v1/iam/applications", listApplications(db), zip.WithTags("applications"))
	zip.Post(app, "/v1/iam/applications", Create(db), zip.WithTags("applications"))
	zip.Get(app, "/v1/iam/applications/get", getApplication(db), zip.WithTags("applications"))
	zip.Post(app, "/v1/iam/applications/update", Update(db), zip.WithTags("applications"))
	zip.Post(app, "/v1/iam/applications/delete", deleteApplication(db), zip.WithTags("applications"))

}

// listApplications returns the applications in one organization, newest first —
// each product or site your people sign in to, with the sign-in methods and
// redirect URIs it allows.
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

// getApplication returns one application: its sign-in methods, its allowed
// redirect URIs and the client credentials your integration authenticates with.
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

// Create registers an application in your organization — one product or site
// your people sign in to, with its own client credentials, sign-in methods and
// allowed redirect URIs. A name already used in the organization is refused
// rather than overwritten.
//
// Exported so the legacy add-application alias reuses this exact path — one
// create, two spellings.
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

		// Global uniqueness: clientId is the mint/Basic-auth resolution key, so it must
		// be free across ALL owners — the invariant the confidential-client gates rely on.
		if err := ensureClientIdUnique(ctx, db, in.ClientId, in.Owner, in.Name); err != nil {
			return nil, err
		}

		// Bind the decoded entity to db under its natural key and persist.
		in.Init(db)
		in.SetId(id)
		if err := in.Create(); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return in.Mask(), nil
	}
}

// Update changes an application's display, its sign-in methods and the redirect
// URIs it may return to — the call that makes login work from a new host. Which
// organization it belongs to and what it is named are fixed when it is created
// and are not editable here.
//
// Exported so the legacy update-application alias reuses this exact path — one
// update, two spellings.
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

		// Global clientId uniqueness (see Create): an update may keep its own clientId
		// but must never steal another app's.
		if err := ensureClientIdUnique(ctx, db, in.ClientId, in.Owner, in.Name); err != nil {
			return nil, err
		}

		// A write that says NOTHING about the credential must not destroy it.
		//
		// This verb is a full REPLACE, and every read of an application MASKS its
		// client secret (Mask, and get-app-login before it) — so the natural admin
		// round-trip — read the record, change one field, write it back — posts
		// ClientSecret:"" for an app that holds one, so the write would blank it. Any
		// console "save" on an application page is then one request from turning a
		// confidential client public, which the token endpoint reads as "PKCE, demand
		// no client auth", weakening every flow that app serves.
		//
		// So an OMITTED secret preserves what is stored. This is the same rule the
		// operator upsert already settled in resolveSecret ("existing app -> preserve
		// what it has"), stated once more here because this is the other door onto the
		// same row; rotation stays possible, it just has to be DELIBERATE — send the
		// new secret to change it.
		//
		// Clearing a secret on purpose (confidential -> public) is therefore no longer
		// expressible as an accident. It goes through the operator upsert's explicit
		// `public: true`, which is the one place that decision is named.
		if in.ClientSecret == "" {
			in.ClientSecret = existing.ClientSecret
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

// Delete exposes the same handler to the legacy delete-application alias — one
// delete path, wrapped in that surface's envelope.
func Delete(db orm.DB) zip.TypedHandler[ApplicationRef, DeleteResult] { return deleteApplication(db) }

// deleteApplication removes an application. Anyone mid-sign-in through it is
// turned away and its client credentials stop working, so retire the integration
// before deleting it.
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
