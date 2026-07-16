// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package providers is the Phase-1 typed CRUD surface for the `providers`
// entity, owner-scoped by the (owner, name) natural key.
//
// The five operations are typed zip handlers over orm: reads are zip.Get,
// writes are zip.Post. zip decodes the request body into the In struct for
// every non-GET method (and, over the MCP projection, for GET too); the REST
// GET projection carries no body, so any op that needs the (owner, name) key
// from the caller is a POST. Each op is also an MCP tool and an OpenAPI 3.1
// operation from this one registration.
package providers

import (
	"context"
	"errors"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam2/internal/schema"
)

// providerId renders the (owner, name) pair as the orm row id so Get, Update,
// and Delete resolve by natural key without a secondary lookup.
func providerId(owner, name string) string { return owner + "/" + name }

// providerKey is the (owner, name) selector for get and delete.
type providerKey struct {
	Owner string `json:"owner" validate:"required"`
	Name  string `json:"name"  validate:"required"`
}

// listProvidersIn scopes a list to one owner. An empty owner lists every
// provider (superuser view); a set owner filters to that tenant.
type listProvidersIn struct {
	Owner string `json:"owner"`
}

type listProvidersOut struct {
	Providers []*schema.Provider `json:"providers"`
}

type providerResult struct {
	Provider *schema.Provider `json:"provider"`
}

// mutationResult mirrors v1's Affected/Unaffected action response and carries
// the resulting row on a successful write.
type mutationResult struct {
	Affected bool             `json:"affected"`
	Provider *schema.Provider `json:"provider,omitempty"`
}

// Route registers the provider surface on app, closing over the entity store.
func Route(app *zip.App, db orm.DB) {
	zip.Get[listProvidersIn, listProvidersOut](app, "/v1/iam/providers", listProviders(db),
		zip.WithOperationID("listProviders"),
		zip.WithSummary("List providers in an owner scope"),
		zip.WithTags("providers"))

	zip.Post[providerKey, providerResult](app, "/v1/iam/providers/get", getProvider(db),
		zip.WithOperationID("getProvider"),
		zip.WithSummary("Get one provider by (owner, name)"),
		zip.WithTags("providers"))

	zip.Post[schema.Provider, providerResult](app, "/v1/iam/providers", addProvider(db),
		zip.WithOperationID("addProvider"),
		zip.WithSummary("Create a provider"),
		zip.WithTags("providers"))

	zip.Post[schema.Provider, mutationResult](app, "/v1/iam/providers/update", updateProvider(db),
		zip.WithOperationID("updateProvider"),
		zip.WithSummary("Update an existing provider"),
		zip.WithTags("providers"))

	zip.Post[providerKey, mutationResult](app, "/v1/iam/providers/delete", deleteProvider(db),
		zip.WithOperationID("deleteProvider"),
		zip.WithSummary("Delete a provider by (owner, name)"),
		zip.WithTags("providers"))
}

// listProviders returns every provider in the owner scope, newest first.
func listProviders(db orm.DB) zip.TypedHandler[listProvidersIn, listProvidersOut] {
	return func(ctx context.Context, in *listProvidersIn) (*listProvidersOut, error) {
		q := orm.TypedQuery[schema.Provider](db)
		if in.Owner != "" {
			q = q.Filter("Owner=", in.Owner)
		}
		rows, err := q.Order("-CreatedTime").GetAll(ctx)
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		for i, p := range rows {
			rows[i] = p.Mask() // never emit clientSecret in a list response
		}
		return &listProvidersOut{Providers: rows}, nil
	}
}

// getProvider resolves one provider by its (owner, name) key.
func getProvider(db orm.DB) zip.TypedHandler[providerKey, providerResult] {
	return func(_ context.Context, in *providerKey) (*providerResult, error) {
		p, err := orm.Get[schema.Provider](db, providerId(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return nil, zip.ErrNotFound("provider not found: " + providerId(in.Owner, in.Name))
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &providerResult{Provider: p.Mask()}, nil
	}
}

// addProvider creates a provider from the request body, keyed by (owner, name).
func addProvider(db orm.DB) zip.TypedHandler[schema.Provider, providerResult] {
	return func(ctx context.Context, in *schema.Provider) (*providerResult, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		// orm.New wires the store and applies defaults; copy the decoded domain
		// fields over it, then restore the wired Model so its db handle and key
		// survive the assignment.
		p := orm.New[schema.Provider](db)
		model := p.Model
		*p = *in
		p.Model = model
		p.SetId(providerId(in.Owner, in.Name))
		if err := p.CreateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &providerResult{Provider: p.Mask()}, nil
	}
}

// updateProvider read-modify-writes a provider in place. A missing row is
// reported as Unaffected (v1 UpdateProvider returns false), not an error.
func updateProvider(db orm.DB) zip.TypedHandler[schema.Provider, mutationResult] {
	return func(ctx context.Context, in *schema.Provider) (*mutationResult, error) {
		if in.Owner == "" || in.Name == "" {
			return nil, zip.ErrBadRequest("owner and name are required")
		}
		p, err := orm.Get[schema.Provider](db, providerId(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return &mutationResult{Affected: false}, nil
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		// Overlay the decoded domain fields onto the loaded row, keeping the
		// loaded Model (id, createdAt, key, snapshot) so the write targets the
		// existing key and preserves creation metadata.
		model := p.Model
		*p = *in
		p.Model = model
		if err := p.UpdateCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &mutationResult{Affected: true, Provider: p.Mask()}, nil
	}
}

// deleteProvider removes a provider by key. A missing row is Unaffected.
func deleteProvider(db orm.DB) zip.TypedHandler[providerKey, mutationResult] {
	return func(ctx context.Context, in *providerKey) (*mutationResult, error) {
		p, err := orm.Get[schema.Provider](db, providerId(in.Owner, in.Name))
		if errors.Is(err, orm.ErrNotFound) {
			return &mutationResult{Affected: false}, nil
		}
		if err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		if err := p.DeleteCtx(ctx); err != nil {
			return nil, zip.ErrInternal(err.Error())
		}
		return &mutationResult{Affected: true}, nil
	}
}
