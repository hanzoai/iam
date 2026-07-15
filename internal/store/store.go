// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package store is the IAM v2 object layer: thin, typed reads over hanzoai/orm
// against the Phase-1 entities. It replaces the v1 xorm ormer.Engine fluent
// calls with orm.TypedQuery, so handlers depend on named operations
// (GetApplicationByClientId, GetProvider, …) rather than a query builder.
//
// Every function takes a context and an orm.DB — one storage abstraction,
// backend-agnostic (sqlite / hanzoai/sql / hanzoai/datastore).
package store

import (
	"context"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
)

// GetApplicationByClientId resolves an OAuth2/OIDC client by its clientId.
// Returns (nil, nil) when no application matches (a not-found is not an error
// at this layer — the handler decides the response).
func GetApplicationByClientId(_ context.Context, db orm.DB, clientId string) (*schema.Application, error) {
	if clientId == "" {
		return nil, nil
	}
	app, err := orm.TypedQuery[schema.Application](db).Filter("ClientId=", clientId).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return app, err
}

// GetApplicationByName resolves an application by (owner, name).
func GetApplicationByName(_ context.Context, db orm.DB, owner, name string) (*schema.Application, error) {
	app, err := orm.TypedQuery[schema.Application](db).
		Filter("Owner=", owner).Filter("Name=", name).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return app, err
}

// GetProvider resolves a provider record by (owner, name) — e.g.
// ("admin", "provider-github"). Providers are shared org-level records the
// application's ProviderItem links to by name.
func GetProvider(_ context.Context, db orm.DB, owner, name string) (*schema.Provider, error) {
	p, err := orm.TypedQuery[schema.Provider](db).
		Filter("Owner=", owner).Filter("Name=", name).First()
	if err == orm.ErrNotFound {
		return nil, nil
	}
	return p, err
}

// EnrichProviders resolves each of the application's ProviderItem links to its
// shared Provider record (Category/Type/ClientId), attaching it to
// item.Provider. A link whose provider record is missing is left with a nil
// Provider (the caller treats that as unconfigured — never a dead-end button).
func EnrichProviders(ctx context.Context, db orm.DB, app *schema.Application) {
	if app == nil {
		return
	}
	for _, item := range app.Providers {
		if item == nil || item.Name == "" {
			continue
		}
		owner := item.Owner
		if owner == "" {
			owner = "admin" // providers are seeded under the admin org
		}
		if p, err := GetProvider(ctx, db, owner, item.Name); err == nil && p != nil {
			item.Provider = p
		}
	}
}
