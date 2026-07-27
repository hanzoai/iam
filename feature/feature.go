// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package feature is the seam enterprise capabilities plug into. A module
// (hanzoiam/scim, saml, ldap, …) implements Feature and reads/writes the core's
// identity via the injected Store — so it shares ONE identity store with the core
// and never carries a second copy. The core NEVER imports a module; dependency
// flows one way (module → feature).
package feature

import (
	"context"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/model"
)

// Store is the identity surface a feature needs — the union of the calls the
// copied Casdoor code makes (object.* → store.*). The core implements it over its
// orm store (internal/featurestore). A feature ignores methods it doesn't use.
type Store interface {
	GetUser(ctx context.Context, owner, name string) (*model.User, error)
	GetUserByID(ctx context.Context, id string) (*model.User, error)
	GetGlobalUsers(ctx context.Context, offset, limit int) ([]*model.User, int, error)
	AddUser(ctx context.Context, u *model.User) (bool, error)
	UpdateUser(ctx context.Context, u *model.User) (bool, error)
	DeleteUser(ctx context.Context, owner, name string) (bool, error)
	GetApplication(ctx context.Context, id string) (*model.Application, error)
	GetOrganization(ctx context.Context, name string) (*model.Organization, error)
	// GetProvider resolves an identity provider by (owner, name) — the SP-inbound
	// SAML/OAuth surface (a user signing in through a corporate IdP where Hanzo is
	// the Service Provider). SAML SP-initiated login reads its IdP config from here.
	GetProvider(ctx context.Context, owner, name string) (*model.Provider, error)
	// GetCert resolves a signing cert by (owner, name) — SAML metadata signing, etc.
	GetCert(ctx context.Context, owner, name string) (*model.Cert, error)
	// SetPassword sets a user's password: the core hashes the plaintext exactly
	// once and stores only the one-way digest (never the clear text). Used by SCIM
	// to provision the `password` attribute. An empty plaintext leaves the digest
	// untouched. Hashing lives in ONE place (the core) — a module never sees a hash.
	SetPassword(ctx context.Context, owner, name, plaintext string) (bool, error)
	// VerifyPassword reports whether plaintext matches the user's stored digest
	// (argon2id for migrated v1 rows, bcrypt for v2, per the org's password type).
	// Used by LDAP bind — verification stays in the core, never in a module.
	VerifyPassword(ctx context.Context, owner, name, plaintext string) (bool, error)
}

// Feature is one pluggable enterprise capability. Route registers its routes on
// the shared app, backed by store. Name is for diagnostics.
type Feature interface {
	Name() string
	Route(app *zip.App, store Store) error
}

var registry []Feature

// Register adds a feature to the set RouteAll registers. Called by the composing
// binary (cloud) or a module init — the core decides which enterprise features ship.
func Register(f Feature) { registry = append(registry, f) }

// Registered returns the registered features (diagnostics/tests).
func Registered() []Feature { return append([]Feature(nil), registry...) }

// RouteAll registers every registered feature on app with store, fail-fast: a
// registered-but-broken enterprise module surfaces loudly at boot, never a silent no-op.
func RouteAll(app *zip.App, store Store) error {
	for _, f := range registry {
		if err := f.Route(app, store); err != nil {
			return err
		}
	}
	return nil
}
