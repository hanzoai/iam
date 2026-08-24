// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package feature is the seam enterprise capabilities plug into. A module
// (hanzoiam/saml, hanzoiam/ldap, …) implements Feature and reads/writes the core's
// identity via the injected Store — so it shares ONE identity store with the core
// and never carries a second copy. The core NEVER imports a module; dependency
// flows one way (module → feature).
//
// What belongs OUT here is PROVENANCE, and only provenance: this tree is
// clean-room (see TestCasdoorLineageRetracted), so a capability whose
// implementation is Casdoor-derived stays in a hanzoiam/* module carrying its own
// Apache-2.0 attribution — SAML's IdP protocol code and LDAP's directory server
// both are. A capability written fresh belongs IN the core, where the Guard,
// principal.Scope and authz.Can cover it without a module having to reimplement them:
// SCIM is served there (internal/scim, at /v1/iam/scim/v2), never through this seam.
//
// A module gets NO authorization for free. IAM's Guard is anchored in IAM's own
// subtree (internal/routes.Route), so a module that registers anywhere else is
// unauthenticated — the one thing a Feature must get right on its own.
package feature

import (
	"context"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/model"
)

// Store is the identity surface a feature needs — the union of the calls the
// copied the legacy surface code makes (object.* → store.*). The core implements it over its
// orm store (internal/featurestore). A feature ignores methods it doesn't use.
type Store interface {
	GetUser(ctx context.Context, owner, name string) (*model.User, error)
	// GetUserByID resolves a user by model.User.Id — the stable opaque UUID the
	// OIDC `sub` carries, which AddUser mints server-side and UpdateUser carries
	// forward. It is the id a module hands back to a client as the user's stable
	// handle, so it must be THIS value and never the orm storage id, which differs
	// per row and is mutable for migrated rows. Returns (nil, nil) when no user
	// matches.
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
	// once and stores only the one-way digest (never the clear text). An empty
	// plaintext leaves the digest untouched. Hashing lives in ONE place (the core) —
	// a module never sees a hash, and never grows its own.
	SetPassword(ctx context.Context, owner, name, plaintext string) (bool, error)
	// VerifyPassword reports whether plaintext matches the user's stored digest
	// (argon2id for migrated v1 rows, bcrypt for v2, per the org's password type).
	// Used by LDAP bind — verification stays in the core, never in a module.
	VerifyPassword(ctx context.Context, owner, name, plaintext string) (bool, error)
}

// Feature is one pluggable enterprise capability. Route activates it against the
// shared app, backed by store. Name is for diagnostics.
//
// Route is really "activate", and the name is honest for only one of the two
// modules: hanzoiam/saml registers HTTP routes on app, while hanzoiam/ldap takes
// app as `_` and binds its own TCP listeners — same hook, no routes. Rename it to
// Start when this seam first grows a composing binary; it has none today, so the
// rename is free then and a coordinated three-repo break now.
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
