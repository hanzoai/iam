// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package schema declares the IAM v2 identity entities on hanzoai/orm.
//
// Thirteen mirror a v1 Casdoor table one-for-one (MIGRATION.md §4) and are the
// ones the drift-compare tool reconciles. Membership is the fourteenth and has
// no v1 counterpart to compare against: the tenancy relation that lets one
// identity act in several orgs is new here, so it is absent from compare's
// mapping by design, not by omission.
//
// Each entity embeds orm.Model[T]; every kind is registered exactly once in
// this file's init(). orm stores every entity as one row in a single
// _entities table keyed by kind — there is no per-entity DDL, so "schema"
// here is the domain model, not a migration. Phase 1 carries the full field
// set per entity, each in its own file beside the handlers that own it
// (MIGRATION.md §4); the (owner, name) pair is the natural key across the
// whole model.
//
// Registration is centralized here — one place, one way. The per-entity
// files declare only the struct (and its nested value types); they add no
// second orm.Register call, which would panic on a duplicate kind.
//
// Scope is deliberate: the v1 Casdoor object package has ~32 tables, but the
// Casbin artifacts (adapter, enforcer, model) are replaced by hanzoai/authz
// and the commerce tables (payment, plan, product, subscription) belong to
// other services. Only identity entities live here.
package schema

import "github.com/hanzoai/orm"

// Kinds lists the registered v2 entity kinds in canonical (MIGRATION.md §4)
// order. The drift-compare tool and diagnostics iterate this.
func Kinds() []string {
	return []string{
		"users", "organizations", "applications", "providers",
		"roles", "permissions", "certs", "keys",
		"webauthn_credentials", "sessions", "tokens", "audit_logs",
		"invitations", "memberships",
	}
}

func init() {
	orm.Register[User]("users")
	orm.Register[Organization]("organizations")
	orm.Register[Application]("applications")
	orm.Register[Provider]("providers")
	orm.Register[Role]("roles")
	orm.Register[Permission]("permissions")
	orm.Register[Cert]("certs")
	orm.Register[Key]("keys")
	orm.Register[WebauthnCredential]("webauthn_credentials")
	orm.Register[Session]("sessions")
	orm.Register[Token]("tokens")
	orm.Register[AuditLog]("audit_logs")
	orm.Register[Invitation]("invitations")
	orm.Register[Membership]("memberships")
}
