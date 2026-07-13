// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// Package schema declares the thirteen IAM v2 identity entities on
// hanzoai/orm.
//
// Each entity embeds orm.Model[T] and registers its kind in init(). orm
// stores every entity as one row in a single _entities table keyed by kind —
// there is no per-entity DDL, so "schema" here is the domain model, not a
// migration. Phase 0 carries only the owner/name identity fields; the full
// field set per entity lands in Phase 1 beside the handlers that own it
// (MIGRATION.md §4).
//
// Scope is deliberate: the v1 Casdoor object package has ~32 tables, but the
// Casbin artifacts (adapter, enforcer, model) are replaced by hanzoai/authz
// and the commerce tables (payment, plan, product, subscription) belong to
// other services. Only identity entities live here.
package schema

import "github.com/hanzoai/orm"

// Every IAM entity is owner-scoped (owner = organization) and named uniquely
// within its owner — the (owner, name) pair is the natural key across the
// whole model. Phase 1 adds the per-entity fields on top of these two.

// User is an identity principal (v1 Casdoor `user`). v2 handles password
// hashing and token keys explicitly in Phase 1, not through a framework's
// auth-collection machinery.
type User struct {
	orm.Model[User]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Organization is a tenant boundary (v1 `organization`).
type Organization struct {
	orm.Model[Organization]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Application is an OAuth2/OIDC client (v1 `application`).
type Application struct {
	orm.Model[Application]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Provider is a federated identity / connector config (v1 `provider`).
type Provider struct {
	orm.Model[Provider]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Role is a named grant bundle (v1 `role`).
type Role struct {
	orm.Model[Role]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Permission is a policy grant (v1 `permission`).
type Permission struct {
	orm.Model[Permission]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Cert is a signing/verification certificate (v1 `cert`).
type Cert struct {
	orm.Model[Cert]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Key is an API/access key (v1 `key`).
type Key struct {
	orm.Model[Key]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// WebauthnCredential is a registered passkey (v1 `webauthn_credential`).
type WebauthnCredential struct {
	orm.Model[WebauthnCredential]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Session is an authenticated session (v1 `session`).
type Session struct {
	orm.Model[Session]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Token is an issued OAuth2 token record (v1 `token`).
type Token struct {
	orm.Model[Token]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// AuditLog is an append-only action record (v1 `record`).
type AuditLog struct {
	orm.Model[AuditLog]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Invitation is a pending org membership invite (v1 `invitation`).
type Invitation struct {
	orm.Model[Invitation]
	Owner string `json:"owner"`
	Name  string `json:"name"`
}

// Kinds lists the registered v2 entity kinds in canonical (MIGRATION.md §4)
// order. The drift-compare tool and diagnostics iterate this.
func Kinds() []string {
	return []string{
		"users", "organizations", "applications", "providers",
		"roles", "permissions", "certs", "keys",
		"webauthn_credentials", "sessions", "tokens", "audit_logs",
		"invitations",
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
}
