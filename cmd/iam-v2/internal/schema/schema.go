// Package schema declares the 13 canonical IAM v2 collections.
//
// Each Register call is idempotent: if a collection with the same name
// already exists it is left alone; otherwise it is created. Re-running
// Register against a healthy database is a no-op.
//
// Phase 0 scope: collection *names* only. Fields and indexes land in
// Phase 1 alongside the handlers that own them, per resource. The point
// of this file is to claim the namespace so MIGRATION.md's mapping is
// observable in the running binary — not to ship the final schema.
//
// See MIGRATION.md §4 for the domain model mapping rationale (v1 xorm
// object → v2 Base collection).
package schema

import (
	"github.com/hanzoai/base/core"
)

// names is the canonical list of v2 collections, in the order they
// appear in MIGRATION.md §4. Order is presentational only; Base does
// not require topological ordering on save.
var names = []string{
	"users",
	"organizations",
	"applications",
	"providers",
	"roles",
	"permissions",
	"certs",
	"keys",
	"webauthn_credentials",
	"sessions",
	"tokens",
	"audit_logs",
	"invitations",
}

// authCollections must be created as auth collections (so Base wires
// up the password/tokenKey/email machinery). Today this is just
// "users"; Phase 1 may add a service-account collection.
var authCollections = map[string]bool{
	"users": true,
}

// Register declares every IAM v2 collection on the given Base app.
//
// Called once at bootstrap from cmd/iam-v2/main.go via OnBootstrap.
// Safe to call repeatedly; only missing collections are created.
func Register(app core.App) error {
	for _, name := range names {
		existing, _ := app.FindCollectionByNameOrId(name)
		if existing != nil {
			continue
		}
		var c *core.Collection
		if authCollections[name] {
			c = core.NewAuthCollection(name)
		} else {
			c = core.NewBaseCollection(name)
		}
		if err := app.Save(c); err != nil {
			return err
		}
	}
	return nil
}
