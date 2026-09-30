// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Tombstone holds the name of a deleted organization. An org's name is the tenant
// key across the estate (commerce's namespace and balance, KMS's /orgs/<org>/,
// per-org data), so deleting the org never frees it: whoever founded the name next
// would inherit everything keyed by it. The tombstone keeps the name taken until a
// SuperAdmin releases it, which is refused while anything keyed by the name remains.
type Tombstone struct {
	orm.Model[Tombstone]

	Owner       string `json:"owner"` // the admin registry, as for organizations
	Name        string `json:"name"`  // the organization's name
	CreatedTime string `json:"createdTime"`
	// Founder carries the deleted org's founder, so an org counted against its
	// founder's cap stays counted after it is deleted.
	Founder string `json:"founder,omitempty"`
}
