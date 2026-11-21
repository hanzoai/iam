// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Role is a named grant bundle (v1 Casdoor `role`, v2 kind "roles"). It gathers
// principals — direct users, member groups, and nested sub-roles — under an
// owner-scoped name, optionally partitioned by domain, and is dereferenced by
// permissions to resolve a principal's effective grants. Identity is the
// (Owner, Name) pair; the orm string key is "owner/name".
//
// The membership lists carry orm:"serialize" so the column backends
// (hanzoai/sql, hanzoai/datastore) persist them through their string siblings;
// the default SQLite store round-trips the arrays inside the entity JSON blob
// and leaves the siblings empty.
type Role struct {
	orm.Model[Role]

	Owner       string `json:"owner"`
	Name        string `json:"name"`
	CreatedTime string `json:"createdTime"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`

	Users    []string `json:"users" orm:"serialize" datastore:"-"`
	Users_   string   `json:"-"`
	Groups   []string `json:"groups" orm:"serialize" datastore:"-"`
	Groups_  string   `json:"-"`
	Roles    []string `json:"roles" orm:"serialize" datastore:"-"`
	Roles_   string   `json:"-"`
	Domains  []string `json:"domains" orm:"serialize" datastore:"-"`
	Domains_ string   `json:"-"`

	IsEnabled bool `json:"isEnabled"`
}
