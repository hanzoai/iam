// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Permission is a policy grant: it binds a set of subjects (users, groups,
// roles, domains) to a set of actions over a set of resources with an
// allow/deny effect, evaluated against a named authz model and adapter. It is
// the v2 form of the v1 `permission` table (kind "permissions").
//
// Identity is the (Owner, Name) pair: Owner is the organization that holds the
// grant, Name is unique within that owner. Every other field is authorization
// state, so the port is deliberately field-complete against v1 — a dropped
// column silently widens or narrows access.
//
// The orm tag on each field preserves the v1 column spec for storage parity;
// slices persist natively as JSON arrays in the orm entity document.
type Permission struct {
	orm.Model[Permission]

	// Identity — the (owner, name) natural key.
	Owner string `json:"owner" orm:"varchar(100) notnull pk"`
	Name  string `json:"name" orm:"varchar(100) notnull pk"`

	// Descriptive metadata.
	CreatedTime string `json:"createdTime" orm:"varchar(100)"`
	DisplayName string `json:"displayName" orm:"varchar(100)"`
	Description string `json:"description" orm:"varchar(100)"`

	// Subjects the grant is evaluated for.
	Users   []string `json:"users" orm:"mediumtext"`
	Groups  []string `json:"groups" orm:"mediumtext"`
	Roles   []string `json:"roles" orm:"mediumtext"`
	Domains []string `json:"domains" orm:"mediumtext"`

	// Authorization model, targets, and decision. AuthzModel carries the v1
	// `model` column (the named authz model); it is not the Go identifier
	// `Model` because that name is taken by the embedded orm.Model[Permission]
	// mixin. The HTTP contract is unchanged — json:"model".
	AuthzModel   string   `json:"model" orm:"varchar(100)"`
	Adapter      string   `json:"adapter" orm:"varchar(100)"`
	ResourceType string   `json:"resourceType" orm:"varchar(100)"`
	Resources    []string `json:"resources" orm:"mediumtext"`
	Actions      []string `json:"actions" orm:"mediumtext"`
	Effect       string   `json:"effect" orm:"varchar(100)"`
	IsEnabled    bool     `json:"isEnabled" orm:"default:false"`

	// Submission / approval workflow.
	Submitter   string `json:"submitter" orm:"varchar(100)"`
	Approver    string `json:"approver" orm:"varchar(100)"`
	ApproveTime string `json:"approveTime" orm:"varchar(100)"`
	State       string `json:"state" orm:"varchar(100)"`
}
