// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import "github.com/hanzoai/orm"

// Membership records that a user may ACT IN an org — the (User × Org × Role)
// relation that lets ONE identity belong to its personal org AND to team orgs.
// It is the tenancy set a token emits as the `orgs` claim, against which the
// edge authorizes an org-switch (X-Org-Id ∈ orgs) with no round-trip.
//
// It is orthogonal to the Role/Permission catalog: Membership answers "which
// orgs may this identity act in, and with what COARSE role", while
// Role/Permission answer fine-grained authorization WITHIN an org. A user's HOME
// org (User.Owner) is always an implicit membership; explicit rows add the team
// orgs the user was invited into.
//
// Like every tenant-registry row it is owned by the platform ("admin"); the
// natural key (Owner, Name) uses Name = "<userId>|<org>", so a (user, org) pair
// is unique by construction and Ensure is idempotent without a read-modify-write
// race. The User and Org columns are the hot lookup paths and stay indexed.
type Membership struct {
	orm.Model[Membership]

	Owner       string `json:"owner"`
	Name        string `json:"name"`
	CreatedTime string `json:"createdTime"`

	User string `json:"user" orm:"index"` // the user id, "<homeOrg>/<username>"
	Org  string `json:"org" orm:"index"`  // the org slug the user may act in
	Role string `json:"role"`             // coarse org role: owner | admin | member
}
