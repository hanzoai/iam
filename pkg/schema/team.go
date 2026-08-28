// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package schema

import "github.com/hanzoai/orm"

// Team is a named set of people. Roles and permissions grant to a team, so access
// follows the team rather than each person: add someone and they inherit what the
// team can do.
//
// A team is a set of people and nothing else. WHERE it has privilege is a
// Membership: (team, scope, role), where the scope is an org, a workspace or a
// project. The same team holds different roles in different places, which one
// scope field on the team could not express.
//
// Parent nests one team inside another; the empty string is a top-level team.
// Membership resolves through the chain, so a person in a child team is in its
// parent for grant purposes.
//
// Identity is the (Owner, Name) pair; the orm string key is "owner/name". Users
// carries orm:"serialize" so the column backends persist it through the string
// sibling, matching Role.
type Team struct {
	orm.Model[Team]

	Owner       string `json:"owner"`
	Name        string `json:"name"`
	CreatedTime string `json:"createdTime"`
	DisplayName string `json:"displayName"`
	Description string `json:"description"`

	Organization string `json:"organization"`
	Parent       string `json:"parent"`

	Users  []string `json:"users" orm:"serialize" datastore:"-"`
	Users_ string   `json:"-"`

	IsEnabled bool `json:"isEnabled"`
}
