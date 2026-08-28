// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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

	// The SUBJECT. Exactly one of these is set: a person, or a team of them.
	// Granting to a team keeps access correct as people come and go.
	User string `json:"user" orm:"index"` // the user id, "<homeOrg>/<username>"
	Team string `json:"team" orm:"index"` // the team name, owner-scoped by Org

	// The SCOPE. Org is the tenant and is always set. Workspace narrows the grant
	// to one workspace inside it; Project narrows it further, and requires
	// Workspace. Empty means the whole of the level above, so a row with neither
	// is an org-wide grant.
	//
	// The scope lives here rather than on the team because a team is a set of
	// people and nothing else: the same team holds different roles in different
	// places, and braiding the two would need one team per scope.
	Org       string `json:"org" orm:"index"`
	Workspace string `json:"workspace" orm:"index"`
	Project   string `json:"project" orm:"index"`

	Role string `json:"role"` // owner | admin | member
}

// OrgRef is the lightweight (org, role) projection of a Membership that a token
// carries in its `orgs` claim — the tenancy set a resource server reads to
// authorize an org-switch (X-Org-Id ∈ orgs) with no round-trip. It is the bind
// value ONLY (no storage identity, no orm.Model): Membership is how the relation
// is stored, OrgRef is how it travels in a JWT and how a consumer (cloud's
// SanitizeIdentity) decodes it. The JSON tags (`org`, `role,omitempty`) are the
// fixed claim contract — a token minted here and read by a consumer round-trips
// byte-for-byte. It is exported to consumers as model.OrgRef (pkg/model), the ONE
// place external services import it from; there is no second copy.
type OrgRef struct {
	Org  string `json:"org"`
	Role string `json:"role,omitempty"`
}

// AsOrgRef projects a Membership onto its claim-side (org, role) reference — the
// ONE way to turn a stored membership into the value a token emits.
func (m *Membership) AsOrgRef() OrgRef {
	return OrgRef{Org: m.Org, Role: m.Role}
}

// OrgRefsFromMemberships projects a membership set onto the `orgs` claim slice a
// token carries. A nil/empty set yields a nil slice so the claim is omitted, not
// emitted empty.
func OrgRefsFromMemberships(ms []*Membership) []OrgRef {
	if len(ms) == 0 {
		return nil
	}
	out := make([]OrgRef, 0, len(ms))
	for _, m := range ms {
		if m != nil {
			out = append(out, m.AsOrgRef())
		}
	}
	return out
}
