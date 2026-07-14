// Copyright 2025 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"fmt"

	"github.com/hanzoai/iam/util"
)

// Membership records that a user may ACT IN an org — the (User × Org × Role)
// relation that lets ONE identity belong to its personal org AND team orgs. It
// is the tenancy set the JWT emits as the `orgs` claim, against which the edge
// authorizes an org-switch (X-Org-Id ∈ orgs) with no round-trip.
//
// It is orthogonal to the Role/Permission catalog: Membership answers "which
// orgs may this identity act in, and with what COARSE role (owner|admin|member)",
// while Role/Permission answer fine-grained authorization WITHIN an org. A user's
// HOME org (User.Owner) is always an implicit membership; explicit rows add the
// TEAM orgs the user has been invited into.
//
// Like every org row it is owned by the platform ("admin"); the natural key
// (Owner, Name) uses Name = "<userId>|<org>" so a (user, org) pair is unique. The
// User and Org columns are the hot lookup paths and stay indexed.
type Membership struct {
	Owner       string `xorm:"varchar(100) notnull pk" json:"owner"`
	Name        string `xorm:"varchar(255) notnull pk" json:"name"`
	CreatedTime string `xorm:"varchar(100)" json:"createdTime"`

	User string `xorm:"varchar(150) index" json:"user"` // the user id, "<homeOrg>/<username>"
	Org  string `xorm:"varchar(100) index" json:"org"`  // the org slug the user may act in
	Role string `xorm:"varchar(100)" json:"role"`       // coarse org role: owner | admin | member
}

// membershipOwner is the platform owner of every membership row, matching how
// every org/project/role row is owned by the reserved "admin" org.
const membershipOwner = "admin"

// Coarse membership roles. These are the tenancy roles (who may administer the
// org), NOT the fine-grained authz roles in the Role catalog.
const (
	MembershipRoleOwner  = "owner"
	MembershipRoleAdmin  = "admin"
	MembershipRoleMember = "member"
)

// membershipName builds the (user, org) natural-key Name. It is deterministic so
// EnsureMembership is idempotent on the pair; the value is never parsed back (the
// User and Org columns are queried directly), so the embedded "/" in userId is
// harmless.
func membershipName(userId, org string) string {
	return userId + "|" + org
}

// GetMembershipsByUser returns every org a user may act in — the explicit team
// memberships. The caller unions the user's HOME org (memberOrgRefs) so the token
// set is complete even before any team is joined.
func GetMembershipsByUser(userId string) ([]*Membership, error) {
	if userId == "" {
		return nil, nil
	}
	memberships := []*Membership{}
	err := ormer.Engine.Where("user = ?", userId).Find(&memberships)
	if err != nil {
		return nil, err
	}
	return memberships, nil
}

// GetMembershipsByOrg returns every user who may act in an org — the org's roster.
func GetMembershipsByOrg(org string) ([]*Membership, error) {
	if org == "" {
		return nil, nil
	}
	memberships := []*Membership{}
	err := ormer.Engine.Where("org = ?", org).Find(&memberships)
	if err != nil {
		return nil, err
	}
	return memberships, nil
}

// getMembership returns one (user, org) membership, or nil when absent.
func getMembership(userId, org string) (*Membership, error) {
	if userId == "" || org == "" {
		return nil, nil
	}
	m := Membership{Owner: membershipOwner, Name: membershipName(userId, org)}
	existed, err := ormer.Engine.Get(&m)
	if err != nil {
		return nil, err
	}
	if existed {
		return &m, nil
	}
	return nil, nil
}

// AddMembership inserts a membership row.
func AddMembership(m *Membership) (bool, error) {
	if m.CreatedTime == "" {
		m.CreatedTime = util.GetCurrentTime()
	}
	affected, err := ormer.Engine.Insert(m)
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

// newMembership builds a membership row for (userId, org, role).
func newMembership(userId, org, role string) *Membership {
	return &Membership{
		Owner:       membershipOwner,
		Name:        membershipName(userId, org),
		CreatedTime: util.GetCurrentTime(),
		User:        userId,
		Org:         org,
		Role:        role,
	}
}

// EnsureMembership records that userId may act in org with the given role. It is
// the ONE way a membership is created — composed into every org-birth path and
// the boot backfill. Idempotent: it ADDS a row only when the (user, org) pair is
// absent, and never downgrades an existing role (an existing owner stays owner
// even if re-ensured as member). Returns whether it created a row.
func EnsureMembership(userId, org, role string) (bool, error) {
	if userId == "" || org == "" {
		return false, nil
	}
	existing, err := getMembership(userId, org)
	if err != nil {
		return false, err
	}
	if existing != nil {
		return false, nil
	}
	return AddMembership(newMembership(userId, org, role))
}

// DeleteMembership removes a user from an org (revokes the ability to act in it).
func DeleteMembership(userId, org string) (bool, error) {
	affected, err := ormer.Engine.ID(PK{membershipOwner, membershipName(userId, org)}).Delete(&Membership{})
	if err != nil {
		return false, err
	}
	return affected != 0, nil
}

// BackfillMemberships records the HOME-org membership for every user that lacks
// one. One-shot, idempotent and live-safe — safe to run on every boot: users
// already carrying their home membership are skipped and no existing row is
// touched. It seeds ONLY the home org (User.Owner); team memberships are added
// explicitly. Returns the number of rows created.
func BackfillMemberships() (int, error) {
	users := []*User{}
	if err := ormer.Engine.Cols("owner", "name", "is_admin").Find(&users); err != nil {
		return 0, err
	}
	created := 0
	for _, user := range users {
		if user.Owner == "" || user.Name == "" {
			continue
		}
		added, err := EnsureMembership(user.GetId(), user.Owner, homeRole(user))
		if err != nil {
			return created, fmt.Errorf("backfill membership for user %q: %w", user.GetId(), err)
		}
		if added {
			created++
		}
	}
	if created > 0 {
		fmt.Printf("[backfill-membership] created=%d\n", created)
	}
	return created, nil
}

// homeRole is a user's coarse role in their OWN home org: an org admin owns it,
// otherwise they are a plain member. (Platform SuperAdmins live in the reserved
// "admin" org and are owners of it.)
func homeRole(user *User) string {
	if user.IsAdmin {
		return MembershipRoleAdmin
	}
	return MembershipRoleMember
}
