// Copyright 2026 The Hanzo Authors. All Rights Reserved.
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

// The org-membership REST surface — the Slack-workspace tenancy contract.
//
// Membership(User × Org × Role) is what the JWT mints as the `orgs` claim; this
// controller is the LIVE query + invite write for the same relation, so a
// product (hanzo.team) can enumerate a user's orgs mid-session and record an
// invite without waiting for the next token mint. One relation, two transports:
// the claim is the mint-time snapshot, get-memberships is the live read,
// add/delete-membership is the one write path (EnsureMembership /
// DeleteMembership underneath — the same functions every org-birth path uses).
//
// Authorization (per endpoint, controller-enforced; the Casbin layer only
// requires a signed-in principal):
//   - a user may read their OWN membership set (self);
//   - an org admin may read their org's roster and invite/remove members of
//     THAT org (owner==org && IsAdmin);
//   - a platform super admin may do anything;
//   - an app/<name> M2M principal may act only when allowlisted under
//     IAM_MEMBERSHIP_ADMIN_APPS (CapMembershipAdmin, fail-secure deny-all);
//     tenant isolation is then enforced by that trusted caller (the CapKeyMint
//     trust model).
package controllers

import (
	"encoding/json"
	"fmt"

	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// membershipForm is the add/delete-membership body: the (user, org) pair plus
// the coarse role for add. It deliberately carries no owner/name — the natural
// key is derived in object.EnsureMembership, never client-supplied.
type membershipForm struct {
	User string `json:"user"` // full user id "<homeOrg>/<name>"
	Org  string `json:"org"`  // org slug the user may act in
	Role string `json:"role"` // owner | admin | member (add only; default member)
}

// validMembershipRole reports whether role is one of the coarse tenancy roles.
func validMembershipRole(role string) bool {
	switch role {
	case object.MembershipRoleOwner, object.MembershipRoleAdmin, object.MembershipRoleMember:
		return true
	}
	return false
}

// membershipAllowed is the ONE authorization rule for acting on org's
// membership plane (roster read, invite, remove). Self-reads are authorized
// separately in GetMemberships.
func (c *ApiController) membershipAllowed(org string) bool {
	username := c.GetSessionUsername()
	if object.IsAppUser(username) {
		return object.AppAllowedForCapability(username, object.CapMembershipAdmin)
	}
	if c.IsSuperAdmin() {
		return true
	}
	if cu := c.getCurrentUser(); cu != nil && cu.IsAdmin && cu.Owner == org {
		return true
	}
	return false
}

// GetMemberships ...
// @Title GetMemberships
// @Tag Membership API
// @Description get the org-membership relation, projected by user or by org
// @Param   user   query   string  false  "full user id <org>/<name>: the user's org set (same shape as the JWT `orgs` claim)"
// @Param   org    query   string  false  "org slug: the org's member roster"
// @Success 200 {array} object.OrgRef (user projection) or {array} object.Membership (org projection)
// @router /get-memberships [get]
func (c *ApiController) GetMemberships() {
	userId := c.Ctx.Input.Query("user")
	org := c.Ctx.Input.Query("org")

	switch {
	case userId != "" && org == "":
		// A user's org set. Self is always allowed; anyone else needs the
		// admin rule against the user's HOME org (their admin may see which
		// team orgs a user was invited into).
		homeOrg, _, err := util.GetOwnerAndNameFromIdWithError(userId)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if c.GetSessionUsername() != userId && !c.membershipAllowed(homeOrg) {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return
		}
		user, err := object.GetUser(userId)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		if user == nil {
			c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), userId))
			return
		}
		c.ResponseOk(object.MemberOrgRefs(user))
	case org != "" && userId == "":
		// The org roster: every explicit membership row. Home members are
		// backfilled as rows on boot + at signup, so the roster is the table.
		if !c.membershipAllowed(org) {
			c.ResponseError(c.T("auth:Unauthorized operation"))
			return
		}
		memberships, err := object.GetMembershipsByOrg(org)
		if err != nil {
			c.ResponseError(err.Error())
			return
		}
		c.ResponseOk(memberships)
	default:
		c.ResponseError("exactly one of ?user= or ?org= is required")
	}
}

// AddMembership ...
// @Title AddMembership
// @Tag Membership API
// @Description record that a user may act in an org (the invite write)
// @Param   body    body   controllers.membershipForm  true  "{user, org, role}"
// @Success 200 {object} controllers.Response The Response object
// @router /add-membership [post]
func (c *ApiController) AddMembership() {
	// Defense in depth: the route filter already gated app principals on
	// CapMembershipAdmin (object/app_route_authz.go); re-check here.
	if !c.requireAppCapability(object.CapMembershipAdmin) {
		return
	}

	var form membershipForm
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &form); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if form.User == "" || form.Org == "" {
		c.ResponseError("user and org are required")
		return
	}
	if form.Role == "" {
		form.Role = object.MembershipRoleMember
	}
	if !validMembershipRole(form.Role) {
		c.ResponseError("role must be owner, admin or member")
		return
	}
	if !c.membershipAllowed(form.Org) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	// Both ends of the relation must exist: a dangling row would mint nothing
	// (the claim resolver joins through User) but would still pollute rosters.
	user, err := object.GetUser(form.User)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if user == nil {
		c.ResponseError(fmt.Sprintf(c.T("general:The user: %s doesn't exist"), form.User))
		return
	}
	organization, err := object.GetOrganization(util.GetId("admin", form.Org))
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	if organization == nil {
		c.ResponseError(fmt.Sprintf(c.T("auth:The organization: %s does not exist"), form.Org))
		return
	}

	added, err := object.EnsureMembership(form.User, form.Org, form.Role)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(added)
}

// DeleteMembership ...
// @Title DeleteMembership
// @Tag Membership API
// @Description revoke a user's ability to act in an org
// @Param   body    body   controllers.membershipForm  true  "{user, org}"
// @Success 200 {object} controllers.Response The Response object
// @router /delete-membership [post]
func (c *ApiController) DeleteMembership() {
	if !c.requireAppCapability(object.CapMembershipAdmin) {
		return
	}

	var form membershipForm
	if err := json.Unmarshal(c.Ctx.Input.RequestBody, &form); err != nil {
		c.ResponseError(err.Error())
		return
	}
	if form.User == "" || form.Org == "" {
		c.ResponseError("user and org are required")
		return
	}
	if !c.membershipAllowed(form.Org) {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return
	}

	// Removing the HOME org row is a no-op for tenancy (MemberOrgRefs always
	// unions the home org back in), so it is allowed but changes nothing.
	affected, err := object.DeleteMembership(form.User, form.Org)
	if err != nil {
		c.ResponseError(err.Error())
		return
	}
	c.ResponseOk(affected)
}
