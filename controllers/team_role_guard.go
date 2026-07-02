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

package controllers

import (
	"github.com/hanzoai/iam/object"
	"github.com/hanzoai/iam/util"
)

// teamCallerContext derives the authenticated caller for the app-scoped
// team-role guard from the session/JWT — NEVER from the request body. Returns
// nil for an anonymous request.
func (c *ApiController) teamCallerContext() *object.CallerContext {
	user := c.getCurrentUser()
	if user == nil {
		return nil
	}
	return &object.CallerContext{
		UserId:        util.GetId(user.Owner, user.Name),
		Org:           user.Owner,
		IsGlobalAdmin: c.IsGlobalAdmin(),
	}
}

// guardManagedRoleWrite enforces the app-scoped team-role policy on a role or
// invitation mutation. Call it AFTER unmarshaling, BEFORE persisting.
//
// Returns true if the caller may proceed — either because the target is not a
// team-managed catalog role (ordinary authz already ran in ApiFilter), or
// because the caller is authorized for this app+rank+org. On denial it emits
// the standard masked "Unauthorized operation" (never leaking which barrier
// tripped) and returns false. The specific reason is logged server-side for
// audit.
//
//	targetOrg  the org that owns the role (Role.Owner / Invitation.Owner)
//	targetName the role name / catalog key being written
//	newUsers   post-mutation membership (for the org:owner orphan check)
//	isDelete   true for a delete
func (c *ApiController) guardManagedRoleWrite(targetOrg, targetName string, newUsers []string, isDelete bool) bool {
	caller := c.teamCallerContext()
	if caller == nil {
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return false
	}

	managed, allowed, reason := object.AuthorizeManagedRoleWrite(*caller, targetOrg, targetName, newUsers, isDelete)
	if managed && !allowed {
		// Audit the true reason server-side; the client only ever sees the
		// generic denial.
		util.LogInfo(c.Ctx, "team-role guard: DENY caller=%s targetOrg=%s target=%s reason=%s",
			caller.UserId, targetOrg, targetName, reason)
		c.ResponseError(c.T("auth:Unauthorized operation"))
		return false
	}
	return true
}
