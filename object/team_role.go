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

package object

import (
	"github.com/hanzoai/iam/conf"
	"github.com/hanzoai/iam/teamrole"
	"github.com/hanzoai/iam/util"
)

// This file is the IAM-side bridge for the app-scoped team-role policy defined
// in package teamrole. It does three things:
//
//  1. Materializes the canonical catalog into per-org Role + Permission rows
//     (EnsureTeamRolesForOrg) — idempotent, safe to call repeatedly.
//  2. Derives the catalog role keys a caller actually holds in an org
//     (GetUserTeamRoleKeys) — the input to the pure guard.
//  3. Authorizes a role mutation server-side (AuthorizeManagedRoleWrite) — the
//     single choke point the role + invitation controllers call before any
//     add/update/delete of a managed role. Roles live co-mingled on the global
//     db keyed only by Owner, so this is the ONLY thing standing between a
//     crafted request and cross-org / privilege-escalating role changes.

// CallerContext is the authenticated caller's identity, derived by the
// controller from the session/JWT — NEVER from the request body.
type CallerContext struct {
	UserId        string // "org/name"
	Org           string // caller's org (User.Owner)
	IsGlobalAdmin bool   // platform superuser
}

// TeamRoleFor builds (does not persist) the IAM Role row for a catalog role in
// an org. Pure: no DB, unit-testable. Role.Name is the exact catalog key so the
// guard, the client, and storage all speak one identifier.
func TeamRoleFor(org string, r teamrole.Role) *Role {
	return &Role{
		Owner:       org,
		Name:        r.Key,
		CreatedTime: util.GetCurrentTime(),
		DisplayName: r.DisplayName,
		Description: r.Description,
		Users:       []string{},
		Groups:      []string{},
		Roles:       []string{},
		Domains:     []string{},
		IsEnabled:   true,
	}
}

// TeamPermissionFor builds (does not persist) the Casbin Permission row that
// binds a catalog role to its resource+actions, so downstream surfaces can call
// /v1/iam/enforce for app-scope checks. Pure: no DB. Mirrors the proven
// initAdminPermission shape (Effect Allow, Approved) but is role-bound and
// org-scoped.
func TeamPermissionFor(org string, r teamrole.Role) *Permission {
	return &Permission{
		Owner:        org,
		Name:         r.Key + "-permission",
		CreatedTime:  util.GetCurrentTime(),
		DisplayName:  r.DisplayName + " Permission",
		Description:  r.Description,
		Users:        []string{},
		Groups:       []string{},
		Roles:        []string{util.GetId(org, r.Key)},
		Domains:      []string{},
		Model:        conf.AdminOrg + "/" + AdminUserModelName(),
		Adapter:      "",
		ResourceType: "Custom",
		Resources:    []string{r.Resource},
		Actions:      r.Actions,
		Effect:       "Allow",
		IsEnabled:    true,
		Submitter:    conf.AdminUser,
		Approver:     conf.AdminUser,
		ApproveTime:  util.GetCurrentTime(),
		State:        "Approved",
	}
}

// EnsureTeamRolesForOrg idempotently seeds the app-scoped role catalog (and the
// bound Casbin permissions) for an org. It creates only what is missing, so it
// is safe to call on org creation and again on demand. Role creation is the
// hard requirement (membership + the guard depend on it); permission creation
// is best-effort defense-in-depth for the enforce path and never blocks role
// seeding.
func EnsureTeamRolesForOrg(org string) error {
	if org == "" {
		return nil
	}
	for _, r := range teamrole.Catalog() {
		existing, err := getRole(org, r.Key)
		if err != nil {
			return err
		}
		if existing == nil {
			if _, err := AddRole(TeamRoleFor(org, r)); err != nil {
				return err
			}
		}
		// Permission is best-effort: a Casbin validation hiccup must not leave
		// the org without its roles. The guard does not depend on it.
		perm, err := getPermission(org, r.Key+"-permission")
		if err == nil && perm == nil {
			_, _ = AddPermission(TeamPermissionFor(org, r))
		}
	}
	return nil
}

// GetUserTeamRoleKeys returns the catalog role keys the user holds within a
// given org. Only roles owned by `org` whose membership includes the user AND
// whose Name is a managed catalog key are returned. This is the caller's
// effective authority, fed into teamrole.CheckAssignment.
func GetUserTeamRoleKeys(userId, org string) ([]string, error) {
	roles, err := getRolesByUser(userId)
	if err != nil {
		return nil, err
	}
	keys := []string{}
	for _, role := range roles {
		if role.Owner != org {
			continue // never let another org's roles confer authority here
		}
		if teamrole.IsManaged(role.Name) {
			keys = append(keys, role.Name)
		}
	}
	return keys, nil
}

// AuthorizeManagedRoleWrite is the server-side authorization choke point for a
// single role mutation (add / update / delete). Contract:
//
//	managed=false            -> the target is not a team-managed role; the
//	                            caller proceeds with ordinary authz unchanged.
//	managed=true, allowed=false -> DENY (reason is safe to log).
//	managed=true, allowed=true  -> the mutation is authorized.
//
// newUsers is the post-mutation membership (Role.Users) for add/update; it is
// used only for the org:owner orphan check. isDelete marks a delete.
//
// It fails CLOSED: any error deriving the caller's authority denies.
func AuthorizeManagedRoleWrite(caller CallerContext, targetOrg, targetName string, newUsers []string, isDelete bool) (managed bool, allowed bool, reason string) {
	if !teamrole.IsManaged(targetName) {
		return false, true, ""
	}

	// Platform superuser: always authorized for managed roles and exempt from
	// the orphan net (they can repair). Short-circuit BEFORE any DB lookup so a
	// superuser can never be blocked by a transient failure resolving their
	// authority. Mirrors teamrole.CheckAssignment's superuser bypass.
	if caller.IsGlobalAdmin {
		return true, true, ""
	}

	// Orphan protection: never let the LAST org:owner be removed or emptied,
	// which would strand the org with no owner. Applies even to an org:owner
	// acting on itself.
	if targetName == catalogOrgOwner().Key {
		if isDelete || len(newUsers) == 0 {
			return true, false, "team: refusing to remove the last org owner"
		}
	}

	callerKeys, err := GetUserTeamRoleKeys(caller.UserId, caller.Org)
	if err != nil {
		return true, false, "team: cannot resolve caller authority: " + err.Error()
	}

	err = teamrole.CheckAssignment(teamrole.Assignment{
		CallerKeys:          callerKeys,
		CallerOrg:           caller.Org,
		CallerIsGlobalAdmin: caller.IsGlobalAdmin,
		TargetOrg:           targetOrg,
		TargetKey:           targetName,
	})
	if err != nil {
		return true, false, err.Error()
	}
	return true, true, ""
}

// catalogOrgOwner returns the org:owner catalog role. Kept as a helper so the
// orphan check references the catalog, not a hardcoded string.
func catalogOrgOwner() teamrole.Role {
	r, _ := teamrole.Lookup("org:owner")
	return r
}
