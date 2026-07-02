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
	"testing"

	"github.com/hanzoai/iam/teamrole"
	"github.com/hanzoai/iam/util"
)

// TestTeamRoleFor pins the IAM Role row built from a catalog entry: the Name is
// the exact catalog key (one identifier everywhere) and the role is enabled
// with an empty membership.
func TestTeamRoleFor(t *testing.T) {
	r, _ := teamrole.Lookup("billing:admin")
	row := TeamRoleFor("acme", r)
	if row.Owner != "acme" || row.Name != "billing:admin" {
		t.Fatalf("TeamRoleFor id = %s/%s, want acme/billing:admin", row.Owner, row.Name)
	}
	if !row.IsEnabled {
		t.Error("seeded role must be enabled")
	}
	if len(row.Users) != 0 {
		t.Error("seeded role must start with no members")
	}
	if row.DisplayName == "" {
		t.Error("seeded role must carry a display name")
	}
}

// TestTeamPermissionFor pins the Casbin permission row: it binds the org-scoped
// role id, grants the catalog resource+actions, and is Allow/Approved so the
// /v1/iam/enforce path can evaluate app scope.
func TestTeamPermissionFor(t *testing.T) {
	r, _ := teamrole.Lookup("billing:viewer")
	p := TeamPermissionFor("acme", r)
	if p.Owner != "acme" || p.Name != "billing:viewer-permission" {
		t.Fatalf("permission id = %s/%s, want acme/billing:viewer-permission", p.Owner, p.Name)
	}
	wantRole := util.GetId("acme", "billing:viewer")
	if len(p.Roles) != 1 || p.Roles[0] != wantRole {
		t.Fatalf("permission roles = %v, want [%s]", p.Roles, wantRole)
	}
	if p.Effect != "Allow" || p.State != "Approved" {
		t.Errorf("permission must be Allow/Approved, got %s/%s", p.Effect, p.State)
	}
	if len(p.Resources) != 1 || p.Resources[0] != "billing:*" {
		t.Errorf("permission resources = %v, want [billing:*]", p.Resources)
	}
	if len(p.Actions) == 0 {
		t.Error("permission must grant at least one action")
	}
}

// TestAuthorizeUnmanagedRoleFallsThrough proves a non-catalog role is NOT the
// guard's concern: managed=false, allowed=true, so the caller proceeds with
// ordinary authz. (No DB is touched on this path.)
func TestAuthorizeUnmanagedRoleFallsThrough(t *testing.T) {
	caller := CallerContext{UserId: "acme/mallory", Org: "acme", IsGlobalAdmin: false}
	managed, allowed, reason := AuthorizeManagedRoleWrite(caller, "acme", "some-custom-team", []string{"acme/x"}, false)
	if managed {
		t.Error("custom role must not be treated as managed")
	}
	if !allowed {
		t.Errorf("unmanaged role must be allowed to proceed, reason=%q", reason)
	}
}

// TestOrgOwnerOrphanProtection proves the last-owner safety net: a non-superuser
// deleting or emptying org:owner is denied BEFORE any authority lookup (the
// orphan check precedes the DB call), so this runs DB-free. A superuser is
// exempt (can repair).
func TestOrgOwnerOrphanProtection(t *testing.T) {
	nonSuper := CallerContext{UserId: "acme/owner", Org: "acme", IsGlobalAdmin: false}

	// Delete of org:owner -> denied (would orphan the org).
	managed, allowed, reason := AuthorizeManagedRoleWrite(nonSuper, "acme", "org:owner", nil, true)
	if !managed || allowed {
		t.Fatalf("delete org:owner must be denied, got managed=%v allowed=%v", managed, allowed)
	}
	if reason == "" {
		t.Error("denial must carry an auditable reason")
	}

	// Update that empties org:owner membership -> denied.
	managed, allowed, _ = AuthorizeManagedRoleWrite(nonSuper, "acme", "org:owner", []string{}, false)
	if !managed || allowed {
		t.Fatalf("emptying org:owner must be denied, got managed=%v allowed=%v", managed, allowed)
	}

	// Superuser is exempt from the orphan net (proceeds to normal authz, which
	// for a global admin allows) — this path also short-circuits pre-DB via the
	// teamrole superuser bypass, so it is DB-free here.
	super := CallerContext{UserId: "admin/root", Org: "admin", IsGlobalAdmin: true}
	managed, allowed, _ = AuthorizeManagedRoleWrite(super, "acme", "org:owner", nil, true)
	if !managed || !allowed {
		t.Fatalf("superuser delete org:owner must be allowed, got managed=%v allowed=%v", managed, allowed)
	}
}
