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

//go:build !skipCi

// Privilege-escalation regression suite (Red findings H-3, H-4, H-5).
//
// THREAT MODEL: one IAM instance, many orgs. Global-admin authority is
// membership in conf.AdminOrg (the isSuperAdmin field is unused here). An identity
// may exist as TWO rows — e.g. hanzo/a (tenant, argon2id) and admin/a
// (global-admin, bcrypt). App logins, secret reveals, and user mutations MUST
// resolve within the requesting context and NEVER silently confer global-admin.
package object

import (
	"testing"

	"github.com/hanzoai/iam/conf"
)

// ── H-3: org-agnostic login must NOT prefer the global-admin row ─────────────
//
// selectVerifyingRow resolves an org-agnostic login when the same identity
// collides across orgs and the first-resolved row's password failed. It MUST
// NOT prefer (or even select) the conf.AdminOrg row: doing so silently escalates
// a tenant login to a full global-admin session. Global-admin login requires an
// explicit organization == conf.AdminOrg (the within-org primary lookup), never
// a collision fallback.

// TestSelectVerifyingRow_NeverPrefersAdminOrg is the H-3 escalation: both the
// global-admin row (admin/z) and the tenant row (hanzo/z) verify. The resolver
// must land on the TENANT row, never the admin row.
func TestSelectVerifyingRow_NeverPrefersAdminOrg(t *testing.T) {
	resolved := &User{Owner: "personal-z", Name: "z", Email: "z@hanzo.ai"}
	candidates := []*User{
		{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"},
		{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"},
		{Owner: "lux", Name: "z", Email: "z@hanzo.ai"},
	}

	got := selectVerifyingRow(resolved, candidates, verifyOnly(conf.AdminOrg+"/z", "hanzo/z", "lux/z"))
	if got == nil {
		t.Fatal("want a tenant row, got nil")
	}
	if got.Owner == conf.AdminOrg {
		t.Fatalf("H-3: org-agnostic collision escalated to global-admin org %q/%s", got.Owner, got.Name)
	}
}

// TestSelectVerifyingRow_AdminOnlyVerifyingYieldsNil proves the documented
// cross-org policy: an identity that verifies ONLY in conf.AdminOrg cannot be
// resolved by a collision fallback. The caller then surfaces the normal
// "password incorrect"; the global admin must log in with an explicit
// organization == conf.AdminOrg instead.
func TestSelectVerifyingRow_AdminOnlyVerifyingYieldsNil(t *testing.T) {
	resolved := &User{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"}
	candidates := []*User{
		{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"},
		{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"},
	}

	// Only the admin row would verify — it must be refused.
	if got := selectVerifyingRow(resolved, candidates, verifyOnly(conf.AdminOrg+"/z")); got != nil {
		t.Fatalf("H-3: admin-only collision must yield nil, got %s/%s", got.Owner, got.Name)
	}
}

// ── H-5: a shared application must NOT unmask secrets to non-owning admins ────
//
// IsApplicationAdmin is the sole gate GetMaskedApplication uses to decide
// whether to reveal clientSecret/Cert. IsShared must NOT widen that gate: a
// shared app is visible to other orgs for LOGIN, but its credentials belong to
// the owning org only. Reveal is limited to the owning-org admin and the global
// admin.

// TestIsApplicationAdmin_SharedDoesNotUnmaskForNonOwner is the H-5 leak: a
// non-owning org admin reading a SHARED app must NOT be treated as an
// application admin (which would unmask clientSecret/Cert).
func TestIsApplicationAdmin_SharedDoesNotUnmaskForNonOwner(t *testing.T) {
	hanzoAdmin := &User{Owner: "hanzo", Name: "admin", IsAdmin: true}
	sharedLuxApp := &Application{Organization: "lux", IsShared: true}

	if hanzoAdmin.IsApplicationAdmin(sharedLuxApp) {
		t.Fatal("H-5: non-owning org admin must NOT be application admin of a shared app (would unmask clientSecret/Cert)")
	}
}

// TestIsApplicationAdmin_OwningAndGlobalStillReveal confirms the fix does not
// over-rotate: the owning-org admin and the global admin retain reveal access.
func TestIsApplicationAdmin_OwningAndGlobalStillReveal(t *testing.T) {
	luxApp := &Application{Organization: "lux", IsShared: false}
	sharedLuxApp := &Application{Organization: "lux", IsShared: true}

	luxAdmin := &User{Owner: "lux", Name: "admin", IsAdmin: true}
	if !luxAdmin.IsApplicationAdmin(luxApp) {
		t.Fatal("owning-org admin must remain application admin of its own app")
	}
	if !luxAdmin.IsApplicationAdmin(sharedLuxApp) {
		t.Fatal("owning-org admin must remain application admin of its own shared app")
	}

	root := &User{Owner: conf.AdminOrg, Name: conf.AdminUser, IsAdmin: true}
	if !root.IsApplicationAdmin(luxApp) {
		t.Fatal("global admin must remain application admin of any app")
	}
}

// ── H-4: owner / IsAdmin are global-admin-only, never self-service ───────────
//
// canMutatePrivilegedUserFields is the deny-by-default policy behind
// CheckPermissionForUpdateUser. A non-global-admin may not move any user
// between orgs (owner change → path to conf.AdminOrg) nor grant the IsAdmin
// flag, on ANY record including their own. Global admins may.

func TestCanMutatePrivilegedUserFields_NonGlobalCannotEscalate(t *testing.T) {
	cases := []struct {
		name         string
		old          *User
		new          *User
		oldIsAdmin   bool
		isSuperAdmin bool
		want         bool
	}{
		{
			name:       "self-grant admin is refused",
			old:        &User{Owner: "hanzo", Name: "a", IsAdmin: false},
			new:        &User{Owner: "hanzo", Name: "a", IsAdmin: true},
			oldIsAdmin: false, isSuperAdmin: false, want: false,
		},
		{
			name:       "self-move to admin org is refused",
			old:        &User{Owner: "hanzo", Name: "a", IsAdmin: false},
			new:        &User{Owner: conf.AdminOrg, Name: "a", IsAdmin: false},
			oldIsAdmin: false, isSuperAdmin: false, want: false,
		},
		{
			name:       "org-admin granting admin to another user is refused",
			old:        &User{Owner: "hanzo", Name: "bob", IsAdmin: false},
			new:        &User{Owner: "hanzo", Name: "bob", IsAdmin: true},
			oldIsAdmin: false, isSuperAdmin: false, want: false,
		},
		{
			name:       "benign self edit (no owner/admin change) is allowed",
			old:        &User{Owner: "hanzo", Name: "a", IsAdmin: false, DisplayName: "A"},
			new:        &User{Owner: "hanzo", Name: "a", IsAdmin: false, DisplayName: "Alice"},
			oldIsAdmin: false, isSuperAdmin: false, want: true,
		},
		{
			name:       "existing admin keeping admin (no grant) is allowed",
			old:        &User{Owner: "hanzo", Name: "a", IsAdmin: true},
			new:        &User{Owner: "hanzo", Name: "a", IsAdmin: true},
			oldIsAdmin: true, isSuperAdmin: false, want: true,
		},
		{
			name:       "global admin may grant admin",
			old:        &User{Owner: "hanzo", Name: "a", IsAdmin: false},
			new:        &User{Owner: "hanzo", Name: "a", IsAdmin: true},
			oldIsAdmin: false, isSuperAdmin: true, want: true,
		},
		{
			name:       "global admin may move user between orgs",
			old:        &User{Owner: "hanzo", Name: "a", IsAdmin: false},
			new:        &User{Owner: conf.AdminOrg, Name: "a", IsAdmin: true},
			oldIsAdmin: false, isSuperAdmin: true, want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := canMutatePrivilegedUserFields(tc.old, tc.new, tc.oldIsAdmin, tc.isSuperAdmin)
			if got != tc.want {
				t.Fatalf("canMutatePrivilegedUserFields = %v, want %v", got, tc.want)
			}
		})
	}
}

// ── H-3 (fallback): cross-org login resolution never lands on the admin org ──
//
// pickCrossOrgLoginUser is the policy behind the GetUserByFields cross-org
// fallback. For a non-admin (or org-agnostic) login it must skip conf.AdminOrg
// rows and return the first tenant row; for an explicit admin login it may
// return the admin row.

func TestPickCrossOrgLoginUser_SkipsAdminForTenantLogin(t *testing.T) {
	users := []*User{
		{Owner: conf.AdminOrg, Name: "a", Email: "a@hanzo.ai"},
		{Owner: "lux", Name: "a", Email: "a@hanzo.ai"},
	}
	got := pickCrossOrgLoginUser(users, false)
	if got == nil || got.Owner != "lux" {
		t.Fatalf("H-3: tenant login must skip admin row and pick lux/a, got %v", got)
	}
}

func TestPickCrossOrgLoginUser_AdminOnlyTenantLoginYieldsNil(t *testing.T) {
	users := []*User{{Owner: conf.AdminOrg, Name: "a", Email: "a@hanzo.ai"}}
	if got := pickCrossOrgLoginUser(users, false); got != nil {
		t.Fatalf("H-3: admin-only cross-org row must be refused for tenant login, got %s/%s", got.Owner, got.Name)
	}
}

func TestPickCrossOrgLoginUser_ExplicitAdminLoginAllowsAdmin(t *testing.T) {
	users := []*User{{Owner: conf.AdminOrg, Name: "a", Email: "a@hanzo.ai"}}
	got := pickCrossOrgLoginUser(users, true)
	if got == nil || got.Owner != conf.AdminOrg {
		t.Fatalf("explicit admin login must resolve the admin row, got %v", got)
	}
}
