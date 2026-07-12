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

// Privilege-escalation regression suite — Red finding R-1.
//
// THREAT MODEL: one IAM instance, many orgs. A confidential-client principal
// "app/<name>" is minted by the client_credentials grant
// (routers/base.go getUsernameByClientIdSecret). It was historically treated as
// an UNCONDITIONAL GLOBAL ADMIN across every org, which let an ordinary org
// admin — who may legitimately read their OWN app's clientSecret — authenticate
// as that app and then (a) reveal EVERY other org's application clientSecret/Cert
// and (b) move users into the admin org / grant is_admin. R-1 revokes that
// blanket global-admin status: an app's authority is now ONLY the per-capability
// allowlist (object/app_authz.go) for mutations and explicit cross-org read
// permission (object/check.go CheckUserPermission) for reads — NEVER global admin.
//
// These are PURE unit tests (no DB, no Beego) over the decision functions the
// fix changes; the controller bridge is covered in
// controllers/app_not_super_admin_test.go and the live integration paths in the
// deployment verification.
package object

import (
	"testing"

	"github.com/hanzoai/iam/conf"
)

// ── R-1: an app/<name> principal is NEVER a global admin (the unmask gate) ────
//
// isUserIdSuperAdmin is the sole gate GetMaskedApplication / GetMaskedApplications
// / GetAllowedApplications use to decide whether to reveal an application's
// clientSecret/Cert. Including app principals there is the get-application leak:
// any confidential client could read every org's app secrets. After R-1 the gate
// admits ONLY real global-admin USERS (rows in conf.AdminOrg).
func TestIsUserIdSuperAdmin_AppPrincipalIsNeverSuperAdmin(t *testing.T) {
	// Every app principal — including one literally named "admin" and one in the
	// admin namespace — must be denied global-admin status.
	for _, p := range []string{
		"app/hanzo-cloud", "app/maxpower-assistant", "app/evil", "app/admin",
		"app/" + conf.AdminOrg, "app/",
	} {
		if isUserIdSuperAdmin(p) {
			t.Fatalf("R-1: app principal %q must NOT be a global admin (would unmask cross-tenant app secrets)", p)
		}
	}

	// Preserved: a real global-admin USER (a row in conf.AdminOrg) still reveals.
	if !isUserIdSuperAdmin(conf.AdminOrg + "/root") {
		t.Fatalf("regression: a real global-admin user (%s/root) must remain a global admin", conf.AdminOrg)
	}

	// Unchanged: tenant users and the operator's unified service-token principal
	// are not global admins (the operator's get-application is a masked existence
	// probe; secrets flow only through the service-token upsert write path).
	for _, p := range []string{"hanzo/dave", "maxpower/dave", "lux/z", "service/token", ""} {
		if isUserIdSuperAdmin(p) {
			t.Fatalf("regression: non-admin principal %q must not be a global admin", p)
		}
	}
}

// ── R-1: the H-4 field wall applies to app principals ─────────────────────────
//
// An app principal now carries isSuperAdmin=false (controllers/base.go and
// mcpself/auth.go). canMutatePrivilegedUserFields — the deny-by-default wall in
// CheckPermissionForUpdateUser — therefore refuses every owner move and is_admin
// grant by an app, on its own synthetic record, another user's, or cross-org.
func TestCanMutatePrivilegedUserFields_AppPrincipalCannotEscalate(t *testing.T) {
	const appIsSuperAdmin = false // the authority value an app/<name> now carries

	cases := []struct {
		name     string
		old, new *User
	}{
		{
			"app grants is_admin to a user in the same org",
			&User{Owner: "hanzo", Name: "bob", IsAdmin: false},
			&User{Owner: "hanzo", Name: "bob", IsAdmin: true},
		},
		{
			"app moves a user into the admin org (== conferring global admin)",
			&User{Owner: "hanzo", Name: "bob", IsAdmin: false},
			&User{Owner: conf.AdminOrg, Name: "bob", IsAdmin: false},
		},
		{
			"app moves a CROSS-ORG user into the admin org and grants admin",
			&User{Owner: "maxpower", Name: "dave", IsAdmin: false},
			&User{Owner: conf.AdminOrg, Name: "dave", IsAdmin: true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if canMutatePrivilegedUserFields(tc.old, tc.new, false, appIsSuperAdmin) {
				t.Fatalf("R-1: an app principal must NOT be able to: %s", tc.name)
			}
		})
	}

	// Constraint: do NOT blanket-deny app writes — a benign field edit with no
	// owner/is_admin delta is still permitted (the capability allowlist, not this
	// wall, decides whether an app may call update-user at all).
	benignOld := &User{Owner: "hanzo", Name: "bob", IsAdmin: false, DisplayName: "Bob"}
	benignNew := &User{Owner: "hanzo", Name: "bob", IsAdmin: false, DisplayName: "Bobby"}
	if !canMutatePrivilegedUserFields(benignOld, benignNew, false, appIsSuperAdmin) {
		t.Fatal("a benign (non-privileged) field edit must still be permitted (no blanket app deny)")
	}
}

// ── Constraint: the M2M masked get-user view preserves the billing identity ───
//
// Because an app is no longer a global admin, the cloud-api money path
// (GET /v1/iam/get-user?accessKey=hk-...) now receives the NON-admin/NON-self
// masked + filtered view. That path resolves an hk- key to its user and keys
// per-org billing on User.Owner, identifying the user by Name. Both MUST survive
// the restricted view — even under an org account-item config that marks them
// "Admin"-only — or every hk- key fails and the whole API goes 401.
func TestMaskedView_PreservesM2MBillingIdentity(t *testing.T) {
	u := &User{
		Owner:     "maxpower",
		Name:      "dave",
		Email:     "dave@example.com",
		Password:  "argon2id$v=19$m=65536$secrethash",
		AccessKey: "hk-43f50b6b",
	}

	// isAdminOrSelf=false is exactly the view an app caller now gets.
	masked, err := GetMaskedUser(u, false)
	if err != nil {
		t.Fatalf("GetMaskedUser: %v", err)
	}
	if masked.Owner != "maxpower" || masked.Name != "dave" {
		t.Fatalf("M2M identity lost in masked view: owner=%q name=%q", masked.Owner, masked.Name)
	}
	if masked.Password != "***" {
		t.Fatalf("password must be masked even for the (now non-admin) app view, got %q", masked.Password)
	}

	// An "Organization" account item maps to no User field (the field is Owner),
	// so it can never strip the billing org; an "Email" item proves the filter is
	// genuinely active for a non-admin caller.
	items := []*AccountItem{
		{Name: "Organization", ViewRule: "Admin"},
		{Name: "Email", ViewRule: "Admin"},
	}
	filtered, err := GetFilteredUser(masked, false, false, items)
	if err != nil {
		t.Fatalf("GetFilteredUser: %v", err)
	}
	if filtered.Owner != "maxpower" {
		t.Fatal("R-1 constraint: Owner (the per-org billing key) MUST survive the non-admin filtered view")
	}
	if filtered.Name != "dave" {
		t.Fatal("R-1 constraint: Name MUST survive the non-admin filtered view")
	}
	if filtered.Email != "" {
		t.Fatal("sanity: an Admin-viewRule field must be filtered for a non-admin caller (filter must be active)")
	}
}

// ── R-3: org-agnostic login never resolves to the global-admin org ────────────
//
// For organization=="" the primary lookup (GetUserByField) queries the global
// engine WITHOUT an owner filter, so DB row order can surface a conf.AdminOrg row
// as the primary; CheckPassword would then confer a full global-admin session on
// a tenant login. The fix re-resolves that case through selectVerifyingRow over
// the colliding rows, which NEVER selects the admin org. These lock the selection
// semantics the CheckUserPassword wiring relies on.
func TestSelectVerifyingRow_R3AdminPrimaryReResolvesToTenant(t *testing.T) {
	adminPrimary := &User{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"}
	candidates := []*User{
		{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"},
		{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"},
	}
	got := selectVerifyingRow(adminPrimary, candidates, verifyOnly(conf.AdminOrg+"/z", "hanzo/z"))
	if got == nil || got.Owner != "hanzo" {
		t.Fatalf("R-3: an admin-org primary must re-resolve to the tenant row, got %v", got)
	}
}

func TestSelectVerifyingRow_R3AdminOnlyOrgAgnosticRefused(t *testing.T) {
	adminPrimary := &User{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"}
	candidates := []*User{{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"}}
	if got := selectVerifyingRow(adminPrimary, candidates, verifyOnly(conf.AdminOrg+"/z")); got != nil {
		t.Fatalf("R-3: an admin-only org-agnostic login must be refused (nil), got %s/%s", got.Owner, got.Name)
	}
}
