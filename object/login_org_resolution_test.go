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
	"path/filepath"
	"testing"

	"github.com/hanzoai/iam/conf"
	sqlitedrv "github.com/hanzoai/sqlite"
	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/names"
)

// TestGetUserByFields_ResolvesUserInAppOrg is the end-to-end proof of the
// operator-panel fix. The same username lives in BOTH the global-admin org
// (admin/z, the isSuperAdmin identity) and a tenant org (hanzo/z). The login
// user is resolved in the org the login TARGETS — the resolved application's
// organization, which controllers/auth.go now passes via loginOrgForApp:
//
//   - an app whose Organization == conf.AdminOrg (e.g. hanzo-admin-guard)
//     resolves admin/z, so the operator gets the global-admin identity;
//   - an app whose Organization == "hanzo" (a tenant client) resolves hanzo/z.
//
// The bug was that the OAuth-authorize login path passed a wrong/empty
// organization (the user's home org, "hanzo") instead of the app's org, so an
// admin-org authorize resolved hanzo/z and the operator became a tenant.
func TestGetUserByFields_ResolvesUserInAppOrg(t *testing.T) {
	prev := ormer
	t.Cleanup(func() { ormer = prev })
	engine := newTestEngine(t)
	ormer = &Ormer{driverName: "sqlite", Engine: engine}

	// z exists in both the global-admin org and a tenant org.
	rawInsertUser(t, engine, conf.AdminOrg, "z", "", "")
	rawInsertUser(t, engine, "hanzo", "z", "", "")

	// The resolved application's org is the single source of truth for the login
	// org. hanzo-admin-guard is registered in the global-admin org; hanzo-cloud
	// is a tenant client.
	adminApp := &Application{Owner: conf.AdminOrg, Name: "hanzo-admin-guard", Organization: conf.AdminOrg}
	tenantApp := &Application{Owner: "hanzo", Name: "hanzo-cloud", Organization: "hanzo"}

	// Admin-org app -> admin/z (the global-admin identity the operator needs).
	if u, err := GetUserByFields(adminApp.Organization, "z"); err != nil {
		t.Fatalf("GetUserByFields(%q): %v", adminApp.Organization, err)
	} else if u == nil || u.Owner != conf.AdminOrg {
		t.Fatalf("admin-org app (%s) must resolve %s/z, got %v", adminApp.Name, conf.AdminOrg, u)
	}

	// Tenant app -> hanzo/z (never the admin identity).
	if u, err := GetUserByFields(tenantApp.Organization, "z"); err != nil {
		t.Fatalf("GetUserByFields(%q): %v", tenantApp.Organization, err)
	} else if u == nil || u.Owner != "hanzo" {
		t.Fatalf("tenant app (%s) must resolve hanzo/z, got %v", tenantApp.Name, u)
	}
}

// ── Privilege-separation contract: superadmin is reachable ONLY via admin org ──
//
// The seeded superuser z@hanzo.ai exists in BOTH the admin (god-mode) org and
// the hanzo brand org — the exact production shape (universe
// infra/k8s/iam/init_data.json: admin/z isGlobalAdmin=true AND hanzo/z
// isGlobalAdmin=false). The login RESOLUTION policy is uniform: a user resolves
// within the requesting application's declared org (loginOrgForApp). So the
// admin (superadmin) row is reached ONLY when the app's org IS the admin org
// (admin.hanzo.ai's hanzo-admin-guard). Every other surface — console, CLI,
// chat, any brand app — resolves the brand row. IsSuperAdmin() == (Owner ==
// conf.AdminOrg), so proving WHICH ORG resolves proves the authority level.
//
// These tests exercise the real resolvers against a seeded SQLite DB
// (orgIsolation=none, single engine): GetUserForLogin (the password path, via
// CheckUserPassword) and GetUserByFields (the Face ID / code / OAuth path).

func seedLoginResolutionDB(t *testing.T) {
	t.Helper()

	prevOrmer := ormer
	prevCache := userCache
	t.Cleanup(func() {
		ormer = prevOrmer
		userCache = prevCache
	})

	dir := t.TempDir()
	dsn := sqlitedrv.DSN(filepath.Join(dir, "test.db"), nil)
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine: %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	if err := engine.Sync2(new(User), new(Organization)); err != nil {
		t.Fatalf("Sync2: %v", err)
	}
	t.Cleanup(func() { _ = engine.Close() })

	ormer = &Ormer{driverName: "sqlite", Engine: engine}
	userCache = &ttlCache{}

	// Organizations — a flat forest (no parent links) so the login resolver's
	// ancestor fast-path is a no-op and the within-org lookup decides everything.
	for _, name := range []string{conf.AdminOrg, "hanzo", "lux"} {
		if _, err := engine.Insert(&Organization{Owner: conf.AdminOrg, Name: name}); err != nil {
			t.Fatalf("seed org %s: %v", name, err)
		}
	}

	seed := []*User{
		// The colliding superuser: present in BOTH admin/ and hanzo/.
		{Owner: conf.AdminOrg, Name: "z", Id: "z-admin", Email: "z@hanzo.ai"},
		{Owner: "hanzo", Name: "z", Id: "z-hanzo", Email: "z@hanzo.ai"},
		// Brand-only user (no admin row) — must be unaffected.
		{Owner: "hanzo", Name: "major", Id: "major-hanzo", Email: "major@hanzo.ai"},
		// Normal tenant user living in their own org.
		{Owner: "lux", Name: "normal", Id: "normal-lux", Email: "normal@lux.network"},
		// A pure global admin: exists ONLY in the admin org.
		{Owner: conf.AdminOrg, Name: "pureadmin", Id: "pureadmin-admin", Email: "pureadmin@hanzo.ai"},
	}
	for _, u := range seed {
		if _, err := engine.Insert(u); err != nil {
			t.Fatalf("seed user %s/%s: %v", u.Owner, u.Name, err)
		}
	}
}

func mustResolveForLogin(t *testing.T, org, field string) *User {
	t.Helper()
	u, err := GetUserForLogin(org, field)
	if err != nil {
		t.Fatalf("GetUserForLogin(%q, %q): %v", org, field, err)
	}
	if u == nil {
		t.Fatalf("GetUserForLogin(%q, %q) = nil, want a user", org, field)
	}
	return u
}

// Scenario 1: z@hanzo.ai via a NON-admin app (hanzo-console / hanzo-cloud, org
// "hanzo") resolves the brand row hanzo/z — never admin. isGlobalAdmin=false.
func TestLoginResolution_SuperuserViaBrandApp_ResolvesBrandOrg(t *testing.T) {
	seedLoginResolutionDB(t)

	for _, field := range []string{"z@hanzo.ai", "z"} {
		u := mustResolveForLogin(t, "hanzo", field)
		if u.Owner != "hanzo" {
			t.Fatalf("LEAK: login via brand app resolved owner=%q (want hanzo) for field %q", u.Owner, field)
		}
		if u.IsSuperAdmin() {
			t.Fatalf("LEAK: login via brand app resolved a superadmin for field %q (%s/%s)", field, u.Owner, u.Name)
		}
	}

	// The Face ID / code / OAuth resolver must agree.
	u, err := GetUserByFields("hanzo", "z@hanzo.ai")
	if err != nil || u == nil || u.Owner != "hanzo" {
		t.Fatalf("GetUserByFields(hanzo, z@hanzo.ai) = %v (err %v), want hanzo/z", u, err)
	}
}

// Scenario 2: z@hanzo.ai via the admin-guard app (org "admin") resolves admin/z —
// superadmin STILL works at admin.hanzo.ai. isGlobalAdmin=true.
func TestLoginResolution_SuperuserViaAdminApp_ResolvesAdminOrg(t *testing.T) {
	seedLoginResolutionDB(t)

	for _, field := range []string{"z@hanzo.ai", "z"} {
		u := mustResolveForLogin(t, conf.AdminOrg, field)
		if u.Owner != conf.AdminOrg {
			t.Fatalf("admin app must resolve owner=%q (want %q) for field %q", u.Owner, conf.AdminOrg, field)
		}
		if !u.IsSuperAdmin() {
			t.Fatalf("admin app must resolve a superadmin for field %q (%s/%s)", field, u.Owner, u.Name)
		}
	}

	u, err := GetUserByFields(conf.AdminOrg, "z@hanzo.ai")
	if err != nil || u == nil || u.Owner != conf.AdminOrg {
		t.Fatalf("GetUserByFields(admin, z@hanzo.ai) = %v (err %v), want admin/z", u, err)
	}
}

// Scenario 3: a brand-only user (major@hanzo.ai, only in hanzo) via a brand app
// resolves hanzo/major — no regression to normal login.
func TestLoginResolution_BrandOnlyUser_Unaffected(t *testing.T) {
	seedLoginResolutionDB(t)

	for _, field := range []string{"major@hanzo.ai", "major"} {
		u := mustResolveForLogin(t, "hanzo", field)
		if u.Owner != "hanzo" || u.Name != "major" {
			t.Fatalf("brand-only login resolved %s/%s, want hanzo/major (field %q)", u.Owner, u.Name, field)
		}
		if u.IsSuperAdmin() {
			t.Fatalf("brand-only user must not be a superadmin (field %q)", field)
		}
	}
}

// Scenario 4: a normal user always resolves in their own org — no lock-out.
func TestLoginResolution_NormalUser_ResolvesOwnOrg(t *testing.T) {
	seedLoginResolutionDB(t)

	for _, field := range []string{"normal@lux.network", "normal"} {
		u := mustResolveForLogin(t, "lux", field)
		if u.Owner != "lux" || u.Name != "normal" {
			t.Fatalf("normal login resolved %s/%s, want lux/normal (field %q)", u.Owner, u.Name, field)
		}
	}
}

// The org-agnostic cross-org path (organization == "") must NEVER surface the
// admin row for a colliding identity — it resolves the brand row. This is the
// direct proof that even a login that omits the org cannot reach superadmin.
func TestLoginResolution_OrgAgnostic_NeverResolvesAdmin(t *testing.T) {
	seedLoginResolutionDB(t)

	u, err := GetUserByFields("", "z@hanzo.ai")
	if err != nil {
		t.Fatalf("GetUserByFields(\"\", z@hanzo.ai): %v", err)
	}
	if u == nil {
		t.Fatalf("org-agnostic resolution returned nil, want the brand row hanzo/z")
	}
	if u.Owner == conf.AdminOrg || u.IsSuperAdmin() {
		t.Fatalf("LEAK: org-agnostic resolution reached the admin org (%s/%s)", u.Owner, u.Name)
	}
	if u.Owner != "hanzo" {
		t.Fatalf("org-agnostic resolution = %s/%s, want hanzo/z", u.Owner, u.Name)
	}
}

// A pure global admin (exists ONLY in the admin org) logging in via a NON-admin
// app must FAIL to resolve there — they are not a member of that app's org, and
// must never be silently elevated (or silently accepted) on a brand surface.
func TestLoginResolution_PureAdminViaBrandApp_DoesNotResolve(t *testing.T) {
	seedLoginResolutionDB(t)

	if u, err := GetUserByFields("hanzo", "pureadmin@hanzo.ai"); err != nil {
		t.Fatalf("GetUserByFields(hanzo, pureadmin@hanzo.ai): %v", err)
	} else if u != nil {
		t.Fatalf("LEAK: pure-admin resolved on a brand app as %s/%s, want no resolution", u.Owner, u.Name)
	}

	if u, err := GetUserForLogin("hanzo", "pureadmin@hanzo.ai"); err != nil {
		t.Fatalf("GetUserForLogin(hanzo, pureadmin@hanzo.ai): %v", err)
	} else if u != nil {
		t.Fatalf("LEAK: pure-admin resolved via GetUserForLogin on a brand app as %s/%s", u.Owner, u.Name)
	}

	// ...but the same pure admin resolves normally through the admin app.
	u := mustResolveForLogin(t, conf.AdminOrg, "pureadmin@hanzo.ai")
	if !u.IsSuperAdmin() {
		t.Fatalf("pure-admin via admin app must be a superadmin, got %s/%s", u.Owner, u.Name)
	}
}
