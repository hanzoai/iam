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

	"github.com/hanzoai/iam/conf"
)

// TestGetUserByFields_ResolvesUserInAppOrg is the end-to-end proof of the
// operator-panel fix. The same username lives in BOTH the global-admin org
// (admin/z, the isGlobalAdmin identity) and a tenant org (hanzo/z). The login
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
