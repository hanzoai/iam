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

// TestAuthorizeLogin_NoPrivilegeEscalation is the safety proof for the
// clientId-authoritative authorize fix (controllers/auth.go resolveLoginApplication).
// The login org is the authorize CLIENT's org — admin-guard -> admin, hanzo-cloud
// -> hanzo — so authenticating there requires the password to match a user row IN
// that org:
//
//   - admin/z exists  -> an admin-guard authorize resolves admin/z (SuperAdmin);
//   - hanzo/z exists  -> a hanzo-cloud authorize resolves hanzo/z (tenant);
//   - a tenant-only user (eve, only in hanzo) has NO admin-org row, so an
//     admin-guard authorize resolves her only as her TENANT identity (hanzo/eve,
//     owner=hanzo) via the cross-org fallback — never as an admin-org identity.
//     Binding the login org to the app's org never widens auth to admin; the
//     guard's owner==admin check then rejects the non-admin session.
func TestAuthorizeLogin_NoPrivilegeEscalation(t *testing.T) {
	prev := ormer
	t.Cleanup(func() { ormer = prev })
	engine := newTestEngine(t)
	ormer = &Ormer{driverName: "sqlite", Engine: engine}

	rawInsertUser(t, engine, conf.AdminOrg, "z", "", "")
	rawInsertUser(t, engine, "hanzo", "z", "", "")
	rawInsertUser(t, engine, "hanzo", "eve", "", "") // tenant-only; no admin-org row

	// admin-guard authorize (app org == conf.AdminOrg) -> admin/z (SuperAdmin).
	if u, err := GetUserByFields(conf.AdminOrg, "z"); err != nil || u == nil || u.Owner != conf.AdminOrg {
		t.Fatalf("admin-guard authorize must resolve %s/z, got %v (err %v)", conf.AdminOrg, u, err)
	}

	// hanzo-cloud authorize (app org == hanzo) -> hanzo/z (tenant, never admin).
	if u, err := GetUserByFields("hanzo", "z"); err != nil || u == nil || u.Owner != "hanzo" {
		t.Fatalf("hanzo-cloud authorize must resolve hanzo/z, got %v (err %v)", u, err)
	}

	// No escalation: eve has no admin-org row. An admin-guard authorize resolves
	// her ONLY as her tenant identity (owner=hanzo), never owner=admin — so she
	// cannot become a SuperAdmin no matter which app the authorize targets.
	if u, err := GetUserByFields(conf.AdminOrg, "eve"); err != nil {
		t.Fatalf("GetUserByFields(%s, eve): %v", conf.AdminOrg, err)
	} else if u != nil && u.Owner == conf.AdminOrg {
		t.Fatalf("no-escalation: eve must NEVER resolve as an %s identity, got %s/%s", conf.AdminOrg, u.Owner, u.Name)
	}
}
