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

package object

import (
	"testing"

	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/names"
)

// newProjectTestOrmer wires the package `ormer` to a fresh in-memory sqlite
// engine with the org + project + user tables. Restores the previous ormer on
// cleanup.
func newProjectTestOrmer(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + dir + "/project.db?_journal_mode=WAL&_busy_timeout=5000"
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine: %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	for _, tbl := range []interface{}{new(Organization), new(Application), new(Project), new(User)} {
		if err := engine.Sync2(tbl); err != nil {
			t.Fatalf("Sync2(%T): %v", tbl, err)
		}
	}
	prev := ormer
	ormer = &Ormer{driverName: "sqlite", Engine: engine}
	t.Cleanup(func() {
		ormer = prev
		_ = engine.Close()
	})
}

// TestOrgHasNoProjectOnCreate proves projects are CREATE-ON-DEMAND: neither the
// CRUD path (AddOrganization) nor signup (CreatePersonalOrganization) seeds a
// project, so a fresh org has none and GetDefaultProject returns nil — the
// caller then operates at the org level.
func TestOrgHasNoProjectOnCreate(t *testing.T) {
	newProjectTestOrmer(t)

	if _, err := AddOrganization(&Organization{Owner: "admin", Name: "acme", DisplayName: "Acme"}); err != nil {
		t.Fatalf("AddOrganization: %v", err)
	}
	if _, err := CreatePersonalOrganization("alice", "Alice"); err != nil {
		t.Fatalf("CreatePersonalOrganization: %v", err)
	}

	for _, slug := range []string{"acme", "alice"} {
		p, err := GetDefaultProject(slug)
		if err != nil {
			t.Fatalf("GetDefaultProject(%q): %v", slug, err)
		}
		if p != nil {
			t.Errorf("org %q has a project %q on create, want none (create-on-demand)", slug, p.Name)
		}
	}
	if n, _ := ormer.Engine.Count(new(Project)); n != 0 {
		t.Errorf("project rows = %d, want 0 (no auto-seeding)", n)
	}
}

// TestNoProjectClaimIsOmitted proves the payoff of org-level scope: with no
// project, the value generateJwtToken resolves is empty, and every JWT format
// OMITS the `project` claim — cloud's principal then keys the request at the org
// level (absent project ⟹ org-wide scope).
func TestNoProjectClaimIsOmitted(t *testing.T) {
	newProjectTestOrmer(t)
	if _, err := AddOrganization(&Organization{Owner: "admin", Name: "acme"}); err != nil {
		t.Fatalf("AddOrganization: %v", err)
	}

	def, err := GetDefaultProject("acme")
	if err != nil {
		t.Fatalf("GetDefaultProject: %v", err)
	}
	project := ""
	if def != nil {
		project = def.Name
	}
	if project != "" {
		t.Fatalf("resolved project = %q, want empty (org-level)", project)
	}

	user := &User{Owner: "acme", Name: "alice", Id: "acme/alice"}
	claims := Claims{User: user, TokenType: "access-token", Scope: "openid", Project: project}
	for surface, m := range map[string]map[string]interface{}{
		"JWT (default)": jsonClaims(t, getClaimsWithoutThirdIdp(claims)),
		"JWT-Empty":     jsonClaims(t, getShortClaims(claims)),
		"JWT-Standard":  jsonClaims(t, getStandardClaims(claims)),
		"JWT-Custom":    getClaimsCustom(claims, []string{"email"}, nil),
	} {
		if v, ok := m["project"]; ok && v != "" {
			t.Errorf("%s: project claim = %v, want omitted (org-level)", surface, v)
		}
	}
}

// TestCreatedDefaultProjectRidesTheClaim proves that once a user CREATES a named
// project and marks it default, GetDefaultProject resolves it and its name rides
// the `project` claim through every JWT format — narrowing the token from org
// scope to that project.
func TestCreatedDefaultProjectRidesTheClaim(t *testing.T) {
	newProjectTestOrmer(t)
	if _, err := AddOrganization(&Organization{Owner: "admin", Name: "acme"}); err != nil {
		t.Fatalf("AddOrganization: %v", err)
	}
	// A user creates a real, named project and marks it their default.
	if _, err := AddProject(&Project{Owner: "acme", Name: "site", Organization: "acme", DisplayName: "Site", IsDefault: true}); err != nil {
		t.Fatalf("AddProject: %v", err)
	}

	def, err := GetDefaultProject("acme")
	if err != nil || def == nil || def.Name != "site" {
		t.Fatalf("GetDefaultProject = %v (err %v), want name %q", def, err, "site")
	}

	user := &User{Owner: "acme", Name: "alice", Id: "acme/alice"}
	claims := Claims{User: user, TokenType: "access-token", Scope: "openid", Project: def.Name}
	for surface, m := range map[string]map[string]interface{}{
		"JWT (default)": jsonClaims(t, getClaimsWithoutThirdIdp(claims)),
		"JWT-Empty":     jsonClaims(t, getShortClaims(claims)),
		"JWT-Standard":  jsonClaims(t, getStandardClaims(claims)),
		"JWT-Custom":    getClaimsCustom(claims, []string{"email"}, nil),
	} {
		if got, ok := m["project"]; !ok || got != "site" {
			t.Errorf("%s: project claim = %v (present=%v), want %q", surface, got, ok, "site")
		}
	}
}
