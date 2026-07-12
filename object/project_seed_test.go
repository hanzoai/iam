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

// newSeedTestOrmer wires the package-level `ormer` global to a fresh in-memory
// sqlite engine with the org + project + user tables synced — the exact tables
// the default-project seed touches. Mirrors newWeb3TestOrmer. Restores the
// previous ormer on cleanup.
func newSeedTestOrmer(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + dir + "/seed.db?_journal_mode=WAL&_busy_timeout=5000"
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

// assertDefaultProject pins the authoritative contract cloud depends on: the
// default project is named exactly "default", Owner == Organization == slug, and
// IsDefault is true.
func assertDefaultProject(t *testing.T, slug string, p *Project) {
	t.Helper()
	if p == nil {
		t.Fatalf("org %q: no default project", slug)
	}
	if p.Name != "default" {
		t.Errorf("org %q: default project name = %q, want %q", slug, p.Name, "default")
	}
	if p.Owner != slug {
		t.Errorf("org %q: default project Owner = %q, want %q", slug, p.Owner, slug)
	}
	if p.Organization != slug {
		t.Errorf("org %q: default project Organization = %q, want %q", slug, p.Organization, slug)
	}
	if !p.IsDefault {
		t.Errorf("org %q: default project IsDefault = false, want true", slug)
	}
}

// TestAddOrganizationSeedsDefaultProject proves the CRUD/seed path
// (AddOrganization — the funnel for init_data, the org API, and bootstrap)
// yields a default project satisfying the contract.
func TestAddOrganizationSeedsDefaultProject(t *testing.T) {
	newSeedTestOrmer(t)

	const slug = "acme"
	if _, err := AddOrganization(&Organization{Owner: "admin", Name: slug, DisplayName: "Acme"}); err != nil {
		t.Fatalf("AddOrganization: %v", err)
	}

	p, err := GetDefaultProject(slug)
	if err != nil {
		t.Fatalf("GetDefaultProject: %v", err)
	}
	assertDefaultProject(t, slug, p)
}

// TestCreatePersonalOrganizationSeedsDefaultProject proves the signup path
// (CreatePersonalOrganization) yields a default project satisfying the contract.
func TestCreatePersonalOrganizationSeedsDefaultProject(t *testing.T) {
	newSeedTestOrmer(t)

	const slug = "alice"
	if _, err := CreatePersonalOrganization(slug, "Alice"); err != nil {
		t.Fatalf("CreatePersonalOrganization: %v", err)
	}

	p, err := GetDefaultProject(slug)
	if err != nil {
		t.Fatalf("GetDefaultProject: %v", err)
	}
	assertDefaultProject(t, slug, p)
}

// TestBackfillDefaultProjectsIsIdempotent proves the one-shot migration seeds
// orgs missing a default, skips those already seeded, and is a no-op on rerun —
// the guarantee that makes it safe to run on every boot against a live DB.
func TestBackfillDefaultProjectsIsIdempotent(t *testing.T) {
	newSeedTestOrmer(t)

	// Two legacy orgs inserted RAW (no seed hook) plus one that already carries a
	// hand-made default project — the backfill must seed the first two and leave
	// the third untouched.
	for _, slug := range []string{"legacy1", "legacy2", "hasdefault"} {
		if _, err := ormer.Engine.Insert(&Organization{Owner: "admin", Name: slug}); err != nil {
			t.Fatalf("raw insert org %q: %v", slug, err)
		}
	}
	if _, err := AddProject(&Project{Owner: "hasdefault", Name: "default", Organization: "hasdefault", DisplayName: "Preexisting", IsDefault: true}); err != nil {
		t.Fatalf("seed preexisting default: %v", err)
	}

	created, err := BackfillDefaultProjects()
	if err != nil {
		t.Fatalf("BackfillDefaultProjects: %v", err)
	}
	if created != 2 {
		t.Errorf("first backfill created = %d, want 2 (legacy1, legacy2)", created)
	}

	// Rerun: nothing left to seed → 0 created (idempotent).
	created, err = BackfillDefaultProjects()
	if err != nil {
		t.Fatalf("BackfillDefaultProjects rerun: %v", err)
	}
	if created != 0 {
		t.Errorf("second backfill created = %d, want 0 (idempotent)", created)
	}

	// Every org — freshly seeded and preexisting — resolves to a contract-valid
	// default, and the preexisting DisplayName was never overwritten.
	for _, slug := range []string{"legacy1", "legacy2", "hasdefault"} {
		p, err := GetDefaultProject(slug)
		if err != nil {
			t.Fatalf("GetDefaultProject(%q): %v", slug, err)
		}
		assertDefaultProject(t, slug, p)
	}
	pre, _ := getProject("hasdefault", "default")
	if pre.DisplayName != "Preexisting" {
		t.Errorf("preexisting default DisplayName = %q, want %q (backfill must not modify existing projects)", pre.DisplayName, "Preexisting")
	}

	// Total project rows == number of orgs (exactly one default each, no dups).
	got, err := ormer.Engine.Count(new(Project))
	if err != nil {
		t.Fatalf("count projects: %v", err)
	}
	if got != 3 {
		t.Errorf("project row count = %d, want 3 (one default per org, no duplicates)", got)
	}
}

// TestSeededProjectRidesTheClaim proves the payoff: after seeding, the value
// generateJwtToken resolves for the `project` claim (GetDefaultProject(owner).Name)
// is "default", and it serializes onto the wire — through the REAL JWT claim
// surface — as project="default".
func TestSeededProjectRidesTheClaim(t *testing.T) {
	newSeedTestOrmer(t)

	const slug = "hanzo"
	if _, err := AddOrganization(&Organization{Owner: "admin", Name: slug, DisplayName: "Hanzo"}); err != nil {
		t.Fatalf("AddOrganization: %v", err)
	}

	// Resolve exactly as generateJwtToken does: GetDefaultProject(user.Owner).Name.
	user := &User{Owner: slug, Name: "alice", Id: slug + "/alice"}
	def, err := GetDefaultProject(user.Owner)
	if err != nil {
		t.Fatalf("GetDefaultProject: %v", err)
	}
	if def == nil || def.Name != "default" {
		t.Fatalf("resolved project = %v, want name %q", def, "default")
	}

	claims := Claims{User: user, TokenType: "access-token", Scope: "openid", Project: def.Name}
	for surface, m := range map[string]map[string]interface{}{
		"JWT (default)": jsonClaims(t, getClaimsWithoutThirdIdp(claims)),
		"JWT-Empty":     jsonClaims(t, getShortClaims(claims)),
		"JWT-Standard":  jsonClaims(t, getStandardClaims(claims)),
		"JWT-Custom":    getClaimsCustom(claims, []string{"email"}, nil),
	} {
		if got, ok := m["project"]; !ok || got != "default" {
			t.Errorf("%s: project claim = %v (present=%v), want %q", surface, got, ok, "default")
		}
	}
}
