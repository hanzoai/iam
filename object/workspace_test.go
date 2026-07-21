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

	"github.com/hanzoai/xorm"
	"github.com/hanzoai/xorm/names"
)

// newWorkspaceTestOrmer wires the package `ormer` to a fresh in-memory sqlite
// engine with the org + workspace + project tables — the Organization → Workspace
// → Project hierarchy — and restores the previous ormer on cleanup.
func newWorkspaceTestOrmer(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + dir + "/workspace.db?_journal_mode=WAL&_busy_timeout=5000"
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine: %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	for _, tbl := range []interface{}{new(Organization), new(Workspace), new(Project)} {
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

// TestWorkspaceCRUD proves the full lifecycle end-to-end: add → get by id → list
// under org → update → default resolution → delete. This is the identity keystone
// (Organization → Workspace → Project), so it must round-trip natively.
func TestWorkspaceCRUD(t *testing.T) {
	newWorkspaceTestOrmer(t)

	// ADD two workspaces under org "acme", one marked default.
	ok, err := AddWorkspace(&Workspace{Owner: "acme", Name: "engineering", DisplayName: "Engineering", Organization: "acme", IsDefault: true})
	if err != nil || !ok {
		t.Fatalf("AddWorkspace(engineering): ok=%v err=%v", ok, err)
	}
	if ok, err := AddWorkspace(&Workspace{Owner: "acme", Name: "design", DisplayName: "Design", Organization: "acme"}); err != nil || !ok {
		t.Fatalf("AddWorkspace(design): ok=%v err=%v", ok, err)
	}
	// A workspace under a DIFFERENT org — must never leak into acme's reads.
	if ok, err := AddWorkspace(&Workspace{Owner: "globex", Name: "engineering", Organization: "globex"}); err != nil || !ok {
		t.Fatalf("AddWorkspace(globex): ok=%v err=%v", ok, err)
	}

	// GET by id (owner/name).
	got, err := GetWorkspace("acme/engineering")
	if err != nil || got == nil {
		t.Fatalf("GetWorkspace: got=%v err=%v", got, err)
	}
	if got.DisplayName != "Engineering" || got.Organization != "acme" {
		t.Fatalf("GetWorkspace fields: %+v", got)
	}

	// LIST under org — exactly the two acme workspaces, never globex's.
	list, err := GetOrganizationWorkspaces("acme")
	if err != nil {
		t.Fatalf("GetOrganizationWorkspaces: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("GetOrganizationWorkspaces(acme) = %d, want 2 (tenant isolation)", len(list))
	}

	// DEFAULT resolution — the IsDefault row, not just any.
	def, err := GetDefaultWorkspace("acme")
	if err != nil || def == nil {
		t.Fatalf("GetDefaultWorkspace: def=%v err=%v", def, err)
	}
	if def.Name != "engineering" {
		t.Fatalf("GetDefaultWorkspace = %q, want engineering", def.Name)
	}

	// UPDATE — bind the S3 bucket handle, confirm it round-trips.
	got.Bucket = "acme-engineering-a1b2"
	if ok, err := UpdateWorkspace("acme/engineering", got); err != nil || !ok {
		t.Fatalf("UpdateWorkspace: ok=%v err=%v", ok, err)
	}
	re, _ := GetWorkspace("acme/engineering")
	if re == nil || re.Bucket != "acme-engineering-a1b2" {
		t.Fatalf("UpdateWorkspace bucket not persisted: %+v", re)
	}

	// A Project can now name its parent Workspace (the FK) — the full hierarchy.
	if ok, err := AddProject(&Project{Owner: "acme", Name: "api", Organization: "acme", Workspace: "engineering"}); err != nil || !ok {
		t.Fatalf("AddProject under workspace: ok=%v err=%v", ok, err)
	}
	p, _ := GetProject("acme/api")
	if p == nil || p.Workspace != "engineering" {
		t.Fatalf("Project.Workspace FK not persisted: %+v", p)
	}

	// DELETE.
	if ok, err := DeleteWorkspace(&Workspace{Owner: "acme", Name: "design"}); err != nil || !ok {
		t.Fatalf("DeleteWorkspace: ok=%v err=%v", ok, err)
	}
	list, _ = GetOrganizationWorkspaces("acme")
	if len(list) != 1 {
		t.Fatalf("after delete: %d workspaces, want 1", len(list))
	}
}
