// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store_test

import (
	"path/filepath"
	"testing"

	"github.com/hanzoai/iam/pkg/model"
	"github.com/hanzoai/iam/pkg/store"
	"github.com/hanzoai/iam/server"
)

func TestProjectStore_AddGetListDelete(t *testing.T) {
	// Open the SAME embedded SQLite store a host binary (cloud) opens via the public
	// embedding surface, so the test exercises the exact binding the embedder uses.
	sdb, err := server.OpenSQLite(filepath.Join(t.TempDir(), "store.db"))
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer func() { _ = sdb.Close() }()

	// Add: two projects for org "hanzo", one for org "acme" (tenant isolation probe).
	for _, p := range []*model.Project{
		{Owner: "hanzo", Name: "alpha", DisplayName: "Alpha", Description: "a"},
		{Owner: "hanzo", Name: "beta", DisplayName: "Beta"},
		{Owner: "acme", Name: "gamma", DisplayName: "Gamma"},
	} {
		ok, err := store.AddProject(sdb, p)
		if err != nil || !ok {
			t.Fatalf("AddProject(%s/%s): ok=%v err=%v", p.Owner, p.Name, ok, err)
		}
	}

	// Get by "owner/name" id — hit.
	got, err := store.GetProject(sdb, "hanzo/alpha")
	if err != nil {
		t.Fatalf("GetProject hit: %v", err)
	}
	if got == nil || got.Owner != "hanzo" || got.Name != "alpha" || got.DisplayName != "Alpha" {
		t.Fatalf("GetProject hit: unexpected %+v", got)
	}
	if got.Organization != "hanzo" {
		t.Fatalf("Organization should default to Owner, got %q", got.Organization)
	}

	// Get miss → (nil, nil), the embedder pre-check convention.
	miss, err := store.GetProject(sdb, "hanzo/nope")
	if err != nil || miss != nil {
		t.Fatalf("GetProject miss: want (nil,nil), got (%v,%v)", miss, err)
	}

	// Tenant isolation: hanzo sees only its two, never acme's gamma.
	orgRows, err := store.GetOrganizationProjects(sdb, "hanzo")
	if err != nil {
		t.Fatalf("GetOrganizationProjects: %v", err)
	}
	if len(orgRows) != 2 {
		t.Fatalf("GetOrganizationProjects(hanzo): want 2, got %d (%v)", len(orgRows), names(orgRows))
	}
	for _, p := range orgRows {
		if p.Owner != "hanzo" {
			t.Fatalf("tenant leak: got project owned by %q", p.Owner)
		}
	}

	// Unscoped admin view: empty owner lists all three across orgs.
	all, err := store.GetProjects(sdb, "")
	if err != nil {
		t.Fatalf("GetProjects(all): %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("GetProjects(all): want 3, got %d (%v)", len(all), names(all))
	}

	// Delete a real project → true, then it is gone.
	ok, err := store.DeleteProject(sdb, &model.Project{Owner: "hanzo", Name: "alpha"})
	if err != nil || !ok {
		t.Fatalf("DeleteProject: ok=%v err=%v", ok, err)
	}
	gone, err := store.GetProject(sdb, "hanzo/alpha")
	if err != nil || gone != nil {
		t.Fatalf("after delete: want (nil,nil), got (%v,%v)", gone, err)
	}

	// Delete a missing project → (false, nil), affected-rows semantics.
	ok, err = store.DeleteProject(sdb, &model.Project{Owner: "hanzo", Name: "nope"})
	if err != nil || ok {
		t.Fatalf("DeleteProject miss: want (false,nil), got (%v,%v)", ok, err)
	}
}

func names(ps []*model.Project) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.Owner+"/"+p.Name)
	}
	return out
}
