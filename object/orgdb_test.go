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
	"os"
	"path/filepath"
	"testing"
)

func TestOrgDBValidateSlug(t *testing.T) {
	tests := []struct {
		slug    string
		wantErr bool
	}{
		{"example", false},
		{"hanzo", false},
		{"my-org", false},
		{"org123", false},
		{"a", false},
		{"", true},
		{".", true},
		{"..", true},
		{"My-Org", true},      // uppercase
		{"org/bad", true},     // slash
		{"org bad", true},     // space
		{"org_bad", true},     // underscore not allowed
		{"../escape", true},   // path traversal
		{"org\x00null", true}, // null byte
	}

	for _, tt := range tests {
		err := validateOrgSlug(tt.slug)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateOrgSlug(%q) error = %v, wantErr = %v", tt.slug, err, tt.wantErr)
		}
	}
}

func TestOrgDBManagerProvision(t *testing.T) {
	dir := t.TempDir()

	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager: %v", err)
	}
	defer mgr.ReleasePools()

	// Provision an org.
	if err := mgr.ProvisionOrg("test-org"); err != nil {
		t.Fatalf("ProvisionOrg: %v", err)
	}

	// Verify directory structure.
	dbPath := filepath.Join(dir, "orgs", "test-org", "iam.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatalf("expected db file at %s, not found", dbPath)
	}

	// GetEngine should return the same engine.
	eng1, err := mgr.GetEngine("test-org")
	if err != nil {
		t.Fatalf("GetEngine: %v", err)
	}
	eng2, err := mgr.GetEngine("test-org")
	if err != nil {
		t.Fatalf("GetEngine (2nd call): %v", err)
	}
	if eng1 != eng2 {
		t.Error("GetEngine returned different engines for the same org")
	}
}

func TestOrgDBManagerListOrgs(t *testing.T) {
	dir := t.TempDir()

	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager: %v", err)
	}
	defer mgr.ReleasePools()

	// Empty initially.
	orgs, err := mgr.ListOrgs()
	if err != nil {
		t.Fatalf("ListOrgs: %v", err)
	}
	if len(orgs) != 0 {
		t.Errorf("expected 0 orgs, got %d", len(orgs))
	}

	// Provision two orgs.
	for _, slug := range []string{"alpha", "beta"} {
		if err := mgr.ProvisionOrg(slug); err != nil {
			t.Fatalf("ProvisionOrg(%s): %v", slug, err)
		}
	}

	orgs, err = mgr.ListOrgs()
	if err != nil {
		t.Fatalf("ListOrgs: %v", err)
	}
	if len(orgs) != 2 {
		t.Errorf("expected 2 orgs, got %d", len(orgs))
	}
}

func TestOrgDBManagerDeleteOrg(t *testing.T) {
	dir := t.TempDir()

	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager: %v", err)
	}
	defer mgr.ReleasePools()

	if err := mgr.ProvisionOrg("doomed"); err != nil {
		t.Fatalf("ProvisionOrg: %v", err)
	}

	if err := mgr.DeleteOrg("doomed"); err != nil {
		t.Fatalf("DeleteOrg: %v", err)
	}

	orgDir := filepath.Join(dir, "orgs", "doomed")
	if _, err := os.Stat(orgDir); !os.IsNotExist(err) {
		t.Errorf("expected org directory to be deleted, but it still exists")
	}

	// Listing should return empty.
	orgs, err := mgr.ListOrgs()
	if err != nil {
		t.Fatalf("ListOrgs: %v", err)
	}
	if len(orgs) != 0 {
		t.Errorf("expected 0 orgs after delete, got %d", len(orgs))
	}
}

func TestOrgDBManagerInvalidSlug(t *testing.T) {
	dir := t.TempDir()

	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager: %v", err)
	}
	defer mgr.ReleasePools()

	if err := mgr.ProvisionOrg("../escape"); err == nil {
		t.Error("expected error for path traversal slug, got nil")
	}

	if _, err := mgr.GetEngine(""); err == nil {
		t.Error("expected error for empty slug, got nil")
	}

	if _, err := mgr.GetEngine("Bad-Slug"); err == nil {
		t.Error("expected error for uppercase slug, got nil")
	}
}

func TestOrgDBManagerTableSync(t *testing.T) {
	dir := t.TempDir()

	mgr, err := NewOrgDBManager(dir)
	if err != nil {
		t.Fatalf("NewOrgDBManager: %v", err)
	}
	defer mgr.ReleasePools()

	if err := mgr.ProvisionOrg("table-test"); err != nil {
		t.Fatalf("ProvisionOrg: %v", err)
	}

	eng, err := mgr.GetEngine("table-test")
	if err != nil {
		t.Fatalf("GetEngine: %v", err)
	}

	// Verify that the user table exists by doing a count.
	count, err := eng.Count(&User{})
	if err != nil {
		t.Fatalf("Count(User): %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 users in fresh org db, got %d", count)
	}

	// Verify that the application table exists.
	count, err = eng.Count(&Application{})
	if err != nil {
		t.Fatalf("Count(Application): %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 applications in fresh org db, got %d", count)
	}

	// Verify that the token table exists.
	count, err = eng.Count(&Token{})
	if err != nil {
		t.Fatalf("Count(Token): %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 tokens in fresh org db, got %d", count)
	}
}

func TestOrgEngineFallback(t *testing.T) {
	// When OrgDBManager is nil (isolation disabled), orgEngine should return
	// the global engine for any owner.
	if ormer == nil {
		t.Skip("ormer not initialized (need InitConfig for this test)")
	}

	saved := ormer.OrgDBManager
	ormer.OrgDBManager = nil
	defer func() { ormer.OrgDBManager = saved }()

	eng := orgEngine("any-org")
	if eng != ormer.Engine {
		t.Error("orgEngine should return global engine when OrgDBManager is nil")
	}

	eng = orgEngine("")
	if eng != ormer.Engine {
		t.Error("orgEngine should return global engine for empty owner")
	}
}
