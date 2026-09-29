// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invariants_test

import (
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"github.com/hanzoai/iam/internal/invariants"
)

func root(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// R7 row 3 (I17): no field, json key or column on any type an account reaches
// names authority.
func TestAdminNamespaceInvariants_noAccountAdminField(t *testing.T) {
	invariants.Report(t, "I17", invariants.AdminFields())
}

// R7 row 7 (I18, R2), static half: exactly one statement in the module files an
// account under admin, inside the constructor grantSuperAdmin calls, and that
// constructor has one caller.
func TestAdminNamespaceInvariants_oneAdminWriter(t *testing.T) {
	sites, err := invariants.AdminWriters(root(t))
	if err != nil {
		t.Fatal(err)
	}
	const home = "internal/superadmin/superadmin.go:newAdmin"
	var found []string
	inside := 0
	for _, s := range sites {
		if s.String() == home {
			inside++
			continue
		}
		found = append(found, s.String())
	}
	if inside == 0 {
		found = append(found, "no statement files an account under admin inside grantSuperAdmin")
	}
	calls, err := invariants.Calls(root(t), "superadmin", "newAdmin")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(calls, []string{"internal/superadmin/superadmin.go:appoint"}) {
		found = append(found, "newAdmin has callers other than appoint")
	}
	invariants.Report(t, "I18 static", found)
}

// The ledger names only rules it knows, and a row with nothing known enforces.
func TestAdminNamespaceInvariants_ledgerIsTight(t *testing.T) {
	for key, r := range invariants.Ledger {
		if r.Mode == invariants.Reporting && len(r.Known) == 0 {
			t.Errorf("%s reports with nothing known; flip it to enforcing", key)
		}
		if r.Mode == invariants.Enforcing && len(r.Known) > 0 {
			t.Errorf("%s enforces and still lists known violations", key)
		}
		if r.Rule == "" {
			t.Errorf("%s names no rule", key)
		}
	}
}
