// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invariants_test

import (
	"fmt"
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

// R7 row 7 (I18, R2): exactly one statement in the module files an account under
// the admin directory, inside the constructor grantSuperAdmin calls, and that
// constructor has one caller — read through the types, so a constant, a renamed
// import or a closure cannot hide one. Every statement that writes an account's
// owner from a value known only at run time is listed too: each is a creation
// path the dynamic half (admits-admin, per path) must hold, and a new one fails.
func TestAdminNamespaceInvariants_oneAdminWriter(t *testing.T) {
	w := scan(t)
	const home = "internal/superadmin/superadmin.go:newAdmin"
	var found []string
	inside := false
	for _, s := range strs(w.admin) {
		if s == home {
			inside = true
			continue
		}
		found = append(found, s)
	}
	if !inside {
		found = append(found, "no statement files an account under admin inside grantSuperAdmin")
	}
	if got := strs(w.callers); !slices.Equal(got, []string{"internal/superadmin/superadmin.go:appoint"}) {
		found = append(found, fmt.Sprintf("newAdmin is called from %v", got))
	}
	invariants.Report(t, "I18 static", found)
	invariants.Report(t, "I18 dynamic-owner", strs(w.dynamic))
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
