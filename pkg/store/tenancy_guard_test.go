// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/pkg/store"
)

// HIP-0527 §8 R5 for the migration (§5 steps 5 and 10, classes A–E): it writes
// facts only. No migration operation creates an account under admin or makes a
// SuperAdmin — only an appointment does — and once every account has moved, each
// lives in id and I4, I8, I14 and I18 hold.
func TestAdminNamespace_migration(t *testing.T) {
	tn := store.NewTenancy("hanzo")
	var at int64
	next := func() int64 { at++; return at }
	var found []string
	check := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	// Today: an appointed SuperAdmin, a person under admin with no appointment
	// (A), people under brand orgs (B), under their own org of one (C), under a
	// named org they founded (D), and a program under an org (E).
	check(tn.Legacy("root-person", "hanzo", false))
	check(tn.Appoint("root", "root-person", store.Genesis, next()))
	check(tn.Legacy("stray", store.DirAdmin, false))
	for _, p := range []string{"b1", "c1", "d1", "e-owner"} {
		check(tn.Legacy(p, "hanzo", false))
	}
	check(tn.Legacy("prog", "acme", true))
	supers := func() []string {
		var out []string
		for _, a := range []string{"root", "stray", "root-person", "b1", "c1", "d1", "e-owner", "prog"} {
			if tn.SuperAdmin(a) {
				out = append(out, a)
			}
		}
		return out
	}
	grew := func(op string, before []string) {
		for _, a := range supers() {
			if !strings.Contains(" "+strings.Join(before, " ")+" ", " "+a+" ") {
				found = append(found, fmt.Sprintf("%s made %s a SuperAdmin", op, a))
			}
		}
	}
	// Step 5: orgs of one, the founded named org, the program's assignment.
	for _, p := range []string{"root-person", "b1", "c1", "d1", "e-owner"} {
		before := supers()
		check(tn.FoundHome(p, "h-"+p, "root", next()))
		grew("found home", before)
	}
	check(tn.Found("d1", "d1-co", "d1", next()))
	check(tn.Found("e-owner", "acme", "e-owner", next()))
	before := supers()
	check(tn.Enroll("prog", "acme", store.RoleMember, "e-owner", next()))
	grew("assign a program", before)
	// Step 10: every account moves to id; the stray leaves admin founding its org.
	for _, a := range []string{"root-person", "b1", "c1", "d1", "e-owner", "prog"} {
		before := supers()
		check(tn.Move(a, "", next()))
		grew("move", before)
	}
	before = supers()
	check(tn.Move("stray", "h-stray", next()))
	grew("move out of admin", before)
	if got := supers(); len(got) != 1 || got[0] != "root" {
		found = append(found, fmt.Sprintf("SuperAdmins after the migration: %v", got))
	}
	found = append(found, tn.Violations()...)
	invariants.Report(t, "I19 migration", found)
}
