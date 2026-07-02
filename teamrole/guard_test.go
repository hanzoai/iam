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

package teamrole

import (
	"errors"
	"testing"
)

// ---- Catalog integrity ---------------------------------------------------

// TestCatalogMatchesSpec pins the exact roles the CTO specified. If someone
// renames or drops a role, this fails loudly — the catalog is a contract shared
// with the client and the seed path.
func TestCatalogMatchesSpec(t *testing.T) {
	want := map[string]struct {
		app  App
		tier Tier
		rank int
	}{
		"billing:viewer": {AppBilling, TierViewer, 10},
		"billing:admin":  {AppBilling, TierAdmin, 20},
		"console:viewer": {AppConsole, TierViewer, 10},
		"console:admin":  {AppConsole, TierAdmin, 20},
		"console:owner":  {AppConsole, TierOwner, 30},
		"org:owner":      {AppOrg, TierOwner, 100},
	}
	got := Catalog()
	if len(got) != len(want) {
		t.Fatalf("catalog size = %d, want %d", len(got), len(want))
	}
	for _, r := range got {
		w, ok := want[r.Key]
		if !ok {
			t.Fatalf("unexpected role %q in catalog", r.Key)
		}
		if r.App != w.app || r.Tier != w.tier || r.Rank != w.rank {
			t.Errorf("role %q = {app:%s tier:%s rank:%d}, want {app:%s tier:%s rank:%d}",
				r.Key, r.App, r.Tier, r.Rank, w.app, w.tier, w.rank)
		}
		if len(r.Actions) == 0 || r.Resource == "" || r.DisplayName == "" {
			t.Errorf("role %q missing resource/actions/displayName", r.Key)
		}
	}
}

// TestRanksStrictlyOrdered ensures the ceiling is total: admin < console:owner
// < org:owner, and org:owner is unreachable by app accumulation.
func TestRanksStrictlyOrdered(t *testing.T) {
	get := func(k string) Role { r, _ := Lookup(k); return r }
	if !(get("billing:viewer").Rank < get("billing:admin").Rank) {
		t.Error("viewer must rank below admin")
	}
	if !(get("console:admin").Rank < get("console:owner").Rank) {
		t.Error("admin must rank below console:owner")
	}
	if !(get("console:owner").Rank < get("org:owner").Rank) {
		t.Error("console:owner must rank below org:owner")
	}
	// org:owner is far above any app-admin so it can never be reached by
	// holding multiple app-admin roles.
	if get("org:owner").Rank <= get("billing:admin").Rank+get("console:admin").Rank {
		t.Error("org:owner rank must exceed the sum of app-admin ranks (unreachable by accumulation)")
	}
}

func TestLookupAndIsManaged(t *testing.T) {
	if _, ok := Lookup("billing:admin"); !ok {
		t.Error("billing:admin must be managed")
	}
	if _, ok := Lookup("billing:supergod"); ok {
		t.Error("unknown key must not be managed")
	}
	if IsManaged("console-admin") { // hyphen, not the canonical colon key
		t.Error("only exact catalog keys are managed")
	}
	if !IsManaged("org:owner") {
		t.Error("org:owner must be managed")
	}
}

func TestAppTiers(t *testing.T) {
	billing := AppTiers(AppBilling)
	if len(billing) != 2 {
		t.Fatalf("billing tiers = %d, want 2 (viewer, admin)", len(billing))
	}
	if billing[0].Rank > billing[1].Rank {
		t.Error("AppTiers must be ordered by rank ascending")
	}
	if got := len(AppTiers(AppConsole)); got != 3 {
		t.Errorf("console tiers = %d, want 3 (viewer, admin, owner)", got)
	}
}

// ---- EffectiveRank -------------------------------------------------------

func TestEffectiveRank(t *testing.T) {
	cases := []struct {
		name    string
		keys    []string
		app     App
		want    int
	}{
		{"no roles", nil, AppBilling, 0},
		{"billing admin in billing", []string{"billing:admin"}, AppBilling, 20},
		{"billing admin has ZERO in console", []string{"billing:admin"}, AppConsole, 0},
		{"console owner in console", []string{"console:owner"}, AppConsole, 30},
		{"org owner dominates billing", []string{"org:owner"}, AppBilling, 100},
		{"org owner dominates console", []string{"org:owner"}, AppConsole, 100},
		{"highest of several in-app", []string{"billing:viewer", "billing:admin"}, AppBilling, 20},
		{"forged/unknown key ignored", []string{"billing:root", "not-a-role"}, AppBilling, 0},
		{"mixed apps score per app", []string{"billing:admin", "console:viewer"}, AppConsole, 10},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := EffectiveRank(tc.keys, tc.app); got != tc.want {
				t.Errorf("EffectiveRank(%v, %s) = %d, want %d", tc.keys, tc.app, got, tc.want)
			}
		})
	}
}

// ---- CheckAssignment: the core authorization proof -----------------------

func TestCheckAssignment(t *testing.T) {
	const org = "acme"
	const other = "globex"

	cases := []struct {
		name    string
		a       Assignment
		wantErr error // nil = allowed; else the sentinel it must wrap
	}{
		// -- legitimate delegation ------------------------------------------
		{
			"billing admin grants billing viewer (delegation)",
			Assignment{CallerKeys: []string{"billing:admin"}, CallerOrg: org, TargetOrg: org, TargetKey: "billing:viewer"},
			nil,
		},
		{
			"billing admin grants billing admin (peer delegation)",
			Assignment{CallerKeys: []string{"billing:admin"}, CallerOrg: org, TargetOrg: org, TargetKey: "billing:admin"},
			nil,
		},
		{
			"console admin grants console viewer",
			Assignment{CallerKeys: []string{"console:admin"}, CallerOrg: org, TargetOrg: org, TargetKey: "console:viewer"},
			nil,
		},
		{
			"console owner grants console owner",
			Assignment{CallerKeys: []string{"console:owner"}, CallerOrg: org, TargetOrg: org, TargetKey: "console:owner"},
			nil,
		},
		{
			"org owner grants anything in own org",
			Assignment{CallerKeys: []string{"org:owner"}, CallerOrg: org, TargetOrg: org, TargetKey: "org:owner"},
			nil,
		},
		{
			"org owner grants console admin (cross-app OK for owner)",
			Assignment{CallerKeys: []string{"org:owner"}, CallerOrg: org, TargetOrg: org, TargetKey: "console:admin"},
			nil,
		},
		{
			"superuser grants org owner cross-org",
			Assignment{CallerKeys: nil, CallerIsGlobalAdmin: true, CallerOrg: "admin", TargetOrg: other, TargetKey: "org:owner"},
			nil,
		},

		// -- VERTICAL privilege escalation (the headline Red vector) --------
		{
			// org:owner lives in the AppOrg surface where an app-admin holds
			// ZERO authority, so this is denied even harder than a rank
			// ceiling: only an existing org:owner (or superuser) has any
			// authority in the org app. This is the strongest possible barrier
			// on minting a new org owner.
			"billing admin CANNOT grant org owner",
			Assignment{CallerKeys: []string{"billing:admin"}, CallerOrg: org, TargetOrg: org, TargetKey: "org:owner"},
			ErrInsufficientAuthority,
		},
		{
			// Same-app vertical escalation is caught by the rank ceiling:
			// console:admin (20) has authority in console but console:owner
			// (30) outranks it.
			"console admin CANNOT grant console owner (rank ceiling)",
			Assignment{CallerKeys: []string{"console:admin"}, CallerOrg: org, TargetOrg: org, TargetKey: "console:owner"},
			ErrRankCeiling,
		},
		{
			"billing viewer CANNOT self-escalate to billing admin",
			Assignment{CallerKeys: []string{"billing:viewer"}, CallerOrg: org, TargetOrg: org, TargetKey: "billing:admin"},
			ErrInsufficientAuthority,
		},

		// -- LATERAL (cross-app) escalation ---------------------------------
		{
			"billing admin CANNOT grant console admin",
			Assignment{CallerKeys: []string{"billing:admin"}, CallerOrg: org, TargetOrg: org, TargetKey: "console:admin"},
			ErrInsufficientAuthority,
		},
		{
			"console owner CANNOT grant billing admin",
			Assignment{CallerKeys: []string{"console:owner"}, CallerOrg: org, TargetOrg: org, TargetKey: "billing:admin"},
			ErrInsufficientAuthority,
		},

		// -- CROSS-ORG member manipulation (the second Red vector) ----------
		{
			"org owner of acme CANNOT touch globex",
			Assignment{CallerKeys: []string{"org:owner"}, CallerOrg: org, TargetOrg: other, TargetKey: "billing:viewer"},
			ErrCrossOrg,
		},
		{
			"billing admin CANNOT invite into another org",
			Assignment{CallerKeys: []string{"billing:admin"}, CallerOrg: org, TargetOrg: other, TargetKey: "billing:viewer"},
			ErrCrossOrg,
		},
		{
			"empty target org fails closed",
			Assignment{CallerKeys: []string{"org:owner"}, CallerOrg: org, TargetOrg: "", TargetKey: "billing:viewer"},
			ErrMissingOrg,
		},
		{
			"empty caller org fails closed",
			Assignment{CallerKeys: []string{"org:owner"}, CallerOrg: "", TargetOrg: org, TargetKey: "billing:viewer"},
			ErrMissingOrg,
		},

		// -- forged caller keys -> ignored, so no authority -----------------
		{
			"forged non-catalog key confers nothing",
			Assignment{CallerKeys: []string{"org:superadmin", "billing:root"}, CallerOrg: org, TargetOrg: org, TargetKey: "billing:viewer"},
			ErrInsufficientAuthority,
		},

		// -- unmanaged target -> caller falls through to ordinary authz -----
		{
			"unmanaged role is not our concern",
			Assignment{CallerKeys: []string{"org:owner"}, CallerOrg: org, TargetOrg: org, TargetKey: "some-custom-role"},
			ErrNotManaged,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := CheckAssignment(tc.a)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("CheckAssignment = %v, want allowed", err)
				}
				if !CanAssign(tc.a) {
					t.Fatal("CanAssign disagreed with CheckAssignment (want true)")
				}
				return
			}
			if err == nil {
				t.Fatalf("CheckAssignment = allowed, want %v", tc.wantErr)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("CheckAssignment = %v, want wrap of %v", err, tc.wantErr)
			}
			if CanAssign(tc.a) {
				t.Fatal("CanAssign disagreed with CheckAssignment (want false)")
			}
		})
	}
}

// TestRankCeilingIsReachable proves the rank-ceiling barrier is not vacuous: a
// same-app admin attempting to grant the higher owner tier in that same app is
// denied specifically by ErrRankCeiling (authority present, rank insufficient).
func TestRankCeilingIsReachable(t *testing.T) {
	err := CheckAssignment(Assignment{
		CallerKeys: []string{"console:admin"}, CallerOrg: "acme", TargetOrg: "acme", TargetKey: "console:owner",
	})
	if err == nil || !errors.Is(err, ErrRankCeiling) {
		t.Fatalf("want rank-ceiling denial, got %v", err)
	}
}

// ---- AssignableKeys (UX mirror) ------------------------------------------

func TestAssignableKeys(t *testing.T) {
	const org = "acme"
	cases := []struct {
		name  string
		keys  []string
		admin bool
		want  []string
	}{
		{"viewer assigns nothing", []string{"billing:viewer"}, false, []string{}},
		{"billing admin assigns billing tiers up to admin", []string{"billing:admin"}, false, []string{"billing:viewer", "billing:admin"}},
		{"console admin assigns console viewer+admin (not owner)", []string{"console:admin"}, false, []string{"console:viewer", "console:admin"}},
		{"console owner assigns all console", []string{"console:owner"}, false, []string{"console:viewer", "console:admin", "console:owner"}},
		{"org owner assigns everything", []string{"org:owner"}, false, []string{"billing:viewer", "billing:admin", "console:viewer", "console:admin", "console:owner", "org:owner"}},
		{"superuser assigns everything", nil, true, []string{"billing:viewer", "billing:admin", "console:viewer", "console:admin", "console:owner", "org:owner"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := AssignableKeys(tc.keys, org, tc.admin)
			if !equalStrings(got, tc.want) {
				t.Errorf("AssignableKeys = %v, want %v", got, tc.want)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
