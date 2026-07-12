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

// verifyOnly returns a verify func that passes only for the given (owner,name)
// rows — a stand-in for a per-row password check, so selectVerifyingRow's
// ordering/preference logic can be exercised without a DB or real crypto.
func verifyOnly(ids ...string) func(*User) bool {
	set := map[string]bool{}
	for _, id := range ids {
		set[id] = true
	}
	return func(u *User) bool { return set[u.Owner+"/"+u.Name] }
}

// TestSelectVerifyingRow_PrefersOtherOrgWhenResolvedFails is the core bug:
// org-agnostic login resolves to the global-admin row (admin/z) whose hash has
// drifted; the matching hash lives in hanzo/z. Resolution must land on hanzo/z.
func TestSelectVerifyingRow_PrefersOtherOrgWhenResolvedFails(t *testing.T) {
	resolved := &User{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"}
	candidates := []*User{
		{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"},
		{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"},
		{Owner: "built-in", Name: "z", Email: "z@hanzo.ai"},
	}

	got := selectVerifyingRow(resolved, candidates, verifyOnly("hanzo/z"))
	if got == nil || got.Owner != "hanzo" {
		t.Fatalf("want hanzo/z, got %v", got)
	}
}

// TestSelectVerifyingRow_ExcludesSuperAdminAmongVerifiers is the H-3 fix
// (this test previously asserted the VULNERABLE behavior — that the global-admin
// org "wins" a collision). When several rows verify INCLUDING the global-admin
// row, the admin row must NOT be selected: an org-agnostic collision must never
// silently escalate a tenant login to a global-admin session. Resolution lands
// on the deterministic non-admin tenant row. Global-admin login requires an
// explicit organization == conf.AdminOrg instead.
func TestSelectVerifyingRow_ExcludesSuperAdminAmongVerifiers(t *testing.T) {
	resolved := &User{Owner: "built-in", Name: "z", Email: "z@hanzo.ai"}
	candidates := []*User{
		{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"},
		{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"},
		{Owner: "lux", Name: "z", Email: "z@hanzo.ai"},
	}

	// admin/z, hanzo/z and lux/z all verify; admin must be refused and the
	// deterministic non-admin winner (hanzo/z, by owner sort) returned.
	got := selectVerifyingRow(resolved, candidates, verifyOnly(conf.AdminOrg+"/z", "hanzo/z", "lux/z"))
	if got == nil {
		t.Fatal("want a non-admin tenant row, got nil")
	}
	if got.Owner == conf.AdminOrg {
		t.Fatalf("H-3: collision must never resolve to global-admin org, got %s/%s", got.Owner, got.Name)
	}
	if got.Owner != "hanzo" {
		t.Fatalf("want deterministic hanzo/z, got %s/%s", got.Owner, got.Name)
	}
}

// TestSelectVerifyingRow_SkipsResolvedRow makes sure the already-failed row is
// never re-selected even if the verify func would (incorrectly) pass it.
func TestSelectVerifyingRow_SkipsResolvedRow(t *testing.T) {
	resolved := &User{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"}
	candidates := []*User{
		{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"},
		{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"},
	}

	got := selectVerifyingRow(resolved, candidates, verifyOnly(conf.AdminOrg+"/z", "hanzo/z"))
	if got == nil || got.Owner != "hanzo" {
		t.Fatalf("resolved row must be skipped; want hanzo/z, got %v", got)
	}
}

// TestSelectVerifyingRow_NoneVerify returns nil so the caller surfaces the
// original "password or code is incorrect".
func TestSelectVerifyingRow_NoneVerify(t *testing.T) {
	resolved := &User{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"}
	candidates := []*User{
		{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai"},
		{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"},
	}

	if got := selectVerifyingRow(resolved, candidates, verifyOnly("nobody/none")); got != nil {
		t.Fatalf("want nil when nothing verifies, got %v", got)
	}
}

// TestSelectVerifyingRow_SkipsUnusableRows ensures deleted/forbidden/LDAP/guest
// rows are never selected even if their password would verify.
func TestSelectVerifyingRow_SkipsUnusableRows(t *testing.T) {
	resolved := &User{Owner: "built-in", Name: "z", Email: "z@hanzo.ai"}
	candidates := []*User{
		{Owner: conf.AdminOrg, Name: "z", Email: "z@hanzo.ai", IsForbidden: true},
		{Owner: "lux", Name: "z", Email: "z@hanzo.ai", IsDeleted: true},
		{Owner: "zoo", Name: "z", Email: "z@hanzo.ai", Ldap: "ldap-server"},
		{Owner: "pars", Name: "z", Email: "z@hanzo.ai", Tag: "guest-user"},
		{Owner: "hanzo", Name: "z", Email: "z@hanzo.ai"},
	}

	// Every row "verifies", but only hanzo/z is usable.
	got := selectVerifyingRow(resolved, candidates,
		verifyOnly(conf.AdminOrg+"/z", "lux/z", "zoo/z", "pars/z", "hanzo/z"))
	if got == nil || got.Owner != "hanzo" {
		t.Fatalf("want hanzo/z (others unusable), got %v", got)
	}
}
