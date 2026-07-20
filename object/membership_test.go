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

// newMembershipTestOrmer wires the package `ormer` to a fresh in-memory sqlite
// engine with exactly the tables the membership plane touches. Mirrors
// newProjectTestOrmer; restores the previous ormer on cleanup.
func newMembershipTestOrmer(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + dir + "/membership.db?_journal_mode=WAL&_busy_timeout=5000"
	engine, err := xorm.NewEngine("sqlite", dsn)
	if err != nil {
		t.Fatalf("xorm.NewEngine: %v", err)
	}
	engine.SetTableMapper(names.NewPrefixMapper(names.SnakeMapper{}, ""))
	for _, tbl := range []interface{}{new(Organization), new(User), new(Membership)} {
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

// TestEnsureMembershipIdempotent proves EnsureMembership creates a (user, org)
// row once, is a no-op on rerun, and never downgrades an existing role — the
// guarantees that make it safe at every org-birth path and on every boot.
func TestEnsureMembershipIdempotent(t *testing.T) {
	newMembershipTestOrmer(t)

	const user, org = "hanzo/alice", "acme-team"

	added, err := EnsureMembership(user, org, MembershipRoleOwner)
	if err != nil || !added {
		t.Fatalf("first EnsureMembership: added=%v err=%v (want true, nil)", added, err)
	}

	// Rerun with a LOWER role must not create a second row nor downgrade.
	added, err = EnsureMembership(user, org, MembershipRoleMember)
	if err != nil || added {
		t.Fatalf("second EnsureMembership: added=%v err=%v (want false, nil)", added, err)
	}
	got, err := getMembership(user, org)
	if err != nil || got == nil {
		t.Fatalf("getMembership: %v (row=%v)", err, got)
	}
	if got.Role != MembershipRoleOwner {
		t.Errorf("role = %q, want %q (Ensure must never downgrade)", got.Role, MembershipRoleOwner)
	}
	if n, _ := ormer.Engine.Count(new(Membership)); n != 1 {
		t.Errorf("row count = %d, want 1 (no duplicate on the (user,org) pair)", n)
	}
}

// TestMemberOrgRefsHomePlusTeams proves the resolver the token uses: the HOME org
// is always present and FIRST (even with no explicit row), team memberships are
// unioned in, and a duplicate of home is deduped (home wins its role).
func TestMemberOrgRefsHomePlusTeams(t *testing.T) {
	newMembershipTestOrmer(t)

	// alice's home org is "acme"; she is an admin there. She is also a member of
	// "beta-team" and (redundantly) has an explicit row for her home org that must
	// NOT duplicate.
	user := &User{Owner: "acme", Name: "alice", Id: "acme/alice", IsAdmin: true}
	if _, err := EnsureMembership(user.GetId(), "beta-team", MembershipRoleMember); err != nil {
		t.Fatalf("ensure beta-team: %v", err)
	}
	if _, err := EnsureMembership(user.GetId(), "acme", MembershipRoleMember); err != nil {
		t.Fatalf("ensure home dup: %v", err)
	}

	refs := MemberOrgRefs(user)
	if len(refs) != 2 {
		t.Fatalf("orgs = %+v, want 2 (acme home + beta-team, home deduped)", refs)
	}
	if refs[0].Org != "acme" || refs[0].Role != MembershipRoleAdmin {
		t.Errorf("orgs[0] = %+v, want {acme admin} (home first, synthesized role wins the dup)", refs[0])
	}
	if refs[1].Org != "beta-team" || refs[1].Role != MembershipRoleMember {
		t.Errorf("orgs[1] = %+v, want {beta-team member}", refs[1])
	}
}

// TestMemberOrgRefsHomeOnlyWithoutRows proves a user with NO membership rows still
// gets their home org in the claim — the synthesis that keeps every valid token
// scoped to at least its own org before any backfill runs.
func TestMemberOrgRefsHomeOnlyWithoutRows(t *testing.T) {
	newMembershipTestOrmer(t)
	user := &User{Owner: "solo", Name: "bob", Id: "solo/bob"}
	refs := MemberOrgRefs(user)
	if len(refs) != 1 || refs[0].Org != "solo" || refs[0].Role != MembershipRoleMember {
		t.Errorf("orgs = %+v, want exactly {solo member}", refs)
	}
}

// TestBackfillMembershipsIdempotent proves the boot backfill seeds a HOME
// membership for every user missing one, skips those already seeded, and is a
// no-op on rerun.
func TestBackfillMembershipsIdempotent(t *testing.T) {
	newMembershipTestOrmer(t)

	users := []*User{
		{Owner: "acme", Name: "alice", Id: "acme/alice", IsAdmin: true},
		{Owner: "acme", Name: "carol", Id: "acme/carol"},
		{Owner: "beta", Name: "dave", Id: "beta/dave"},
	}
	for _, u := range users {
		if _, err := ormer.Engine.Insert(u); err != nil {
			t.Fatalf("insert user %q: %v", u.GetId(), err)
		}
	}
	// carol already carries an explicit home membership — backfill must skip her.
	if _, err := EnsureMembership("acme/carol", "acme", MembershipRoleMember); err != nil {
		t.Fatalf("pre-seed carol: %v", err)
	}

	created, err := BackfillMemberships()
	if err != nil {
		t.Fatalf("BackfillMemberships: %v", err)
	}
	if created != 2 {
		t.Errorf("first backfill created = %d, want 2 (alice, dave; carol already had one)", created)
	}

	created, err = BackfillMemberships()
	if err != nil {
		t.Fatalf("BackfillMemberships rerun: %v", err)
	}
	if created != 0 {
		t.Errorf("second backfill created = %d, want 0 (idempotent)", created)
	}

	// alice is an org admin → her home role is admin; carol/dave are members.
	if m, _ := getMembership("acme/alice", "acme"); m == nil || m.Role != MembershipRoleAdmin {
		t.Errorf("alice home membership = %v, want role admin", m)
	}
	if n, _ := ormer.Engine.Count(new(Membership)); n != 3 {
		t.Errorf("membership rows = %d, want 3 (one home per user)", n)
	}
}

// TestMembershipRidesTheClaim proves the payoff: the resolved membership set
// serializes onto the wire — through EVERY real JWT claim surface — as an `orgs`
// array carrying the user's orgs.
func TestMembershipRidesTheClaim(t *testing.T) {
	newMembershipTestOrmer(t)

	user := &User{Owner: "hanzo", Name: "alice", Id: "hanzo/alice"}
	if _, err := EnsureMembership(user.GetId(), "acme-team", MembershipRoleMember); err != nil {
		t.Fatalf("ensure team: %v", err)
	}

	claims := Claims{User: user, TokenType: "access-token", Scope: "openid", Orgs: MemberOrgRefs(user)}
	for surface, m := range map[string]map[string]interface{}{
		"JWT (default)": jsonClaims(t, getClaimsWithoutThirdIdp(claims)),
		"JWT-Empty":     jsonClaims(t, getShortClaims(claims)),
		"JWT-Standard":  jsonClaims(t, getStandardClaims(claims)),
		"JWT-Custom":    getClaimsCustom(claims, []string{"email"}, nil),
	} {
		raw, ok := m["orgs"]
		if !ok {
			t.Errorf("%s: orgs claim absent", surface)
			continue
		}
		orgs, ok := raw.([]interface{})
		if !ok {
			// JWT-Custom carries the native []OrgRef (no JSON round-trip); handle it.
			if native, isNative := raw.([]OrgRef); isNative {
				if len(native) != 2 || native[0].Org != "hanzo" || native[1].Org != "acme-team" {
					t.Errorf("%s: orgs = %+v, want [hanzo, acme-team]", surface, native)
				}
				continue
			}
			t.Errorf("%s: orgs claim is %T, want array", surface, raw)
			continue
		}
		if len(orgs) != 2 {
			t.Errorf("%s: orgs len = %d, want 2 (hanzo home + acme-team)", surface, len(orgs))
		}
	}
}
