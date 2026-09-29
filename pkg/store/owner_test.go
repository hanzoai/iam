// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testdb"
	"github.com/hanzoai/iam/pkg/schema"
)

func org(t *testing.T, db orm.DB, name, founder string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name, o.Founder = policy.AdminOrg, name, founder
	o.SetId(policy.AdminOrg + "/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func seedPerson(t *testing.T, db orm.DB, owner, name, id string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.SetId(id)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func trail(t *testing.T, db orm.DB, action string) int {
	t.Helper()
	n, err := orm.TypedQuery[schema.AuditLog](db).Filter("Action=", action).Count(context.Background())
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		t.Fatal(err)
	}
	return n
}

// No account of another org becomes a member of the admin org, whoever asks;
// the admin org's own accounts do.
func TestTheAdminOrgAdmitsOnlyItsOwnAccounts(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedPerson(t, db, "hanzo", "z", "uuid-hanzo-z")
	for _, user := range []string{"hanzo/z", "Admin/z", "z"} {
		if _, err := EnsureMembership(ctx, db, user, policy.AdminOrg, RoleMember); !errors.Is(err, ErrAdminOrgMember) {
			t.Errorf("%s into the admin org: %v, want ErrAdminOrgMember", user, err)
		}
	}
	if _, err := SetRole(ctx, db, "hanzo/z", policy.AdminOrg, RoleOwner, ""); !errors.Is(err, ErrAdminOrgMember) {
		t.Errorf("SetRole into the admin org: %v, want ErrAdminOrgMember", err)
	}
	if _, err := EnsureMembership(ctx, db, "admin/z", policy.AdminOrg, RoleAdmin); err != nil {
		t.Errorf("admin/z into its own org: %v", err)
	}
}

// An account that is some org's last owner is not deleted out from under it; one
// beside another owner is.
func TestTheLastOwnerKeepsTheAccount(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedPerson(t, db, "acme", "ann", "uuid-ann")
	seedPerson(t, db, "hanzo", "bob", "uuid-bob")
	if _, err := SetRole(ctx, db, "acme/ann", "acme", RoleOwner, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := ForgetUser(ctx, db, "acme/ann"); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("forgetting the last owner: %v, want ErrLastOwner", err)
	}
	if o, _ := Owners(ctx, db, "acme"); len(o) != 1 {
		t.Fatalf("owners after a refused forget = %v", o)
	}
	if _, err := SetRole(ctx, db, "hanzo/bob", "acme", RoleOwner, ""); err != nil {
		t.Fatal(err)
	}
	if n, err := ForgetUser(ctx, db, "acme/ann"); err != nil || n != 1 {
		t.Fatalf("forgetting an owner beside another: n=%d err=%v", n, err)
	}
	if o, _ := Owned(ctx, db, "hanzo/bob"); len(o) != 1 || o[0] != "acme" {
		t.Fatalf("bob owns %v, want [acme]", o)
	}
}

// Boot gives each ownerless org the founder it recorded, lists the rest, and
// files each finding once however many times it boots.
func TestBackfillOwners(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedPerson(t, db, "acme", "ann", "uuid-ann")
	seedPerson(t, db, "beta", "bo", "uuid-bo")
	seedPerson(t, db, "delta", "carol", "uuid-new-carol")
	seedPerson(t, db, "else", "eve", "uuid-eve")
	org(t, db, "acme", "uuid-ann")     // founder on record → owner
	org(t, db, "beta", "")             // nobody recorded → listed
	org(t, db, "gone", "uuid-deleted") // founder gone → listed
	org(t, db, "owned", "uuid-bo")     // already owned → untouched
	org(t, db, "delta", "delta/carol") // a name, now someone else's → listed
	org(t, db, "left", "uuid-eve")     // founder no longer belongs → listed
	org(t, db, policy.AdminOrg, "")    // reserved → never considered
	if _, err := SetRole(ctx, db, "beta/bo", "owned", RoleOwner, ""); err != nil {
		t.Fatal(err)
	}

	for boot := 0; boot < 2; boot++ {
		added, ownerless, err := BackfillOwners(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if boot == 0 && (len(added) != 1 || added[0] != "acme") {
			t.Fatalf("boot 0 added %v, want [acme]", added)
		}
		if boot == 1 && len(added) != 0 {
			t.Fatalf("boot 1 added %v, want none", added)
		}
		sort.Strings(ownerless)
		if strings.Join(ownerless, " ") != "beta delta gone left" {
			t.Fatalf("boot %d ownerless %v, want [beta delta gone left]", boot, ownerless)
		}
	}
	if o, _ := Owners(ctx, db, "acme"); len(o) != 1 || o[0] != "acme/ann" {
		t.Fatalf("acme owners = %v", o)
	}
	if n := trail(t, db, schema.ActionOrgOwnerless); n != 4 {
		t.Fatalf("ownerless rows = %d, want 4", n)
	}
	if n := trail(t, db, schema.ActionOrgRole); n != 1 {
		t.Fatalf("role rows = %d, want 1", n)
	}
}

// An admin-org membership held by another org's account is listed, once.
func TestAdminOrgStrangers(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	if err := testdb.Member(ctx, db, "hanzo/z", policy.AdminOrg, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureMembership(ctx, db, "admin/z", policy.AdminOrg, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	for boot := 0; boot < 2; boot++ {
		got, err := AdminOrgStrangers(ctx, db)
		if err != nil || len(got) != 1 || got[0] != "hanzo/z" {
			t.Fatalf("boot %d strangers = %v (err=%v), want [hanzo/z]", boot, got, err)
		}
	}
	if n := trail(t, db, schema.ActionAdminOrgStranger); n != 1 {
		t.Fatalf("stranger rows = %d, want 1", n)
	}
}

// The owner role is a live person's: no machine, no unknown account.
func TestNoMachineOwns(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedPerson(t, db, "acme", "ann", "uuid-ann")
	bot := orm.New[schema.User](db)
	bot.Owner, bot.Name, bot.Type = "acme", "bot", schema.ServiceAccount
	bot.SetId("uuid-bot")
	if err := bot.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	for _, u := range []string{"acme/bot", "acme/nobody"} {
		if _, err := SetRole(ctx, db, u, "acme", RoleOwner, ""); !errors.Is(err, ErrMachineOwner) {
			t.Errorf("SetRole owner for %s: %v, want ErrMachineOwner", u, err)
		}
		if _, err := EnsureMembership(ctx, db, u, "acme", "Owner"); !errors.Is(err, ErrMachineOwner) {
			t.Errorf("EnsureMembership owner for %s: %v, want ErrMachineOwner", u, err)
		}
	}
	if _, err := SetRole(ctx, db, "acme/ann", "acme", RoleOwner, ""); err != nil {
		t.Fatal(err)
	}
}

// A change decided on a role the row no longer holds is refused.
func TestAStaleDecisionMovesNothing(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedPerson(t, db, "acme", "ann", "uuid-ann")
	seedPerson(t, db, "acme", "cy", "uuid-cy")
	for _, u := range []string{"acme/ann", "acme/cy"} {
		if _, err := SetRole(ctx, db, u, "acme", RoleOwner, ""); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := SetRole(ctx, db, "acme/cy", "acme", RoleMember, RoleAdmin); !errors.Is(err, ErrMoved) {
		t.Fatalf("demoting on a stale read: %v, want ErrMoved", err)
	}
	if _, err := DeleteMembership(ctx, db, "acme/cy", "acme", RoleMember); !errors.Is(err, ErrMoved) {
		t.Fatalf("removing on a stale read: %v, want ErrMoved", err)
	}
	if o, _ := Owners(ctx, db, "acme"); len(o) != 2 {
		t.Fatalf("owners = %v, want both", o)
	}
}

// An account that moves to another home org takes its memberships with it, and
// leaves nothing under the old name for whoever takes it next.
func TestRekeyMovesEveryMembership(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedPerson(t, db, "side", "bob", "uuid-bob")
	if err := testdb.Member(ctx, db, "tenant/bob", "side", RoleOwner); err != nil {
		t.Fatal(err)
	}
	for _, org := range []string{"tenant", "team"} {
		if err := testdb.Member(ctx, db, "tenant/bob", org, RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	if err := testdb.Member(ctx, db, "tenant/bob", policy.AdminOrg, RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if err := Rekey(ctx, db, "tenant/bob", "side/bob"); err != nil {
		t.Fatal(err)
	}
	if left, _ := MembershipsByUser(ctx, db, "tenant/bob"); len(left) != 0 {
		t.Fatalf("rows left under the old id: %v", left)
	}
	got := map[string]string{}
	rows, _ := MembershipsByUser(ctx, db, "side/bob")
	for _, m := range rows {
		got[m.Org] = m.Role
	}
	if len(got) != 2 || got["side"] != RoleOwner || got["team"] != RoleMember {
		t.Fatalf("rows under the new id = %v, want side owner and team member", got)
	}
}

// A deleted org takes its memberships and keys with it, and a name whose
// accounts or memberships remain is not taken again.
func TestADeletedOrgLeavesNothingThatSpeaks(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedPerson(t, db, "hanzo", "eve", "uuid-eve")
	if _, err := SetRole(ctx, db, "hanzo/eve", "victimco", RoleOwner, ""); err != nil {
		t.Fatal(err)
	}
	if err := Leftovers(ctx, db, "victimco"); !errors.Is(err, ErrLeftovers) {
		t.Fatalf("a name with a membership: %v, want ErrLeftovers", err)
	}
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.AccessKey = "victimco", "k", "pk-live-victim"
	k.SetId("victimco/k")
	if err := k.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if err := ForgetOrg(ctx, db, "victimco"); err != nil {
		t.Fatal(err)
	}
	if o, _ := Owners(ctx, db, "victimco"); len(o) != 0 {
		t.Fatalf("owners after delete = %v", o)
	}
	if _, err := orm.Get[schema.Key](db, "victimco/k"); !errors.Is(err, orm.ErrNotFound) {
		t.Fatalf("the org's key outlived it: %v", err)
	}
	if err := Leftovers(ctx, db, "victimco"); err != nil {
		t.Fatalf("a clean name: %v", err)
	}
	seedPerson(t, db, "victimco", "mallory", "uuid-mallory")
	if err := Leftovers(ctx, db, "victimco"); !errors.Is(err, ErrLeftovers) {
		t.Fatalf("a name with an account: %v, want ErrLeftovers", err)
	}
}
