// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
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

func person(t *testing.T, db orm.DB, owner, name, id string) {
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
	for _, user := range []string{"hanzo/z", "Admin/z", "z"} {
		if _, err := EnsureMembership(ctx, db, user, policy.AdminOrg, RoleMember); !errors.Is(err, ErrAdminOrgMember) {
			t.Errorf("%s into the admin org: %v, want ErrAdminOrgMember", user, err)
		}
	}
	if _, err := SetRole(ctx, db, "hanzo/z", policy.AdminOrg, RoleOwner); !errors.Is(err, ErrAdminOrgMember) {
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
	if _, err := SetRole(ctx, db, "acme/ann", "acme", RoleOwner); err != nil {
		t.Fatal(err)
	}
	if _, err := ForgetUser(ctx, db, "acme/ann"); !errors.Is(err, ErrLastOwner) {
		t.Fatalf("forgetting the last owner: %v, want ErrLastOwner", err)
	}
	if o, _ := Owners(ctx, db, "acme"); len(o) != 1 {
		t.Fatalf("owners after a refused forget = %v", o)
	}
	if _, err := SetRole(ctx, db, "hanzo/bob", "acme", RoleOwner); err != nil {
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
	person(t, db, "acme", "ann", "uuid-ann")
	person(t, db, "beta", "bo", "uuid-bo")
	org(t, db, "acme", "uuid-ann")     // founder on record → owner
	org(t, db, "beta", "")             // nobody recorded → listed
	org(t, db, "gone", "uuid-deleted") // founder gone → listed
	org(t, db, "owned", "uuid-bo")     // already owned → untouched
	org(t, db, policy.AdminOrg, "")    // reserved → never considered
	if _, err := SetRole(ctx, db, "beta/bo", "owned", RoleOwner); err != nil {
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
		if len(ownerless) != 2 || ownerless[0] != "beta" || ownerless[1] != "gone" {
			t.Fatalf("boot %d ownerless %v, want [beta gone]", boot, ownerless)
		}
	}
	if o, _ := Owners(ctx, db, "acme"); len(o) != 1 || o[0] != "acme/ann" {
		t.Fatalf("acme owners = %v", o)
	}
	if n := trail(t, db, schema.ActionOrgOwnerless); n != 2 {
		t.Fatalf("ownerless rows = %d, want 2", n)
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
