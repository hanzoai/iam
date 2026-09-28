// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keys

import (
	"context"
	"errors"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// operatorDB seeds admin/z, a SuperAdmin; hanzo/z, a hanzo account holding an
// admin-org membership; and hanzo/alice.
func operatorDB(t *testing.T) orm.DB {
	t.Helper()
	db := memDB(t)
	for _, id := range [][2]string{{policy.AdminOrg, "z"}, {"hanzo", "z"}, {"hanzo", "alice"}} {
		u := orm.New[schema.User](db)
		u.Owner, u.Name = id[0], id[1]
		u.SetId(id[0] + "/" + id[1])
		if err := u.CreateCtx(context.Background()); err != nil {
			t.Fatalf("seed %s/%s: %v", id[0], id[1], err)
		}
	}
	if _, err := store.EnsureMembership(context.Background(), db, "hanzo/z", policy.AdminOrg, store.RoleMember); err != nil {
		t.Fatalf("grant: %v", err)
	}
	return db
}

// No account in the admin org is minted a secret key by any of the three mints —
// its SuperAdmins and its machines alike — and a publishable key, which names
// only the org, is minted as for anyone. An admin-org membership held from a
// brand org is no bar: hanzo/z is minted a key like hanzo/alice.
func TestTheMintsIssueNoSuperAdminASecretKey(t *testing.T) {
	ctx := context.Background()
	db := operatorDB(t)

	for _, user := range []string{"z", "Z"} {
		if _, err := MintUserKey(ctx, db, policy.AdminOrg, user, ""); !errors.Is(err, ErrSuperAdminKey) {
			t.Errorf("MintUserKey(admin, %s) = %v, want ErrSuperAdminKey", user, err)
		}
	}
	if _, _, err := MintAccountKey(ctx, db, policy.AdminOrg, "provisioner"); !errors.Is(err, ErrSuperAdminKey) {
		t.Errorf("MintAccountKey(admin, provisioner) = %v, want ErrSuperAdminKey", err)
	}
	rows, err := orm.TypedQuery[schema.Key](db).GetAll(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("refused mints left %d rows (%v)", len(rows), err)
	}

	if _, err := MintUserKey(ctx, db, policy.AdminOrg, "z", schema.KeyScopePublish); err != nil {
		t.Errorf("a publishable key for the admin org: %v", err)
	}
	for _, user := range []string{"z", "alice"} {
		if _, err := MintUserKey(ctx, db, "hanzo", user, ""); err != nil {
			t.Errorf("hanzo/%s's key: %v", user, err)
		}
	}
	if _, _, err := MintAccountKey(ctx, db, "hanzo", "hanzo-bot"); err != nil {
		t.Errorf("a tenant's service account key: %v", err)
	}
}
