// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keys

import (
	"context"
	"errors"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/internal/testdb"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// operatorDB seeds hanzo/z made a SuperAdmin by membership, and hanzo/alice.
func operatorDB(t *testing.T) orm.DB {
	t.Helper()
	db := memDB(t)
	for _, name := range []string{"z", "alice"} {
		u := orm.New[schema.User](db)
		u.Owner, u.Name = "hanzo", name
		u.SetId("hanzo/" + name)
		if err := u.CreateCtx(context.Background()); err != nil {
			t.Fatalf("seed %s: %v", name, err)
		}
	}
	if _, err := store.EnsureMembership(context.Background(), db, "hanzo/z", policy.AdminOrg, store.RoleMember); err != nil {
		t.Fatalf("grant: %v", err)
	}
	return db
}

// A SuperAdmin is minted no secret key by any of the three mints, and a
// publishable key, which names only the org, is minted as for anyone.
func TestTheMintsIssueNoSuperAdminASecretKey(t *testing.T) {
	ctx := context.Background()
	db := operatorDB(t)

	for _, user := range []string{"z", "Z"} {
		if _, err := MintUserKey(ctx, db, "hanzo", user, ""); !errors.Is(err, ErrSuperAdminKey) {
			t.Errorf("MintUserKey(hanzo, %s) = %v, want ErrSuperAdminKey", user, err)
		}
	}
	if _, _, err := MintAccountKey(ctx, db, policy.AdminOrg, "provisioner"); !errors.Is(err, ErrSuperAdminKey) {
		t.Errorf("MintAccountKey(admin, provisioner) = %v, want ErrSuperAdminKey", err)
	}
	rows, err := orm.TypedQuery[schema.Key](db).GetAll(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("refused mints left %d rows (%v)", len(rows), err)
	}

	if _, err := MintUserKey(ctx, db, "hanzo", "z", schema.KeyScopePublish); err != nil {
		t.Errorf("a publishable key for the operator's org: %v", err)
	}
	if _, err := MintUserKey(ctx, db, "hanzo", "alice", ""); err != nil {
		t.Errorf("an ordinary member's key: %v", err)
	}
	if _, _, err := MintAccountKey(ctx, db, "hanzo", "hanzo-bot"); err != nil {
		t.Errorf("a tenant's service account key: %v", err)
	}
}

// The refusal is asked of a store that can say who is a SuperAdmin. One that
// cannot read the membership set refuses the write and mints nothing.
func TestAnUnreadableMembershipSetWritesNoKey(t *testing.T) {
	ctx := context.Background()
	db := operatorDB(t)
	blind := testdb.Unreadable(db, "memberships")
	boss := principal.Bind(ctx, &principal.Principal{Org: "hanzo", User: "boss", Admin: true})

	if _, err := create(blind)(boss, &schema.Key{Owner: "hanzo", Name: "k", User: "alice"}); status(t, err) != 500 {
		t.Fatalf("create over an unreadable roster answered %v, want 500", err)
	}
	if _, err := MintUserKey(ctx, blind, "hanzo", "alice", ""); !errors.Is(err, testdb.ErrUnreadable) {
		t.Fatalf("MintUserKey over an unreadable roster = %v, want the read error", err)
	}
	if _, _, err := MintAccountKey(ctx, blind, "hanzo", "hanzo-bot"); !errors.Is(err, testdb.ErrUnreadable) {
		t.Fatalf("MintAccountKey over an unreadable roster = %v, want the read error", err)
	}
	rows, err := orm.TypedQuery[schema.Key](db).GetAll(ctx)
	if err != nil || len(rows) != 0 {
		t.Fatalf("an unreadable roster let %d rows through (%v)", len(rows), err)
	}
}
