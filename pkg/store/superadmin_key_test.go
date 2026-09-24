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

// operatorKeys seeds hanzo/z, a SuperAdmin by membership who is also a member of
// orgb; hanzo/alice, an ordinary member of both; and admin/root.
func operatorKeys(t *testing.T) orm.DB {
	t.Helper()
	ctx := context.Background()
	db := memDB(t)
	seedKeyUser(t, db, "hanzo", "z", "z@hanzo.test", "")
	seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.test", "")
	seedKeyUser(t, db, policy.AdminOrg, "root", "root@hanzo.test", "")
	for _, m := range [][2]string{{"hanzo/z", policy.AdminOrg}, {"hanzo/z", "orgb"}, {"hanzo/alice", "orgb"}} {
		if _, err := EnsureMembership(ctx, db, m[0], m[1], RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// Every spelling a key can name its holder in is asked as the row it resolves to:
// a bare name, a qualified one, either in any case, and a member's key minted in
// another org.
func TestSuperAdminKey_EverySpellingOfTheHolder(t *testing.T) {
	ctx := context.Background()
	db := operatorKeys(t)
	for _, c := range []struct {
		owner, user string
		want        bool
	}{
		{"hanzo", "z", true},
		{"hanzo", "Z", true},
		{"hanzo", "hanzo/z", true},
		{"hanzo", "hanzo/Z", true},
		{"orgb", "hanzo/z", true},
		{"orgb", "hanzo/Z", true},
		{policy.AdminOrg, "root", true},
		{policy.AdminOrg, "nobody-yet", true},
		{"hanzo", "alice", false},
		{"orgb", "hanzo/alice", false},
		{"hanzo", "", false},
	} {
		got, err := SuperAdminKey(ctx, db, &schema.Key{Owner: c.owner, User: c.user})
		if err != nil || got != c.want {
			t.Errorf("SuperAdminKey(%s, %q) = %v, %v; want %v", c.owner, c.user, got, err, c.want)
		}
	}
}

// The write gates refuse on a true, so a membership set SuperAdminKey cannot read
// is reported, never answered.
func TestSuperAdminKey_AnUnreadableRosterIsNotAnAnswer(t *testing.T) {
	db := operatorKeys(t)
	blind, err := SuperAdminKey(context.Background(), testdb.Unreadable(db, "memberships"), &schema.Key{Owner: "hanzo", User: "z"})
	if !errors.Is(err, testdb.ErrUnreadable) || blind {
		t.Fatalf("SuperAdminKey over an unreadable roster = %v, %v; want the read error", blind, err)
	}
}
