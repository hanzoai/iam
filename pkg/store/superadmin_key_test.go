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

// No secret key resolves to a SuperAdmin, home key or member key, however it came
// to exist; the reason names it. An ordinary member's keys resolve as before.
func TestHolderByAccessKey_NoKeySpeaksForASuperAdmin(t *testing.T) {
	ctx := context.Background()
	db := operatorKeys(t)
	seedKey(t, db, "hanzo", "z-home", "z", "pk-live-ZHOME", "sk-live-ZHOME")
	seedKey(t, db, "hanzo", "z-folded", "hanzo/Z", "pk-live-ZFOLD", "sk-live-ZFOLD")
	seedKey(t, db, "orgb", "z-member", "hanzo/z", "pk-live-ZMEMBER", "sk-live-ZMEMBER")
	seedKey(t, db, policy.AdminOrg, "root-home", "root", "pk-live-ROOT", "sk-live-ROOT")
	seedKey(t, db, "hanzo", "alice-home", "alice", "pk-live-AHOME", "sk-live-AHOME")
	seedKey(t, db, "orgb", "alice-member", "hanzo/alice", "pk-live-AMEMBER", "sk-live-AMEMBER")

	for _, sk := range []string{"sk-live-ZHOME", "sk-live-ZFOLD", "sk-live-ZMEMBER", "sk-live-ROOT"} {
		h, err := HolderByAccessKey(ctx, db, sk)
		if !errors.Is(err, orm.ErrNotFound) || h.User != nil || Reason(err) != KeySuperAdmin {
			t.Errorf("%s resolved to %+v (err=%v, reason=%q), want nobody and %q", sk, h.User, err, Reason(err), KeySuperAdmin)
		}
	}
	for _, sk := range []string{"sk-live-AHOME", "sk-live-AMEMBER"} {
		if h, err := HolderByAccessKey(ctx, db, sk); err != nil || h.User == nil || h.User.Name != "alice" {
			t.Errorf("%s = %+v, %v; want hanzo/alice", sk, h.User, err)
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

// Resolution refuses on a true, so a membership set it cannot read is a store
// fault, never a holder and never a named refusal a caller would read as final.
func TestHolderByAccessKey_AnUnreadableRosterIsNotAnAnswer(t *testing.T) {
	db := operatorKeys(t)
	seedKey(t, db, "hanzo", "z-home", "z", "pk-live-ZHOME", "sk-live-ZHOME")

	h, err := HolderByAccessKey(context.Background(), testdb.Unreadable(db, "memberships"), "sk-live-ZHOME")
	if !errors.Is(err, testdb.ErrUnreadable) || h.User != nil || Reason(err) != "" {
		t.Fatalf("an unreadable roster answered %+v (err=%v, reason=%q), want the read error", h.User, err, Reason(err))
	}
}
