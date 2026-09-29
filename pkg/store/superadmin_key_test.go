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

// operatorKeys seeds admin/root, a SuperAdmin; admin/svc, a service account in
// the admin org; hanzo/z, a brand org's person holding an admin-org membership and
// an orgb membership; and hanzo/alice, an ordinary member of orgb.
func operatorKeys(t *testing.T) orm.DB {
	t.Helper()
	ctx := context.Background()
	db := memDB(t)
	seedKeyUser(t, db, "hanzo", "z", "z@hanzo.test", "")
	seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.test", "")
	seedKeyUser(t, db, policy.AdminOrg, "root", "root@hanzo.test", "")
	svc := seedKeyUser(t, db, policy.AdminOrg, "svc", "", "")
	svc.Type = schema.ServiceAccount
	if err := svc.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	for _, m := range [][2]string{{"hanzo/z", policy.AdminOrg}, {"hanzo/z", "orgb"}, {"hanzo/alice", "orgb"}} {
		if err := testdb.Member(ctx, db, m[0], m[1], RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

// A key is refused for every account in the admin org — its SuperAdmins, its
// machines, and a name nobody holds yet — in every spelling of the holder. A
// brand org's person is not one of them, whatever memberships they hold.
func TestSuperAdminKey_EverySpellingOfTheHolder(t *testing.T) {
	for _, c := range []struct {
		owner, user string
		want        bool
	}{
		{policy.AdminOrg, "root", true},
		{policy.AdminOrg, "Root", true},
		{policy.AdminOrg, "admin/root", true},
		{policy.AdminOrg, "svc", true},
		{policy.AdminOrg, "nobody-yet", true},
		{"hanzo", "admin/root", true},
		{"hanzo", "z", false},
		{"hanzo", "hanzo/Z", false},
		{"orgb", "hanzo/z", false},
		{"hanzo", "alice", false},
		{"orgb", "hanzo/alice", false},
		{"hanzo", "", false},
		{"Admin", "root", false},
	} {
		if got := SuperAdminKey(&schema.Key{Owner: c.owner, User: c.user}); got != c.want {
			t.Errorf("SuperAdminKey(%s, %q) = %v; want %v", c.owner, c.user, got, c.want)
		}
	}
}

// No secret key resolves to an account in the admin org, however it came to
// exist; the reason names it. A brand org's person holding an admin-org
// membership is an ordinary person, and their keys resolve like anyone's.
func TestHolderByAccessKey_NoKeySpeaksForTheAdminOrg(t *testing.T) {
	ctx := context.Background()
	db := operatorKeys(t)
	seedKey(t, db, policy.AdminOrg, "root-home", "root", "pk-live-ROOT", "sk-live-ROOT")
	seedKey(t, db, policy.AdminOrg, "root-folded", "admin/Root", "pk-live-RFOLD", "sk-live-RFOLD")
	seedKey(t, db, policy.AdminOrg, "svc-key", "svc", "pk-live-SVC", "sk-live-SVC")
	seedKey(t, db, "hanzo", "z-home", "z", "pk-live-ZHOME", "sk-live-ZHOME")
	seedKey(t, db, "orgb", "z-member", "hanzo/z", "pk-live-ZMEMBER", "sk-live-ZMEMBER")
	seedKey(t, db, "orgb", "alice-member", "hanzo/alice", "pk-live-AMEMBER", "sk-live-AMEMBER")

	for _, sk := range []string{"sk-live-ROOT", "sk-live-RFOLD", "sk-live-SVC"} {
		h, err := HolderByAccessKey(ctx, db, sk)
		if !errors.Is(err, orm.ErrNotFound) || h.User != nil || Reason(err) != KeySuperAdmin {
			t.Errorf("%s resolved to %+v (err=%v, reason=%q), want nobody and %q", sk, h.User, err, Reason(err), KeySuperAdmin)
		}
	}
	for sk, want := range map[string]string{"sk-live-ZHOME": "z", "sk-live-ZMEMBER": "z", "sk-live-AMEMBER": "alice"} {
		if h, err := HolderByAccessKey(ctx, db, sk); err != nil || h.User == nil || h.User.Name != want {
			t.Errorf("%s = %+v, %v; want hanzo/%s", sk, h.User, err, want)
		}
	}
}

// A member key is admitted by its membership row, so a roster the resolver cannot
// read is a store fault, never a holder and never a named refusal a caller would
// read as final.
func TestHolderByAccessKey_AnUnreadableRosterIsNotAnAnswer(t *testing.T) {
	db := operatorKeys(t)
	seedKey(t, db, "orgb", "alice-member", "hanzo/alice", "pk-live-AMEMBER", "sk-live-AMEMBER")

	h, err := HolderByAccessKey(context.Background(), testdb.Unreadable(db, "memberships"), "sk-live-AMEMBER")
	if !errors.Is(err, testdb.ErrUnreadable) || h.User != nil || Reason(err) != "" {
		t.Fatalf("an unreadable roster answered %+v (err=%v, reason=%q), want the read error", h.User, err, Reason(err))
	}
}
