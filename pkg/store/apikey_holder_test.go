// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
	"testing"

	"github.com/hanzoai/orm"
)

// A key works exactly as long as its holder may sign in. Suspending an account —
// by hand, or by SCIM active=false — or deleting it ends every key it holds, its
// org's default key above all: that one is an owner's, never expires, and outlived
// the founder an org offboarded.
func TestAKeyDiesWithItsHolder(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		disable func(*testing.T, orm.DB)
	}{
		{"suspended", func(t *testing.T, db orm.DB) { holderFlag(t, db, func(u *userFlags) { u.forbidden = true }) }},
		{"deleted", func(t *testing.T, db orm.DB) { holderFlag(t, db, func(u *userFlags) { u.deleted = true }) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := memDB(t)
			seedKeyUser(t, db, "acme", "alice", "alice@acme.test", "")
			seedKey(t, db, "acme", "default", "acme/alice", "pk-live-ALICE", "sk-live-ALICE")
			// A member's key in a second org dies the same way.
			seedKey(t, db, "team", "alice-k", "acme/alice", "pk-live-TEAM", "sk-live-TEAM")
			if _, err := EnsureMembership(ctx, db, "acme/alice", "team", RoleMember); err != nil {
				t.Fatal(err)
			}
			for _, sk := range []string{"sk-live-ALICE", "sk-live-TEAM"} {
				if _, err := HolderByAccessKey(ctx, db, sk); err != nil {
					t.Fatalf("%s before: %v, want it to resolve", sk, err)
				}
			}
			tc.disable(t, db)
			for _, sk := range []string{"sk-live-ALICE", "sk-live-TEAM"} {
				h, err := HolderByAccessKey(ctx, db, sk)
				if h.User != nil || !errors.Is(err, orm.ErrNotFound) || Reason(err) != KeyHolderDisabled {
					t.Fatalf("%s after the holder was %s: %+v %v, want refused as %s", sk, tc.name, h.User, err, KeyHolderDisabled)
				}
			}
		})
	}
}

type userFlags struct{ forbidden, deleted bool }

// holderFlag sets acme/alice's account flags.
func holderFlag(t *testing.T, db orm.DB, set func(*userFlags)) {
	t.Helper()
	u, err := GetUserByName(context.Background(), db, "acme", "alice")
	if err != nil || u == nil {
		t.Fatalf("read acme/alice: %v", err)
	}
	var f userFlags
	set(&f)
	u.IsForbidden, u.IsDeleted = f.forbidden, f.deleted
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A key acting in an org the platform runs works for the people who run it and its
// machines, and for no plain member: a customer who landed in a brand org holds no
// credential that acts in it.
func TestAKeyInABrandOrgActsOnlyForThoseWhoRunIt(t *testing.T) {
	ctx := context.Background()
	db := memDB(t)
	seedKeyUser(t, db, "hanzo", "eve", "eve@x.test", "")
	seedKey(t, db, "hanzo", "eve-key", "hanzo/eve", "pk-live-EVE", "sk-live-EVE")
	staff := seedKeyUser(t, db, "hanzo", "lead", "lead@hanzo.test", "")
	staff.IsAdmin = true
	if err := staff.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedKey(t, db, "hanzo", "lead-key", "hanzo/lead", "pk-live-LEAD", "sk-live-LEAD")
	bot := seedKeyUser(t, db, "hanzo", "bot", "", "")
	bot.Type = "service-account"
	if err := bot.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedKey(t, db, "hanzo", "bot-key", "hanzo/bot", "pk-live-BOT", "sk-live-BOT")

	if _, err := HolderByAccessKey(ctx, db, "sk-live-EVE"); Reason(err) != KeyNotTenant {
		t.Fatalf("a plain member's key in hanzo: %v, want %s", err, KeyNotTenant)
	}
	for _, sk := range []string{"sk-live-LEAD", "sk-live-BOT"} {
		if h, err := HolderByAccessKey(ctx, db, sk); err != nil || h.Org != "hanzo" {
			t.Fatalf("%s: %+v %v, want it to act in hanzo", sk, h, err)
		}
	}
}

// A brand's directory is no one's tenant: a key filed there acts for nobody,
// whatever its holder's standing, so a directory account's key can never read as
// one tenant shared by every customer in it.
func TestAKeyInADirectoryActsForNobody(t *testing.T) {
	ctx := context.Background()
	db := memDB(t)
	u := seedKeyUser(t, db, "hanzo-id", "ann", "ann@x.test", "")
	u.IsAdmin = true
	if err := u.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedKey(t, db, "hanzo-id", "ann-key", "hanzo-id/ann", "pk-live-ANN", "sk-live-ANN")
	h, err := HolderByAccessKey(ctx, db, "sk-live-ANN")
	if h.User != nil || Reason(err) != KeyNotTenant {
		t.Fatalf("a directory key resolved to %+v (%v), want nobody (%s)", h.User, err, KeyNotTenant)
	}
}

// A machine acts in the org that made it. A service account of another org that
// holds a plain membership of a brand org is a plain member there, as a person is.
func TestAnotherOrgsMachineIsAPlainMemberOfABrandOrg(t *testing.T) {
	ctx := context.Background()
	db := memDB(t)
	bot := seedKeyUser(t, db, "evil", "evil-bot", "", "")
	bot.Type = "service-account"
	if err := bot.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureMembership(ctx, db, "evil/evil-bot", "lux", RoleMember); err != nil {
		t.Fatal(err)
	}
	seedKey(t, db, "lux", "evil-bot-key", "evil/evil-bot", "pk-live-EVILBOT", "sk-live-EVILBOT")
	if h, err := HolderByAccessKey(ctx, db, "sk-live-EVILBOT"); h.User != nil || Reason(err) != KeyNotTenant {
		t.Fatalf("another org's machine acts in lux: %+v (%v)", h.User, err)
	}
	if !Acts("evil", bot, HomeRole(bot)) || Acts("lux", bot, RoleMember) {
		t.Fatal("a machine acts in its own org and in no brand org it merely belongs to")
	}
}

// A key selects an org per request exactly where a member's key filed there would
// act: its holder's home or an org-wide membership. Anything else is refused as
// KeyOrgNotOpen, and the key's own name and limit travel with it unchanged
// (hanzo-inc/cloud#429).
func TestHolderInActsOnlyWhereTheHolderDoes(t *testing.T) {
	ctx := context.Background()
	db := memDB(t)
	seedKeyUser(t, db, "acme", "alice", "alice@acme.test", "")
	seedKey(t, db, "acme", "default", "acme/alice", "pk-live-ALICE", "sk-live-ALICE")
	seedKeyUser(t, db, "other", "olga", "olga@other.test", "")
	if _, err := EnsureMembership(ctx, db, "acme/alice", "team", RoleMember); err != nil {
		t.Fatal(err)
	}
	h, err := HolderByAccessKey(ctx, db, "sk-live-ALICE")
	if err != nil || h.Org != "acme" {
		t.Fatalf("home key: %+v %v", h, err)
	}

	in, err := HolderIn(ctx, db, h, "team")
	if err != nil || in.Org != "team" || in.Role != RoleMember || in.Key != "default" || in.KeyOrg != "acme" || in.Scope != h.Scope {
		t.Fatalf("selected a membership: %+v %v, want Org team, Role member, Key default filed in acme", in, err)
	}
	if same, err := HolderIn(ctx, db, h, "acme"); err != nil || same.Org != "acme" || same.KeyOrg != "" {
		t.Fatalf("selecting the key's own org: %+v %v, want it unchanged", same, err)
	}
	if same, err := HolderIn(ctx, db, h, ""); err != nil || same.Org != "acme" {
		t.Fatalf("selecting nothing: %+v %v, want it unchanged", same, err)
	}
	for _, org := range []string{"other", "nosuch", "admin"} {
		if got, err := HolderIn(ctx, db, h, org); got.User != nil || Reason(err) != KeyOrgNotOpen {
			t.Fatalf("selected %q: %+v %v, want refused as %s", org, got, err, KeyOrgNotOpen)
		}
	}

	// A member's key may select its holder's home, which it acts in by right.
	seedKey(t, db, "team", "alice-k", "acme/alice", "pk-live-TEAM", "sk-live-TEAM")
	m, err := HolderByAccessKey(ctx, db, "sk-live-TEAM")
	if err != nil || m.Org != "team" {
		t.Fatalf("member key: %+v %v", m, err)
	}
	if home, err := HolderIn(ctx, db, m, "acme"); err != nil || home.Org != "acme" || home.KeyOrg != "team" || home.Key != "alice-k" {
		t.Fatalf("member key selecting home: %+v %v", home, err)
	}

	// Removing the membership ends the selection on the next call.
	if _, err := DeleteMembership(ctx, db, "acme/alice", "team"); err != nil {
		t.Fatal(err)
	}
	if got, err := HolderIn(ctx, db, h, "team"); got.User != nil || Reason(err) != KeyOrgNotOpen {
		t.Fatalf("after removal: %+v %v, want refused as %s", got, err, KeyOrgNotOpen)
	}
}

// A plain member of an org the platform runs selects none of it, as their key
// filed there would act in none of it.
func TestHolderInRefusesABrandOrgToAPlainMember(t *testing.T) {
	ctx := context.Background()
	db := memDB(t)
	seedKeyUser(t, db, "acme", "alice", "alice@acme.test", "")
	seedKey(t, db, "acme", "default", "acme/alice", "pk-live-ALICE", "sk-live-ALICE")
	if _, err := EnsureMembership(ctx, db, "acme/alice", "hanzo", RoleMember); err != nil {
		t.Fatal(err)
	}
	h, err := HolderByAccessKey(ctx, db, "sk-live-ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := HolderIn(ctx, db, h, "hanzo"); got.User != nil || Reason(err) != KeyOrgNotOpen {
		t.Fatalf("plain member selecting hanzo: %+v %v, want refused as %s", got, err, KeyOrgNotOpen)
	}
}
