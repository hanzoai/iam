// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// An org's roster is what an access review reads. It is built from membership
// ROWS, while access is granted from the user row's home org — so a member who
// never had a row is INVISIBLE to the review while holding full access to the
// org. That is the silent half of the same asymmetry `remove` refuses: one shows
// a member who cannot be removed, this hides a member who is there.
//
// BackfillMemberships is what makes the roster total. It was written for exactly
// this and had no caller, so the completeness its own doc claims was never true.

func seedUser(t *testing.T, db orm.DB, owner, name string, admin bool) *schema.User {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.IsAdmin = owner, name, admin
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
	return u
}

func rosterOf(t *testing.T, db orm.DB, org string) []string {
	t.Helper()
	rows, err := MembershipsByOrg(context.Background(), db, org)
	if err != nil {
		t.Fatalf("roster %s: %v", org, err)
	}
	names := make([]string, 0, len(rows))
	for _, r := range rows {
		names = append(names, r.User)
	}
	return names
}

// A user whose account lives in the org HOLDS access to it (MemberOrgRefs says so)
// but does not appear in its roster until a row exists. Backfill closes the gap.
func TestRoster_BackfillMakesEveryHolderVisible(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	dave := seedUser(t, db, "hanzo", "dave", false) // no row: the invisible member
	boss := seedUser(t, db, "hanzo", "boss", true)  // no row either, and an admin
	_ = seedUser(t, db, "acme", "eve", false)       // another tenant, must not leak in

	// Access is real for dave and boss...
	for _, u := range []*schema.User{dave, boss} {
		got := MemberOrgRefs(ctx, db, u)
		if len(got) == 0 || got[0].Org != "hanzo" {
			t.Fatalf("%s/%s holds no hanzo tenancy: %+v", u.Owner, u.Name, got)
		}
	}
	// ...yet the roster an access review reads is EMPTY.
	if before := rosterOf(t, db, "hanzo"); len(before) != 0 {
		t.Fatalf("precondition: roster = %v, want empty (no rows written yet)", before)
	}

	created, err := BackfillMemberships(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if created != 3 {
		t.Fatalf("backfill created %d rows, want 3 (one home row per user)", created)
	}

	after := rosterOf(t, db, "hanzo")
	if len(after) != 2 {
		t.Fatalf("roster = %v, want both hanzo holders visible", after)
	}
	for _, want := range []string{"hanzo/dave", "hanzo/boss"} {
		found := false
		for _, got := range after {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("INVISIBLE MEMBER: %q holds hanzo access but is absent from the roster %v", want, after)
		}
	}
	// Tenant isolation: acme's user never appears in hanzo's roster.
	for _, got := range after {
		if got == "acme/eve" {
			t.Fatalf("cross-tenant leak: acme/eve in hanzo roster %v", after)
		}
	}
}

// Backfill must not disturb what any token says. The home ref is emitted from the
// user row and deduped, so writing the row it duplicates changes no claim, no
// order, and no role — which is why this is safe to run on a live estate.
func TestRoster_BackfillChangesNoClaim(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	boss := seedUser(t, db, "hanzo", "boss", true) // admin: home role must stay admin
	plain := seedUser(t, db, "hanzo", "dave", false)
	if _, err := EnsureMembership(ctx, db, "hanzo/dave", "team-x", RoleAdmin); err != nil {
		t.Fatal(err)
	}

	before := map[string][]schema.OrgRef{
		"boss": MemberOrgRefs(ctx, db, boss),
		"dave": MemberOrgRefs(ctx, db, plain),
	}
	if _, err := BackfillMemberships(ctx, db); err != nil {
		t.Fatal(err)
	}
	for who, was := range before {
		u := boss
		if who == "dave" {
			u = plain
		}
		now := MemberOrgRefs(ctx, db, u)
		if len(now) != len(was) {
			t.Fatalf("%s: claim length moved %d -> %d (%+v -> %+v)", who, len(was), len(now), was, now)
		}
		for i := range was {
			if now[i] != was[i] {
				t.Fatalf("%s: claim moved at %d: %+v -> %+v (backfill must be invisible to a token)",
					who, i, was[i], now[i])
			}
		}
	}
	// The billing account is derived from those refs, so it must be unmoved too —
	// an admin keeps the org pool, a plain member keeps their wallet.
	if got := BillingAccount(boss, MemberOrgRefs(ctx, db, boss)); got == "" {
		t.Fatal("admin lost the org ledger after backfill")
	}
	if got := BillingAccount(plain, MemberOrgRefs(ctx, db, plain)); got != "" {
		t.Fatalf("plain member gained a ledger claim %q after backfill", got)
	}
}

// A deleted account must vanish from EVERY roster, not just its home org's.
// Backfill makes the roster total, which is exactly what makes a leftover row a
// ghost: a person who no longer exists, listed as able to act.
func TestRoster_ForgetUserClearsEveryRoster(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedUser(t, db, "hanzo", "dave", false)
	seedUser(t, db, "hanzo", "boss", true)
	for _, org := range []string{"hanzo", "team-x", "team-y"} {
		if _, err := EnsureMembership(ctx, db, "hanzo/dave", org, RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := EnsureMembership(ctx, db, "hanzo/boss", "team-x", RoleAdmin); err != nil {
		t.Fatal(err)
	}

	removed, err := ForgetUser(ctx, db, "hanzo/dave")
	if err != nil || removed != 3 {
		t.Fatalf("ForgetUser removed=%d err=%v, want 3", removed, err)
	}
	for _, org := range []string{"hanzo", "team-x", "team-y"} {
		for _, who := range rosterOf(t, db, org) {
			if who == "hanzo/dave" {
				t.Errorf("GHOST: deleted account still on the %s roster", org)
			}
		}
	}
	// The bystander keeps their membership — forgetting one account is not a purge.
	if got := rosterOf(t, db, "team-x"); len(got) != 1 || got[0] != "hanzo/boss" {
		t.Fatalf("team-x roster = %v, want only hanzo/boss left", got)
	}
	// Idempotent: forgetting an account that holds nothing removes nothing.
	if removed, err := ForgetUser(ctx, db, "hanzo/dave"); err != nil || removed != 0 {
		t.Fatalf("second ForgetUser removed=%d err=%v, want 0", removed, err)
	}
	if removed, err := ForgetUser(ctx, db, ""); err != nil || removed != 0 {
		t.Fatalf("ForgetUser(\"\") removed=%d err=%v, want 0", removed, err)
	}
}

// Idempotent: a second run writes nothing, so booting twice is not a migration
// twice, and a re-ensured row never downgrades an owner to a member.
func TestRoster_BackfillIsIdempotent(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedUser(t, db, "hanzo", "dave", false)
	if _, err := EnsureMembership(ctx, db, "hanzo/dave", "hanzo", RoleOwner); err != nil {
		t.Fatal(err)
	}

	created, err := BackfillMemberships(ctx, db)
	if err != nil || created != 0 {
		t.Fatalf("backfill over an existing home row: created=%d err=%v, want 0", created, err)
	}
	m, _ := GetMembership(ctx, db, "hanzo/dave", "hanzo")
	if m == nil || m.Role != RoleOwner {
		t.Fatalf("backfill downgraded an owner: %+v", m)
	}
}
