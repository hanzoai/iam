// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// seedArgonUser writes a user whose row names no PasswordType, the shape the
// in-org lookup relies on the org's type for.
func seedArgonUser(t *testing.T, db orm.DB, org, name, email, pw, typ string) {
	t.Helper()
	h, err := cred.Hash(pw)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email, u.PasswordHash, u.PasswordType = org, name, email, h, typ
	u.SetId(org + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func seedOrgType(t *testing.T, db orm.DB, name, passwordType string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name, o.PasswordType = "admin", name, passwordType
	o.SetId("admin/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// The design states that no tenant sign-in form reaches a SuperAdmin. The roster
// search refuses a member HOMED in a reserved org, but a SuperAdmin is decided by
// membership of the admin org (store.IsSuperAdmin), and operators are normally
// anchored in a brand org. Such an operator, once a member of a tenant, is
// resolved by that tenant's shared-app form.
func TestLogin_MemberSuperAdminByMembershipIsNotReached(t *testing.T) {
	db, login := memberApp(t)
	seedUserInOrg(t, db, "hanzo", "op", "op@hanzo.example", "pw-op")
	for _, org := range []string{"admin", "client"} {
		if _, err := store.EnsureMembership(tctx(), db, "hanzo/op", org, store.RoleOwner); err != nil {
			t.Fatal(err)
		}
	}
	if super, err := store.IsSuperAdmin(tctx(), db, "hanzo", "op"); err != nil || !super {
		t.Fatalf("precondition: hanzo/op should be a SuperAdmin, got %v %v", super, err)
	}
	if u, err := store.MemberByIdentifier(tctx(), db, "client", "op"); err != nil || u != nil {
		t.Errorf("the client roster search resolved SuperAdmin %s/%s (err=%v); want nobody", u.Owner, u.Name, err)
	}
	if m := login("client", "op", "pw-op"); minted(m) {
		t.Errorf("a SuperAdmin signed in through a tenant's shared app: %v", m)
	}
}

// A member's row that carries no PasswordType is verified under the FORM org's
// type rather than the member's own home org's, so the same account verifies at
// home and fails through the shared app.
func TestLogin_MemberPasswordTypeFollowsTheHolderNotTheForm(t *testing.T) {
	db, login := memberApp(t)
	seedOrgType(t, db, "home2", cred.TypeArgon2id)
	seedOrgType(t, db, "client", cred.TypeBcrypt)
	seedArgonUser(t, db, "home2", "ana", "ana@home2.example", "pw-ana", "")
	if _, err := store.EnsureMembership(tctx(), db, "home2/ana", "client", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if m := login("client", "ana", "pw-ana"); !minted(m) {
		t.Fatalf("a member with the right password was refused through the shared app: %v", m)
	}
}

// "No member by that name" and "wrong password" take the same time through the real
// handler: the decoy is an argon2id verify at the current parameters, and a miss on
// a member row pays that row's own digest plus the lockout write. The medians must
// be within 25% of each other.
func TestLogin_MemberMissTakesAsLongAsAWrongPassword(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed func(db orm.DB)
	}{
		// argon2id is what every live row carries and what the decoy spends. A legacy
		// bcrypt row is verified at its own cost, which no decoy can know in advance.
		{"argon2id member row", func(db orm.DB) { seedArgonUser(t, db, "home3", "tim", "tim@home3.example", "pw-tim", cred.TypeArgon2id) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, login := memberApp(t)
			tc.seed(db)
			if _, err := store.EnsureMembership(tctx(), db, "home3/tim", "client", store.RoleMember); err != nil {
				t.Fatal(err)
			}
			const n = 4 // below the lockout threshold
			med := func(user string) time.Duration {
				var ds []time.Duration
				for i := 0; i < n; i++ {
					s := time.Now()
					login("client", user, "not-the-password")
					ds = append(ds, time.Since(s))
				}
				for i := range ds {
					for j := i + 1; j < len(ds); j++ {
						if ds[j] < ds[i] {
							ds[i], ds[j] = ds[j], ds[i]
						}
					}
				}
				return ds[len(ds)/2]
			}
			hit, miss := med("tim"), med("nobody-here")
			t.Logf("wrong password on a member: %v, no such member: %v", hit, miss)
			lo, hi := hit, miss
			if lo > hi {
				lo, hi = hi, lo
			}
			if float64(hi) > 1.25*float64(lo) {
				t.Fatalf("distinguishable: wrong password %v vs no member %v", hit, miss)
			}
		})
	}
}

// A sign-in at a shared app that misses the org's own rows looks the name up, not
// the roster: a miss against 2,000 members costs what a miss against none does.
func TestLogin_MemberMissDoesNotWalkTheRoster(t *testing.T) {
	db, _ := memberApp(t)
	const n = 2000
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("m%04d", i)
		u := orm.New[schema.User](db)
		u.Owner, u.Name = "far", name
		u.SetId("far/" + name)
		if err := u.CreateCtx(tctx()); err != nil {
			t.Fatal(err)
		}
		if _, err := store.EnsureMembership(tctx(), db, "far/"+name, "client", store.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	s := time.Now()
	if _, err := store.MemberByIdentifier(tctx(), db, "client", "nobody-here"); err != nil {
		t.Fatal(err)
	}
	took := time.Since(s)
	t.Logf("one miss against a %d-member roster: %v", n, took)
	if took > 100*time.Millisecond {
		t.Fatalf("a miss took %v against %d members; it should not depend on the roster", took, n)
	}
	if u, err := store.MemberByIdentifier(tctx(), db, "client", "m1234"); err != nil || u == nil || u.Name != "m1234" {
		t.Fatalf("a member of the large roster was not found: %v %v", u, err)
	}
}
