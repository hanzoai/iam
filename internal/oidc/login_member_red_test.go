// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"fmt"
	"net/url"
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
// a member row pays that row's own digest plus the lockout write. The fastest of
// many samples of each must be within 25% of the other; the samples are spread over
// several members so no account reaches its lockout.
func TestLogin_MemberMissTakesAsLongAsAWrongPassword(t *testing.T) {
	db, login := memberApp(t)
	const members, tries = 4, 4 // tries stays below the lockout threshold
	for i := 0; i < members; i++ {
		name := fmt.Sprintf("tim%d", i)
		seedArgonUser(t, db, "home3", name, name+"@home3.example", "pw-tim", cred.TypeArgon2id)
		if _, err := store.EnsureMembership(tctx(), db, "home3/"+name, "client", store.RoleMember); err != nil {
			t.Fatal(err)
		}
	}
	fastest := func(user func(i int) string) time.Duration {
		best := time.Duration(1<<62 - 1)
		for i := 0; i < members*tries; i++ {
			s := time.Now()
			login("client", user(i), "not-the-password")
			if d := time.Since(s); d < best {
				best = d
			}
		}
		return best
	}
	hit := fastest(func(i int) string { return fmt.Sprintf("tim%d", i%members) })
	miss := fastest(func(i int) string { return fmt.Sprintf("nobody-%d", i) })
	t.Logf("wrong password on a member: %v, no such member: %v", hit, miss)
	lo, hi := min(hit, miss), max(hit, miss)
	if float64(hi) > 1.25*float64(lo) {
		t.Fatalf("distinguishable: wrong password %v vs no member %v", hit, miss)
	}
}

// A sign-in at a shared app that misses the org's own rows costs ONE read of the
// roster, never a read per member. At 2,000 members one read takes milliseconds
// (about a hundred under the race detector the gate runs with), while a read per
// member takes seconds, so the budget sits between the two.
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
	if took > 500*time.Millisecond {
		t.Fatalf("a miss took %v against %d members; it should not depend on the roster", took, n)
	}
	if u, err := store.MemberByIdentifier(tctx(), db, "client", "m1234"); err != nil || u == nil || u.Name != "m1234" {
		t.Fatalf("a member of the large roster was not found: %v %v", u, err)
	}
}

// A username many other orgs also use costs the org's roster, not the estate.
func TestLogin_MemberMissWithACommonNameCostsTheRosterOnly(t *testing.T) {
	db, _ := memberApp(t)
	const n = 2000
	for i := 0; i < n; i++ {
		org := fmt.Sprintf("o%04d", i)
		u := orm.New[schema.User](db)
		u.Owner, u.Name, u.Email = org, "sam", "sam@shared.example"
		u.SetId(org + "/sam")
		if err := u.CreateCtx(tctx()); err != nil {
			t.Fatal(err)
		}
	}
	for _, id := range []string{"sam", "sam@shared.example"} {
		s := time.Now()
		u, err := store.MemberByIdentifier(tctx(), db, "client", id)
		took := time.Since(s)
		t.Logf("one miss for %q held in %d orgs: %v", id, n, took)
		if u != nil {
			t.Fatalf("%q resolved a non-member %s/%s", id, u.Owner, u.Name)
		}
		if err != nil && !errors.Is(err, store.ErrMemberAmbiguous) {
			t.Fatal(err)
		}
		if took > 100*time.Millisecond {
			t.Fatalf("a miss for %q took %v; it should cost the roster, not the estate", id, took)
		}
	}
}

// Rows written before names and addresses were lowercased keep their case, and
// their people still sign in by name in any case and by the address as written.
func TestLogin_LegacyMixedCaseMemberStillSignsIn(t *testing.T) {
	db, login := memberApp(t)
	seedUserInOrg(t, db, "agency", "Legacy", "Legacy.Person@Agency.Example", "pw-legacy")
	if _, err := store.EnsureMembership(tctx(), db, "agency/Legacy", "client", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"legacy", "LEGACY", "Legacy.Person@Agency.Example"} {
		if m := login("client", id, "pw-legacy"); !minted(m) {
			t.Errorf("legacy member signing in as %q was refused: %v", id, m)
		}
	}
}

// Every reserved home is refused, not only the admin org: built-in and app are
// not SuperAdmins by IsSuperAdmin, so the home check alone keeps them out.
func TestLogin_ReservedHomesAreNotReached(t *testing.T) {
	db, login := memberApp(t)
	for _, home := range []string{"built-in", "app"} {
		name := "svc-" + home
		seedUserInOrg(t, db, home, name, name+"@hanzo.example", "pw-svc")
		if _, err := store.EnsureMembership(tctx(), db, home+"/"+name, "client", store.RoleMember); err != nil {
			t.Fatal(err)
		}
		if u, _ := store.MemberByIdentifier(tctx(), db, "client", name); u != nil {
			t.Errorf("a %s-homed member was resolved: %s/%s", home, u.Owner, u.Name)
		}
		if m := login("client", name, "pw-svc"); minted(m) {
			t.Errorf("a %s-homed member signed in through a tenant app: %v", home, m)
		}
	}
}

// A roster row that names no home is nobody's: it is skipped, not read as a user
// of the org.
func TestLogin_ABareRosterRowNamesNobody(t *testing.T) {
	db, login := memberApp(t)
	if _, err := store.EnsureMembership(tctx(), db, "stray", "client", store.RoleOwner); err != nil {
		t.Fatal(err)
	}
	if m := login("client", "stray", "pw-stray"); minted(m) || m["msg"] != "the username or password is incorrect" {
		t.Fatalf("a bare roster row admitted elsewhere/stray: %v", m)
	}
}

// The password grant and the code-proved reset keep to the org's own accounts:
// only a shared app's interactive sign-in reaches the roster.
func TestLogin_PasswordGrantAndResetStayOffTheRoster(t *testing.T) {
	bindSender(t, &fakeSender{})
	app, db := newServer(t)
	a := seedApp(t, db, appOpts{clientID: "client-patrol", secret: "s3cret", redirectURIs: []string{testRedirect}, shared: true})
	a.Organization = "client"
	if err := a.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	home := seedApp(t, db, appOpts{clientID: "agency-app", secret: "s3cret", redirectURIs: []string{testRedirect}})
	home.Organization = "agency"
	if err := home.UpdateCtx(tctx()); err != nil {
		t.Fatal(err)
	}
	seedOrg(t, db, "agency")
	seedUserInOrg(t, db, "agency", "josh", "josh@agency.example", "pw-josh")
	if _, err := store.EnsureMembership(tctx(), db, "agency/josh", "client", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"}, "client_id": {"client-patrol"}, "client_secret": {"s3cret"},
		"username": {"josh"}, "password": {"pw-josh"}, "scope": {"openid"},
	})
	if resp.StatusCode == 200 || tok["access_token"] != nil {
		t.Fatalf("the password grant reached the roster: %d %v", resp.StatusCode, tok)
	}

	// A code minted for josh in his own org, which a reset naming his own org spends.
	if status, env := sendCode(t, app, map[string]string{
		"dest": "josh@agency.example", "type": "email", "applicationId": "admin/agency-app",
	}); status != 200 || env["status"] != "ok" {
		t.Fatalf("send a code: %d %v", status, env)
	}
	rec, err := store.GetLatestVerificationRecord(tctx(), db, "agency", "josh@agency.example")
	if err != nil || rec == nil {
		t.Fatalf("no code persisted: %v", err)
	}
	status, env := putPassword(t, app, "", `{"organization":"client","username":"josh@agency.example",`+
		`"code":"`+rec.Code+`","password":"a new one"}`)
	if status == 200 && env["status"] == "ok" {
		t.Fatalf("a reset naming client reached its member: %v", env)
	}
	// The control: the same code is good where josh lives.
	status, env = putPassword(t, app, "", `{"organization":"agency","username":"josh@agency.example",`+
		`"code":"`+rec.Code+`","password":"a new one"}`)
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("the control reset at home was refused: %d %v", status, env)
	}
}

// An address that names more accounts than the lookup may weigh is refused as
// ambiguous, deterministically, rather than read in part.
func TestLogin_AnAddressNamingTooManyAccountsIsAmbiguous(t *testing.T) {
	db, _ := memberApp(t)
	for i := 0; i < 20; i++ {
		org := fmt.Sprintf("p%02d", i)
		u := orm.New[schema.User](db)
		u.Owner, u.Name, u.Email = org, "pat", "pat@shared.example"
		u.SetId(org + "/pat")
		if err := u.CreateCtx(tctx()); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.EnsureMembership(tctx(), db, "p19/pat", "client", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if u, err := store.MemberByIdentifier(tctx(), db, "client", "pat@shared.example"); !errors.Is(err, store.ErrMemberAmbiguous) {
		t.Fatalf("an address held by 20 accounts resolved to %v (err=%v); want ambiguous", u, err)
	}
}
