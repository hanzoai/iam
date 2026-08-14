// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A signup at a founding application lands in an org of its OWN.
//
// The application's org is where an account is REGISTERED — its username is
// unique there, and its sign-in screen names it. It is not the tenant the person
// works in, and an application open to strangers must not put them in the tenant
// it happens to belong to, which is where the credentials and the spend are.
func TestSignup_FoundsItsOwnOrg(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	status, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo",
		"password": "correct horse battery staple", "email": "stranger@example.com",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("signup failed: status=%d env=%v", status, env)
	}
	data, _ := env["data"].(map[string]any)
	if data["owner"] == "hanzo" {
		t.Fatal("the account was filed in the application's own org")
	}
	if data["owner"] != "stranger" {
		t.Fatalf("owner = %v, want the personal org \"stranger\"", data["owner"])
	}

	// The org exists, is marked personal, and the account is really in it.
	org, err := store.GetOrganizationByName(tctx(), db, "stranger")
	if err != nil || org == nil {
		t.Fatalf("personal org not founded: %v", err)
	}
	if !org.IsPersonal {
		t.Error("the org is not marked personal")
	}
	if u, _ := store.GetUserByName(tctx(), db, "hanzo", "stranger"); u != nil {
		t.Fatal("the account is still in the application's own org")
	}
	if u, _ := store.GetUserByName(tctx(), db, "stranger", "stranger"); u == nil {
		t.Fatal("the account is not in its own org")
	}

	// Sole member. The roster is the (user × org) relation, and it holds one row.
	rows, err := store.MembershipsByOrg(tctx(), db, "stranger")
	if err != nil {
		t.Fatalf("roster: %v", err)
	}
	if len(rows) != 1 || rows[0].User != "stranger/stranger" {
		t.Fatalf("roster = %v, want exactly stranger/stranger", rows)
	}
	// And nothing carried the old tenant over.
	for _, m := range mustMemberships(t, db, "stranger/stranger") {
		if m.Org == "hanzo" {
			t.Fatal("the account kept a membership in the application's own org")
		}
	}
}

// Two people whose addresses yield the same handle both get an org of their own.
// The slug is derived, so the second one cannot simply take the first one's.
func TestSignup_SecondPersonGetsTheirOwnOrgToo(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	for _, addr := range []string{"dave@example.com", "dave@other.example"} {
		status, env := signupReq(t, app, map[string]string{
			"application": "hanzo-cloud", "organization": "hanzo",
			"password": "correct horse battery staple", "email": addr,
		})
		if status != 200 || env["status"] != "ok" {
			t.Fatalf("signup %s failed: %v", addr, env)
		}
	}
	first, _ := store.GetUserByEmail(tctx(), db, "dave", "dave@example.com")
	second, _ := store.GetUserByEmail(tctx(), db, "dave2", "dave@other.example")
	if first == nil || second == nil {
		t.Fatalf("want one account in each of dave and dave2; got %v / %v", first, second)
	}
}

// An address stays taken after the account that holds it moves into its own org.
//
// The uniqueness check reads the application's org, and founding empties that org
// of the very accounts it should be checking against — so without the second
// reach the address is free again, a second person registers it, and then NEITHER
// of them can sign in: two accounts of one application carrying one address name
// nobody, which is the refusal that keeps a person from being authenticated as
// somebody else.
func TestSignup_AddressStaysTakenAfterFounding(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	const addr = "twice@example.com"
	if _, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo",
		"password": "correct horse battery staple", "email": addr,
	}); env["status"] != "ok" {
		t.Fatalf("first signup failed: %v", env)
	}
	_, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo",
		"password": "correct horse battery staple", "email": addr,
	})
	if env["status"] != "error" {
		t.Fatalf("the address was registered twice: %v", env)
	}
	if msg, _ := env["msg"].(string); msg != "email already exists" {
		t.Fatalf("refusal = %q, want the uniqueness refusal", msg)
	}

	// The first account still signs in, which is what the refusal protects.
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": addr, "password": "correct horse battery staple",
		"application": "hanzo-cloud", "clientId": "hanzo-cloud",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	if m := decode(t, body); m["status"] != "ok" {
		t.Fatalf("the account that holds the address cannot sign in: %v", m)
	}
}

// A username too short to be an org slug still gets one. minOrgSlug is 2, so the
// derivation has to walk rather than hand provision a name it will refuse.
func TestSignup_ShortNameStillGetsAnOrg(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	status, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo",
		"username": "z", "password": "correct horse battery staple", "email": "z@example.com",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("signup failed: %v", env)
	}
	data, _ := env["data"].(map[string]any)
	if data["owner"] == "hanzo" || data["owner"] == "z" {
		t.Fatalf("owner = %v, want a slug of at least %d characters", data["owner"], minOrgSlug)
	}
}

// A long address still gets an org. The org's own credential is named after the
// slug, so a slug at the bound leaves no room for that name — and the person
// would be refused at the end of their signup over a name they never chose.
func TestSignup_LongNameStillGetsAnOrg(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	long := strings.Repeat("a", 60)
	for i, addr := range []string{long + "@example.com", long + "@other.example"} {
		status, env := signupReq(t, app, map[string]string{
			"application": "hanzo-cloud", "organization": "hanzo",
			"password": "correct horse battery staple", "email": addr,
		})
		if status != 200 || env["status"] != "ok" {
			t.Fatalf("signup %d failed: %v", i, env)
		}
		data, _ := env["data"].(map[string]any)
		slug, _ := data["owner"].(string)
		if len(slug) > maxOrgSlug {
			t.Fatalf("slug %q is %d characters, over the %d bound", slug, len(slug), maxOrgSlug)
		}
		// The org's default credential is a user row, so its name must be legal too.
		if _, err := schema.Username(slug + "-default"); err != nil {
			t.Fatalf("slug %q yields an illegal credential name: %v", slug, err)
		}
	}
}

// A reserved system owner can never be founded, however the account is named. A
// user under "admin" is a SuperAdmin, so the derivation must walk past it.
func TestSignup_DerivedSlugNeverReservedOrg(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	status, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo",
		"username": "admin", "password": "correct horse battery staple", "email": "admin@example.com",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("signup failed: %v", env)
	}
	data, _ := env["data"].(map[string]any)
	if store.IsReservedOrg(data["owner"].(string)) {
		t.Fatalf("owner = %v, a reserved system org", data["owner"])
	}
	if u, _ := store.GetUserByName(tctx(), db, "admin", "admin"); u != nil {
		t.Fatal("an account was created under the reserved admin org")
	}
}

// An application that does not found orgs is untouched: its accounts stay in its
// own org. The change is per-application, declared, and narrow.
func TestSignup_AppThatDoesNotFoundIsUnchanged(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true})
	seedOrg(t, db, "hanzo")

	_, env := signupReq(t, app, map[string]string{
		"application": "conf", "organization": "hanzo",
		"username": "member", "password": "correct horse battery staple", "email": "member@hanzo.ai",
	})
	data, _ := env["data"].(map[string]any)
	if data["owner"] != "hanzo" {
		t.Fatalf("owner = %v, want hanzo — this app declares no founding", data["owner"])
	}
	if org, _ := store.GetOrganizationByName(tctx(), db, "member"); org != nil {
		t.Fatal("an org was founded for an application that does not found orgs")
	}
}

// A person who has their own org can still JOIN a team org. hanzo, lux and zoo
// are team orgs like any other — nothing about them is special, only membership
// varies — so restricting where a signup LANDS must not restrict who may join.
func TestSignup_TeamOrgStaysJoinable(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	for _, team := range []string{"hanzo", "lux", "zoo"} {
		seedOrg(t, db, team)
	}

	_, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo",
		"password": "correct horse battery staple", "email": "joiner@example.com",
	})
	if env["status"] != "ok" {
		t.Fatalf("signup failed: %v", env)
	}
	me := "joiner/joiner"
	for _, team := range []string{"hanzo", "lux", "zoo"} {
		if _, err := store.EnsureMembership(tctx(), db, me, team, store.RoleMember); err != nil {
			t.Fatalf("join %s: %v", team, err)
		}
	}

	// The signed membership set carries the personal org as home plus every team.
	user, _ := store.GetUserByName(tctx(), db, "joiner", "joiner")
	if user == nil {
		t.Fatal("the account is missing")
	}
	got := map[string]bool{}
	for _, ref := range store.MemberOrgRefs(tctx(), db, user) {
		got[ref.Org] = true
	}
	for _, want := range []string{"joiner", "hanzo", "lux", "zoo"} {
		if !got[want] {
			t.Errorf("membership set is missing %q: %v", want, got)
		}
	}
}

// The account can SIGN IN afterwards. The login screen names the application's
// org — it has no way to know a person's own — so an account founded into its own
// org is unreachable unless login resolves the accounts the application created.
// Without this the fix above is an outage: everybody who signs up is locked out
// the moment they come back.
func TestLogin_ResolvesAnAccountInItsOwnOrg(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	const pw = "correct horse battery staple"
	_, env := signupReq(t, app, map[string]string{
		"application": "hanzo-cloud", "organization": "hanzo",
		"password": pw, "email": "returning@example.com",
	})
	if env["status"] != "ok" {
		t.Fatalf("signup failed: %v", env)
	}

	// Exactly what the portal posts: the APPLICATION's org, and the address.
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "returning@example.com", "password": pw,
		"application": "hanzo-cloud", "clientId": "hanzo-cloud",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("the account it just created cannot sign in: %v", m)
	}
	if code, _ := m["data"].(string); code == "" {
		t.Fatal("no authorization code was minted")
	}
}

// The new arm reaches only the accounts THIS application created. A stranger's
// account elsewhere stays unreachable, so the tenant refusal login already makes
// is unchanged.
func TestLogin_OwnOrgArmDoesNotReachAnotherApp(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-cloud", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedApp(t, db, appOpts{clientID: "other", secret: "s3cret", redirectURIs: []string{testRedirect}, signup: true, orgChoice: "create"})
	seedOrg(t, db, "hanzo")

	const pw = "correct horse battery staple"
	if _, env := signupReq(t, app, map[string]string{
		"application": "other", "organization": "hanzo",
		"password": pw, "email": "elsewhere@example.com",
	}); env["status"] != "ok" {
		t.Fatalf("signup failed: %v", env)
	}

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "elsewhere@example.com", "password": pw,
		"application": "hanzo-cloud", "clientId": "hanzo-cloud",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	if m := decode(t, body); m["status"] != "error" {
		t.Fatalf("an account another application created must not sign in here: %v", m)
	}
}

// mustMemberships reads a user's membership rows or fails the test.
func mustMemberships(t *testing.T, db orm.DB, user string) []*schema.Membership {
	t.Helper()
	rows, err := store.MembershipsByUser(tctx(), db, user)
	if err != nil {
		t.Fatalf("memberships: %v", err)
	}
	return rows
}
