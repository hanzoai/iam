// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package oidc

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// SELF-SERVICE ORG CREATION — the hanzo.id /onboarding flow.
//
// A person signing up types an org name and gets an org they OWN. The authority
// is FOUNDERSHIP, not a borrowed console capability: the caller is resolved from
// its own session (or bearer) and may only found an org for ITSELF, so widening
// IAM_ORG_ADMIN_APPS — which would let one app administer EVERY tenant's orgs —
// is never the mechanism. These pin the three properties that makes the org
// first-class and the endpoint safe:
//
//  1. the founder succeeds, and the org is real: Founder stamped, roster row
//     (user × org × owner), `orgs` claim, and the session survives the re-key;
//  2. a DIFFERENT identity can neither complete nor join that org;
//  3. an unauthenticated caller is still refused.

// seedFounder creates a password user in org `owner` who can drive a bare portal
// sign-in — the browser credential the onboarding page actually carries.
func seedFounder(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.Email = name + "@example.com"
	u.EmailVerified = true
	u.PasswordHash = string(hash)
	u.PasswordType = "bcrypt"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed founder %s/%s: %v", owner, name, err)
	}
}

// portalSession drives a bare (type=login) sign-in for (org, user) and returns
// the session cookie — exactly what hanzo.id holds after a portal sign-in, which
// mints NO bearer at all.
func portalSession(t *testing.T, app *zip.App, org, user string) string {
	t.Helper()
	form := url.Values{
		"organization": {org}, "application": {"conf"},
		"username": {user}, "password": {"pw"}, "type": {"login"},
	}
	resp, body := do(t, app, formReq("POST", PathLogin, form))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("portal sign-in for %s/%s failed: %s", org, user, body)
	}
	return cookieKV(resp.Header.Get("Set-Cookie"))
}

// onboardAs posts the onboarding form with the caller's session cookie.
func onboardAs(t *testing.T, app *zip.App, cookie, orgName string) (*http.Response, map[string]any) {
	t.Helper()
	req := fromPage(jsonReq("POST", PathOnboard, map[string]any{"name": orgName}))
	if cookie != "" {
		req.Header.Set("Cookie", cookie)
	}
	resp, body := do(t, app, req)
	return resp, decode(t, body)
}

// A signed-in human founds their OWN org and it is FIRST-CLASS: the org exists
// with them stamped as Founder, they are on its roster as owner, the org rides
// their `orgs` claim (so the switcher shows it immediately), and their session
// survives the identity re-key the move performs.
func TestOnboard_FounderGetsAFirstClassOrg(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")
	// The boot backfill files every user's HOME-org membership; founding an org
	// leaves it where it is.
	if _, err := store.EnsureMembership(ctx, db, "hanzo/alice", "hanzo", store.RoleMember); err != nil {
		t.Fatalf("seed home membership: %v", err)
	}

	cookie := portalSession(t, app, "hanzo", "alice")
	resp, env := onboardAs(t, app, cookie, "First-Start")
	if resp.StatusCode != 200 {
		t.Fatalf("founder onboarding refused: status=%d body=%+v", resp.StatusCode, env)
	}
	if env["org"] != "first-start" {
		t.Fatalf("onboard org = %v, want first-start", env["org"])
	}

	// The founder's account is the one they signed up with, untouched.
	alice, err := store.GetUserByName(ctx, db, "hanzo", "alice")
	if err != nil || alice == nil || alice.IsAdmin {
		t.Fatalf("hanzo/alice = %+v (%v), want the same account, admin of nothing new", alice, err)
	}
	if moved, _ := store.GetUserByName(ctx, db, "first-start", "alice"); moved != nil {
		t.Fatalf("the founder was moved into the org: %+v", moved)
	}
	// The org is real and stamped to its founder.
	org, err := store.GetOrganizationByName(ctx, db, "first-start")
	if err != nil || org == nil {
		t.Fatalf("org row missing: %v", err)
	}
	if org.DisplayName != "First-Start" {
		t.Errorf("org displayName = %q, want %q", org.DisplayName, "First-Start")
	}
	if org.Founder != alice.Model.Id() {
		t.Errorf("org.Founder = %q, want the founder's storage id %q", org.Founder, alice.Model.Id())
	}

	// It has a ROSTER: the founder is on it, as owner, and that row is how they own
	// it at all.
	roster, err := store.MembershipsByOrg(ctx, db, "first-start")
	if err != nil || len(roster) != 1 || roster[0].User != "hanzo/alice" || roster[0].Role != store.RoleOwner {
		t.Fatalf("org roster = %+v (%v), want exactly hanzo/alice as owner", roster, err)
	}
	// Its default key is the founder's.
	if k, _ := orm.Get[schema.Key](db, "first-start/default"); k == nil || k.User != "hanzo/alice" {
		t.Errorf("first-start/default = %+v, want it held by hanzo/alice", k)
	}

	// It rides the `orgs` claim, which is what the @hanzo/iam switcher renders,
	// after the home org.
	refs := store.MemberOrgRefs(ctx, db, alice)
	if len(refs) != 2 || refs[0].Org != "hanzo" || refs[1].Org != "first-start" || refs[1].Role != store.RoleOwner {
		t.Errorf("orgs claim = %+v, want hanzo then first-start as owner", refs)
	}
	if home, _ := store.GetMembership(ctx, db, "hanzo/alice", "hanzo"); home == nil {
		t.Error("the founder's home membership was removed")
	}

	// The founder's session is the one they had: nothing was re-keyed.
	req := formReqNoBody("GET", PathAccount)
	req.Header.Set("Cookie", cookie)
	_, body := do(t, app, req)
	acct := decode(t, body)
	data, _ := acct["data"].(map[string]any)
	if acct["status"] != "ok" || data["owner"] != "hanzo" {
		t.Fatalf("the founder's session after onboarding = %s, want hanzo/alice", body)
	}

	// And they sign in again with the address and password they signed up with.
	// A move re-keyed them to first-start/alice, and the sign-in, which looks an
	// address up in the app's org, found nobody.
	_, lbody := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "application": "conf", "clientId": "conf",
		"username": "alice@example.com", "password": "pw",
		"redirectUri": testRedirect, "scope": "openid", "type": "code",
	}))
	if m := decode(t, lbody); m["status"] != "ok" {
		t.Fatalf("signing in again by address after founding an org: %v", m)
	}
}

// A DIFFERENT identity can neither complete nor join an org someone else founded:
// the slug is refused, and the intruder gains no roster row and no `orgs` entry.
func TestOnboard_ForeignIdentityCannotTakeOrJoinTheOrg(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")
	seedFounder(t, db, "hanzo", "mallory")

	if resp, env := onboardAs(t, app, portalSession(t, app, "hanzo", "alice"), "First-Start"); resp.StatusCode != 200 {
		t.Fatalf("founder onboarding refused: status=%d body=%+v", resp.StatusCode, env)
	}

	resp, env := onboardAs(t, app, portalSession(t, app, "hanzo", "mallory"), "First-Start")
	if resp.StatusCode != 409 {
		t.Fatalf("foreign claim on an existing org: status=%d body=%+v, want 409", resp.StatusCode, env)
	}

	// No membership, so no `orgs` entry, so no switch into someone else's tenant.
	if m, _ := store.GetMembership(ctx, db, "hanzo/mallory", "first-start"); m != nil {
		t.Errorf("intruder was granted membership of another founder's org: %+v", m)
	}
	if m, _ := store.GetMembership(ctx, db, "first-start/mallory", "first-start"); m != nil {
		t.Errorf("intruder was granted membership of another founder's org: %+v", m)
	}
	roster, _ := store.MembershipsByOrg(ctx, db, "first-start")
	if len(roster) != 1 || roster[0].User != "hanzo/alice" {
		t.Errorf("roster = %+v, want only the founder", roster)
	}
	// And the intruder was not moved: their identity is untouched.
	if u, _ := store.GetUserByName(ctx, db, "hanzo", "mallory"); u == nil || u.Owner != "hanzo" {
		t.Errorf("intruder identity was disturbed by the refused claim: %+v", u)
	}
	for _, r := range store.MemberOrgRefs(ctx, db, mustUser(t, db, "hanzo", "mallory")) {
		if r.Org == "first-start" {
			t.Errorf("intruder's orgs claim carries another founder's org: %+v", r)
		}
	}
}

// An anonymous caller is still refused — the endpoint authorizes a FOUNDER, and an
// unauthenticated request has no founder to be.
func TestOnboard_AnonymousIsRefused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedFounder(t, db, "hanzo", "alice")

	resp, env := onboardAs(t, app, "", "First-Start")
	if resp.StatusCode != 401 {
		t.Fatalf("anonymous onboarding status=%d body=%+v, want 401", resp.StatusCode, env)
	}
	if org, _ := store.GetOrganizationByName(context.Background(), db, "first-start"); org != nil {
		t.Fatalf("an anonymous caller created an org: %+v", org)
	}
	// A garbage bearer is no better than none.
	req := jsonReq("POST", PathOnboard, map[string]any{"name": "First-Start"})
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 40))
	resp2, body2 := do(t, app, req)
	if resp2.StatusCode != 401 {
		t.Fatalf("forged-bearer onboarding status=%d body=%s, want 401", resp2.StatusCode, body2)
	}
}

func mustUser(t *testing.T, db orm.DB, owner, name string) *schema.User {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("user %s/%s: %v", owner, name, err)
	}
	return u
}
