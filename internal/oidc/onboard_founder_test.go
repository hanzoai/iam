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
// first-class and the door safe:
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
	req := jsonReq("POST", PathOnboard, map[string]any{"name": orgName})
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
	// The boot backfill files every user's HOME-org membership; the move must not
	// strand it on an identity that no longer exists.
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

	// The org is real and stamped to its founder.
	moved, err := store.GetUserByName(ctx, db, "first-start", "alice")
	if err != nil || moved == nil {
		t.Fatalf("founder not resolvable in the org they founded: %v", err)
	}
	org, err := store.GetOrganizationByName(ctx, db, "first-start")
	if err != nil || org == nil {
		t.Fatalf("org row missing: %v", err)
	}
	if org.DisplayName != "First-Start" {
		t.Errorf("org displayName = %q, want %q", org.DisplayName, "First-Start")
	}
	if org.Founder != moved.Model.Id() {
		t.Errorf("org.Founder = %q, want the founder's storage id %q", org.Founder, moved.Model.Id())
	}

	// It has a ROSTER: the founder is on it, as owner. Without this the org is born
	// with nobody on it and no team flow can read who owns it.
	m, err := store.GetMembership(ctx, db, "first-start/alice", "first-start")
	if err != nil {
		t.Fatalf("read membership: %v", err)
	}
	if m == nil {
		t.Fatalf("no membership row: the founder is not on their own org's roster")
	}
	if m.Role != store.RoleOwner {
		t.Errorf("membership role = %q, want %q", m.Role, store.RoleOwner)
	}
	roster, err := store.MembershipsByOrg(ctx, db, "first-start")
	if err != nil || len(roster) != 1 || roster[0].User != "first-start/alice" {
		t.Errorf("org roster = %+v, want exactly the founder", roster)
	}

	// It rides the `orgs` claim, which is what the @hanzo/iam switcher renders.
	refs := store.MemberOrgRefs(ctx, db, moved)
	if len(refs) == 0 || refs[0].Org != "first-start" {
		t.Errorf("orgs claim = %+v, want the founded org", refs)
	}

	// The move re-keyed the identity, so the PREVIOUS home membership must not be
	// left naming a user that no longer exists.
	if stale, _ := store.GetMembership(ctx, db, "hanzo/alice", "hanzo"); stale != nil {
		t.Errorf("stale membership left on the old org's roster: %+v", stale)
	}

	// The founder is still signed in. The re-key invalidates the cookie's
	// (owner, name) key, so onboarding must hand back a session under the new one —
	// otherwise a person is signed out by their own signup.
	fresh := cookieKV(resp.Header.Get("Set-Cookie"))
	if fresh == "" {
		t.Fatalf("onboarding did not re-issue the session cookie across the re-key")
	}
	req := formReqNoBody("GET", PathAccount)
	req.Header.Set("Cookie", fresh)
	_, body := do(t, app, req)
	acct := decode(t, body)
	if acct["status"] != "ok" {
		t.Fatalf("re-issued session does not resolve the caller: %s", body)
	}
	data, _ := acct["data"].(map[string]any)
	if data["owner"] != "first-start" || data["isAdmin"] != true {
		t.Errorf("account after onboarding = owner:%v isAdmin:%v, want first-start / true", data["owner"], data["isAdmin"])
	}

	// The superseded cookie is revoked, not left as a second live credential.
	old := formReqNoBody("GET", PathAccount)
	old.Header.Set("Cookie", cookie)
	_, oldBody := do(t, app, old)
	if decode(t, oldBody)["status"] == "ok" {
		t.Errorf("the pre-re-key session cookie still authenticates: %s", oldBody)
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
	if len(roster) != 1 || roster[0].User != "first-start/alice" {
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

// An anonymous caller is still refused — the door authorizes a FOUNDER, and an
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
