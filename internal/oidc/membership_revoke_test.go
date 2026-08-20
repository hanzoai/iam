// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func orgNames(refs []schema.OrgRef) []string {
	names := make([]string, 0, len(refs))
	for _, r := range refs {
		names = append(names, r.Org)
	}
	return names
}

// Revoking a membership must reach a credential the holder ALREADY HAS, not only
// the next sign-in. The rotation is the reach: a resource server reads `orgs` off
// a signed token with no round-trip, so the question is what the NEXT mint says,
// and refresh is the mint every live session performs on its own.
//
// These drive the real router — PKCE grant, store revoke, refresh — and read the
// claim off the signed token, so nothing here can pass by asserting on the row it
// just wrote.

// orgsIn lists the `orgs` claim of a signed token, in order. Order matters: the
// home org is first, and a consumer reads Orgs[0] as the account's own org.
func orgsIn(t *testing.T, raw string) []string {
	t.Helper()
	if raw == "" {
		t.Fatal("no token to read")
	}
	var got Claims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &got); err != nil {
		t.Fatalf("parse token: %v", err)
	}
	names := make([]string, 0, len(got.Orgs))
	for _, o := range got.Orgs {
		names = append(names, o.Org)
	}
	return names
}

func has(orgs []string, want string) bool {
	for _, o := range orgs {
		if o == want {
			return true
		}
	}
	return false
}

// THE NEGATIVE THAT MATTERS: a member revoked from a TEAM org loses it on the
// credential they were already holding. They present the refresh token issued
// before the revoke; the access token it mints no longer carries the org.
func TestRevoke_TeamOrgIsGoneOnACredentialAlreadyHeld(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	if _, err := store.EnsureMembership(ctx, db, "hanzo/alice", "team-x", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	// Alice signs in BEFORE the revoke and keeps this credential.
	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	held := tok["refresh_token"].(string)
	if before := orgsIn(t, tok["access_token"].(string)); !has(before, "team-x") {
		t.Fatalf("precondition: orgs = %v, want team-x present", before)
	}

	removed, err := store.DeleteMembership(ctx, db, "hanzo/alice", "team-x")
	if err != nil || !removed {
		t.Fatalf("revoke: removed=%v err=%v", removed, err)
	}

	// The credential she already held, exercised.
	status, out := refresh(t, app, "pub", held, nil)
	if status != 200 {
		t.Fatalf("refresh after revoke: status=%d body=%v", status, out)
	}
	after := orgsIn(t, out["access_token"].(string))
	if has(after, "team-x") {
		t.Fatalf("REVOKE NOT EFFECTIVE: orgs = %v, team-x survived a revoke on a token already held", after)
	}
	if !has(after, "hanzo") {
		t.Fatalf("orgs = %v: the revoke took the home org too — that is a lockout, not a revoke", after)
	}
}

// THE REGRESSION A NAIVE FIX BREAKS: revoking one member must not touch anybody
// else. Bob keeps team-x on the credential he was already holding while Alice
// loses it.
func TestRevoke_LeavesEveryOtherMemberAlone(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	seedUser(t, db, "bob", "bob@hanzo.ai", "pw")
	for _, u := range []string{"hanzo/alice", "hanzo/bob"} {
		if _, err := store.EnsureMembership(ctx, db, u, "team-x", store.RoleMember); err != nil {
			t.Fatal(err)
		}
	}

	// The harness signs in as alice, so alice is the BYSTANDER holding a
	// credential and bob is the one revoked.
	aliceHeld := grantViaPKCE(t, app, "pub", "openid offline_access")["refresh_token"].(string)

	removed, err := store.DeleteMembership(ctx, db, "hanzo/bob", "team-x")
	if err != nil || !removed {
		t.Fatalf("revoke bob: removed=%v err=%v", removed, err)
	}

	status, out := refresh(t, app, "pub", aliceHeld, nil)
	if status != 200 {
		t.Fatalf("bystander refresh: status=%d body=%v", status, out)
	}
	if got := orgsIn(t, out["access_token"].(string)); !has(got, "team-x") {
		t.Fatalf("BYSTANDER HARMED: alice was not revoked but her orgs = %v, want team-x still present", got)
	}
	// And bob really did lose it — otherwise the case above proves nothing.
	if refs := store.MemberOrgRefs(ctx, db, mustUser(t, db, "hanzo", "bob")); has(orgNames(refs), "team-x") {
		t.Fatalf("bob kept team-x: %v", orgNames(refs))
	}
}

// WHY `remove` REFUSES A HOME-ORG PAIR. Deleting the row through the store — the
// mechanism, beneath the face's refusal — leaves the org in the claim, on a
// credential already held and on every mint after it. The account grants this
// tenancy; the row was only a roster entry beside it.
//
// This is the hole the refusal closes. It is asserted rather than described so
// that anyone who later makes MemberOrgRefs row-only is told, here, that they
// have moved the home org — which is Orgs[0], the value a consumer reads as the
// account's own org and bills against.
func TestRevoke_HomeOrgIsGrantedByTheAccountNotTheRow(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	// The roster row the invite path writes for a member of their own org.
	if _, err := store.EnsureMembership(ctx, db, "hanzo/alice", "hanzo", store.RoleMember); err != nil {
		t.Fatal(err)
	}

	held := grantViaPKCE(t, app, "pub", "openid offline_access")["refresh_token"].(string)

	removed, err := store.DeleteMembership(ctx, db, "hanzo/alice", "hanzo")
	if err != nil || !removed {
		t.Fatalf("row delete: removed=%v err=%v", removed, err)
	}
	if m, _ := store.GetMembership(ctx, db, "hanzo/alice", "hanzo"); m != nil {
		t.Fatal("row still present — this case is about a row that IS gone")
	}

	status, out := refresh(t, app, "pub", held, nil)
	if status != 200 {
		t.Fatalf("refresh: status=%d body=%v", status, out)
	}
	got := orgsIn(t, out["access_token"].(string))
	if !has(got, "hanzo") {
		t.Fatalf("orgs = %v: the home org left the claim. MemberOrgRefs no longer grants "+
			"it from the user row, so Orgs[0] and the billing account move with it — "+
			"store.IsHomeOrg and the `remove` refusal are now describing something untrue", got)
	}
	if got[0] != "hanzo" {
		t.Fatalf("orgs = %v: home org must stay FIRST — a consumer reads Orgs[0] as the account's own org", got)
	}
}

// A machine credential resolves no user and therefore no membership: revoking
// anything cannot alter it, and it never acquires an `orgs` claim it could be
// authorized on. len(orgs)==0 is how a consumer tells a machine from a person, so
// this staying empty is load-bearing in both directions.
func TestRevoke_MachineCredentialCarriesNoMembership(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	seedApp(t, db, appOpts{clientID: "svc", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	if _, err := store.EnsureMembership(ctx, db, "hanzo/alice", "team-x", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}

	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"client_credentials"}, "client_id": {"svc"}, "client_secret": {"s3cret"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("client_credentials: status=%d body=%v", resp.StatusCode, tok)
	}
	raw, _ := tok["access_token"].(string)
	if got := orgsIn(t, raw); len(got) != 0 {
		t.Fatalf("machine token orgs = %v, want none — a machine has no membership", got)
	}
}
