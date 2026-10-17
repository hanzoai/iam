// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// The groups claim answers which organizations a person belongs to. UserInfo and
// the access token answer that one question, so they read it from one place — the
// membership rows — and a client that reads either holds the same answer. A second
// source on the account row would let the two disagree, and a relying party that
// maps groups onto access would follow whichever it happened to read.

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// groupsIn reads the claim as a comparable set.
func groupsIn(info map[string]any) map[string]bool {
	out := map[string]bool{}
	list, _ := info["groups"].([]any)
	for _, g := range list {
		if s, ok := g.(string); ok {
			out[s] = true
		}
	}
	return out
}

// The claim is the part of the membership set the person is a tenant of and
// nothing besides: every organization a membership grants that opens to them. A
// brand org held as a plain member — alice's home here, and lux — opens nothing
// and is no group. "Exactly" is the load-bearing word — there is no other input
// for anything to reach.
func TestUserinfo_GroupsAreExactlyTheMembershipSet(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	for _, org := range []string{"lux", "acme"} {
		if _, err := store.EnsureMembership(context.Background(), db, "hanzo/alice", org, store.RoleMember); err != nil {
			t.Fatalf("grant membership: %v", err)
		}
	}

	_, info := userinfo(t, app, accessTokenFor(t, app, "openid profile"))
	got := groupsIn(info)
	if !got["acme"] || len(got) != 1 {
		t.Fatalf("groups = %v, want exactly acme, the one org that opens to her", info["groups"])
	}
}

// An organization reaches the claim by being GRANTED and by nothing else. Before
// the grant the reserved organization is absent however the account is written;
// after it, it is there. So the claim reports a membership rather than a stored
// string, and a relying party that maps groups onto access is reading a grant.
func TestUserinfo_GroupsFollowTheGrant(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)

	_, info := userinfo(t, app, accessTokenFor(t, app, "openid profile"))
	if got := groupsIn(info); got["admin"] || len(got) != 0 {
		t.Fatalf("groups = %v before any grant, want none: a plain member of hanzo is no tenant of it", info["groups"])
	}

	// An org the platform runs is a group of those who run it, so the grant that
	// reaches the claim is an admin one.
	if _, err := store.EnsureMembership(context.Background(), db, "hanzo/alice", "admin", store.RoleAdmin); err != nil {
		t.Fatalf("grant membership: %v", err)
	}
	_, info = userinfo(t, app, accessTokenFor(t, app, "openid profile"))
	if !groupsIn(info)["admin"] {
		t.Fatalf("groups = %v after the grant, want the granted organization present", info["groups"])
	}
}

// UserInfo and the access token carry the same value, which is the whole point of
// reading them from one place.
func TestUserinfo_GroupsMatchTheToken(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	if _, err := store.EnsureMembership(context.Background(), db, "hanzo/alice", "zoo", store.RoleAdmin); err != nil {
		t.Fatalf("grant membership: %v", err)
	}

	access := accessTokenFor(t, app, "openid profile")
	_, info := userinfo(t, app, access)

	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	got, want := groupsIn(info), map[string]bool{}
	for _, g := range claims.Groups {
		want[g] = true
	}
	if len(got) != len(want) {
		t.Fatalf("userinfo groups %v differ from the token's %v", info["groups"], claims.Groups)
	}
	for g := range want {
		if !got[g] {
			t.Fatalf("userinfo groups %v differ from the token's %v", info["groups"], claims.Groups)
		}
	}
}
