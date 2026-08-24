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

// The claim is the membership set and nothing besides: the home organization, plus
// every organization a membership grants. "Exactly" is the load-bearing word —
// there is no other input for anything to reach.
func TestUserinfo_GroupsAreExactlyTheMembershipSet(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf", secret: "s3cret", redirectURIs: []string{testRedirect}})
	seedRichUser(t, db)
	if _, err := store.EnsureMembership(context.Background(), db, "hanzo/alice", "lux", store.RoleMember); err != nil {
		t.Fatalf("grant membership: %v", err)
	}

	_, info := userinfo(t, app, accessTokenFor(t, app, "openid profile"))
	got := groupsIn(info)
	if !got["hanzo"] || !got["lux"] {
		t.Fatalf("groups = %v, want the home organization and the granted one", info["groups"])
	}
	if len(got) != 2 {
		t.Fatalf("groups = %v, want exactly the membership set", info["groups"])
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
	if got := groupsIn(info); got["admin"] || len(got) != 1 {
		t.Fatalf("groups = %v before any grant, want the home organization alone", info["groups"])
	}

	if _, err := store.EnsureMembership(context.Background(), db, "hanzo/alice", "admin", store.RoleMember); err != nil {
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
