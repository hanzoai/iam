// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz

import (
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/pkg/store"
)

// ONE PERSON, MANY ORGS.
//
// A human's account lives in one IAM tenant; the organizations they work in are
// a SET. The policy used to answer "may you read this org?" with "is this org
// your account's owner?", so an org's own member — its own ADMIN — could not
// read the org they belong to. Every console that renders a tenant reads that
// row for its name and logo, so a second org was invisible: the picker fell back
// to the signed-in person, and the org mark showed a personal monogram.
func TestOrgReadFollowsMembershipNotTheAccountOwner(t *testing.T) {
	// A person whose account lives in `hanzo`, who also belongs to `maxpower`.
	dave := &Principal{
		Org: "hanzo", User: "davelorenzini",
		Orgs: map[string]policy.Role{"maxpower": store.RoleAdmin},
	}
	// A person in `hanzo` with no other membership.
	stranger := &Principal{Org: "hanzo", User: "nobody"}

	for _, tc := range []struct {
		name   string
		p      *Principal
		method string
		org    string
		want   bool
	}{
		{"member reads the org they belong to", dave, "GET", "maxpower", true},
		{"member reads their home org", dave, "GET", "hanzo", true},
		{"org admin edits the org they administer", dave, "POST", "maxpower", true},
		{"a non-member cannot read that org", stranger, "GET", "maxpower", false},
		{"a non-member cannot edit that org", stranger, "POST", "maxpower", false},
		{"home-org membership alone does not grant editing", stranger, "POST", "hanzo", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := authorize(tc.p, tc.method, "organizations", "admin", tc.org); got != tc.want {
				t.Errorf("authorize(%s %s) = %v, want %v", tc.method, tc.org, got, tc.want)
			}
		})
	}
}

// Belonging is permission to SEE, never to edit. A plain member of an org may
// read it and nothing more — otherwise inviting someone to a workspace would
// hand them its settings.
func TestPlainMemberReadsButCannotWrite(t *testing.T) {
	guest := &Principal{
		Org: "hanzo", User: "guest",
		Orgs: map[string]policy.Role{"maxpower": store.RoleMember},
	}
	if !authorize(guest, "GET", "organizations", "admin", "maxpower") {
		t.Error("a member must be able to read the org they belong to")
	}
	if authorize(guest, "POST", "organizations", "admin", "maxpower") {
		t.Error("a plain member must NOT be able to write the org they belong to")
	}
}

// The membership set carries no authority outside organizations: it says which
// orgs you act in, not that you may reach another tenant's users or signing
// material.
func TestMembershipDoesNotLeakIntoOtherEntities(t *testing.T) {
	dave := &Principal{
		Org: "hanzo", User: "davelorenzini",
		Orgs: map[string]policy.Role{"maxpower": store.RoleAdmin},
	}
	for _, entity := range []string{"users", "certs", "applications", "providers"} {
		if authorize(dave, "GET", entity, "maxpower", "anything") {
			t.Errorf("membership must not grant %s reads in another owner", entity)
		}
	}
}
