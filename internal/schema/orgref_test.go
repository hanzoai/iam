// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package schema

import (
	"encoding/json"
	"testing"
)

// OrgRef is the claim-side value a consumer (cloud) decodes off a v2 token in
// place of the dead iam-v1 type. These tests pin the HTTP contract: the JSON
// tags MUST stay `org` and `role,omitempty` so a token minted by v2 round-trips
// byte-for-byte through a consumer, and the Membership → OrgRef projection is
// the ONE way to build the `orgs` claim.

func TestOrgRef_wireContract(t *testing.T) {
	// role present: both fields emitted.
	b, err := json.Marshal(OrgRef{Org: "hanzo", Role: "admin"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(b), `{"org":"hanzo","role":"admin"}`; got != want {
		t.Fatalf("marshal(org+role) = %s, want %s", got, want)
	}

	// role omitted: role,omitempty drops the empty field (iam-v1 parity).
	b, err = json.Marshal(OrgRef{Org: "hanzo"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if got, want := string(b), `{"org":"hanzo"}`; got != want {
		t.Fatalf("marshal(org only) = %s, want %s", got, want)
	}

	// decode round-trips (a consumer reading the claim).
	var back OrgRef
	if err := json.Unmarshal([]byte(`{"org":"lux","role":"member"}`), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Org != "lux" || back.Role != "member" {
		t.Fatalf("unmarshal = %+v, want {lux member}", back)
	}
}

func TestOrgRefsFromMemberships_projection(t *testing.T) {
	ms := []*Membership{
		{User: "hanzo/alice", Org: "hanzo", Role: "owner"},
		{User: "hanzo/alice", Org: "lux", Role: "member"},
		nil, // a nil row is skipped, never panics.
	}
	got := OrgRefsFromMemberships(ms)
	want := []OrgRef{{Org: "hanzo", Role: "owner"}, {Org: "lux", Role: "member"}}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d (%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("orgRef[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}

	// an empty set yields a nil slice so the claim is omitted, not emitted empty.
	if OrgRefsFromMemberships(nil) != nil {
		t.Fatalf("OrgRefsFromMemberships(nil) should be nil")
	}
}
