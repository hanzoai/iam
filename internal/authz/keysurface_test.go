// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz

import "testing"

// THE KEY LIST KEEPS THE GUARD'S READ GATE.
//
// Two key endpoints are handler-authorized by NAME — `keys/org` resolves a
// publishable key to its org, `keys/principal` resolves a secret one to its
// principal — because the key they are asked about rides in ?accessKey= and the
// handler is what decides. Both live under `keys`, which is the whole point: one
// surface, and the address says which projection you get.
//
// What must not follow is a PREFIX rule over that surface. `keys` also carries
// the key LIST, whose rows are credentials, and a prefix entry would take the
// Guard's entity check off it — turning a capability-gated read of an org's keys
// into a read any authenticated caller reaches. Exactness is what keeps the two
// endpoints handler-authorized without exempting what they sit next to.
//
// This is the reason `keys/org` may be spelled that way at all, so it is checked
// rather than asserted in a comment: the earlier address avoided `keys` on
// exactly this worry, and the worry is real — it is the mechanism, not the
// spelling, that answers it.
func TestKeySurfaceHasNoPrefixRule(t *testing.T) {
	for _, p := range handlerAuthorizedPrefixes {
		if len("/v1/iam/keys") >= len(p) && "/v1/iam/keys"[:len(p)] == p {
			t.Errorf("handlerAuthorizedPrefixes carries %q, which covers the key "+
				"surface — the key list would lose the Guard's entity check", p)
		}
	}
	// The list itself is Guard-authorized...
	if pathAuthorized("/v1/iam/keys") {
		t.Error("/v1/iam/keys is handler-authorized; its rows are credentials and " +
			"the Guard's capability check is what gates reading them")
	}
	// ...while the two resolvers beside it are not, by exact name.
	for _, p := range []string{"/v1/iam/keys/org", "/v1/iam/keys/principal"} {
		if !pathAuthorized(p) {
			t.Errorf("%s is not handler-authorized; it names no key the Guard "+
				"could authorize, so the handler is what decides", p)
		}
	}
}
