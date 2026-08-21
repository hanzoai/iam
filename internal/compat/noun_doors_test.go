// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package compat_test

import (
	"encoding/json"
	"testing"
)

// THE TWO SPELLINGS ANSWER THE SAME BYTES.
//
// This is the whole guarantee the second address exists to make. A key resolver
// is on the request-authentication path of cloud, ai and base, so its address
// cannot move in one release — the callers are separate deployments. Serving both
// spellings turns a flag day into an ordinary migration, but only if a caller
// that moves gets exactly what it had. "Same handler" is the mechanism; identical
// BYTES is the property, and only the property is worth pinning: a later refactor
// can give the noun its own handler and this still holds, or fails loudly.
//
// It compares full response bodies rather than a field or a status, because the
// projection is what cloud parses — owner, name, email, isAdmin, scope, and the
// billing account that decides who pays. A drift in any one of them is a caller
// resolving a different principal after a migration nobody thought was risky.
func TestBothSpellingsAnswerTheSameBytes(t *testing.T) {
	// Each door has its OWN capability and its own fixture; using one for both
	// would compare two refusals and call them identical.
	for _, tc := range []struct {
		name, verb, noun, key, app, secret string
		seed                               func(*testing.T, *harness)
	}{
		{"the secret door", "/v1/iam/get-user?accessKey=", "/v1/iam/keys/principal?accessKey=",
			projSK, resolverApp, svcSecret, keyFixtures},
		{"the publishable door", "/v1/iam/resolve-key?accessKey=", "/v1/iam/keys/org?accessKey=",
			sitePK, pubResolverApp, pubSecret, pubKeyFixtures},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarness(t)
			tc.seed(t, h)

			vs, vb := h.getBasic(t, tc.verb+tc.key, tc.app, tc.secret)
			ns, nb := h.getBasic(t, tc.noun+tc.key, tc.app, tc.secret)
			if vs != ns {
				t.Fatalf("status: verb=%d noun=%d", vs, ns)
			}
			if vb != nb {
				t.Fatalf("bodies differ, so a caller that moves address changes answer:\n"+
					"  %s -> %s\n  %s -> %s", tc.verb, vb, tc.noun, nb)
			}
			if vs != 200 {
				t.Fatalf("neither answered: status=%d body=%s — the fixture, not the doors", vs, vb)
			}
		})
	}
}

// The noun door for a SECRET key resolves a key and nothing else. get-user also
// reads a user by ?id=, and carrying that here would make this a second address
// for the user read — the thing being retired. Without this, the door would look
// migrated and quietly widen what it answers.
func TestThePrincipalDoorReadsKeysOnly(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	status, body := h.getBasic(t, "/v1/iam/keys/principal?id=hanzo/keyuser", resolverApp, svcSecret)
	if status == 200 && len(body) > 0 && body[0] == '{' {
		var e keyEnv
		if err := json.Unmarshal([]byte(body), &e); err == nil && e.Status == "ok" && e.Data.Owner != "" {
			t.Errorf("?id= resolved a user at the key door: %s", body)
		}
	}
}
