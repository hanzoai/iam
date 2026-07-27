// Copyright 2026 Hanzo AI, Inc. All rights reserved.

// SCIM read-side org-scope + the cross-org existence oracle — the port of the
// iam-v1 fix da0732a1 ("scope SCIM reads to caller org + collapse the 404/403
// existence oracle") into the iam architecture.
//
// THREAT (as it existed in iam-v1): Get/Delete/Replace/Patch resolved the SCIM id
// GLOBALLY, then checked scope AFTER the load — so a tenant admin got a 404 for a
// genuinely missing id but a 403 for a row that exists in ANOTHER org. That
// 404-vs-403 split is a cross-org existence oracle: it confirms whether an
// arbitrary user id / userName / email exists in a tenant the caller cannot see.
//
// iam closes it by CONSTRUCTION, one layer earlier than iam-v1 did: scopedTarget
// (scim/users.go) re-pins the requested owner to the caller's OWN org through
// authz.Scope for every non-super, on every verb, BEFORE the store is touched. A
// non-super therefore never addresses a foreign row at all — the lookup key is
// always (callerOrg, name) — so "exists in another org" and "does not exist" are
// the SAME 404, and there is no 403 branch to distinguish them. This test pins
// that invariant so a regression toward the iam-v1 shape (resolve-then-scope,
// which reintroduces the 403) FAILS here.
//
// Reuses the scim_test.go harness: newHarness seeds {admin/root super, hanzo/boss
// admin, hanzo/alice regular, orgb/bob admin}; h.token / h.do / scimUsers.

package scim_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/iam/internal/store"
)

// TestRed_scimGet_noCrossOrgExistenceOracle proves the read path is not an
// existence oracle: for a non-super (hanzo's org-admin), a FOREIGN-existing id
// (orgb/bob — a real row in another tenant), a FOREIGN-missing id (orgb/ghost),
// and an OWN-org-missing id (hanzo/ghost) are ALL the identical 404 with no
// resource body. If scopedTarget regressed to iam-v1's resolve-globally-then-scope
// shape, orgb/bob would resolve and yield a 403 while the others stayed 404 — this
// test would then fail on the mismatched status.
func TestRed_scimGet_noCrossOrgExistenceOracle(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss") // org-admin of hanzo, NOT super

	foreignExistsStatus, foreignExistsBody := h.do(t, "GET", scimUsers+"/orgb/bob", boss, "") // bob EXISTS in orgb
	foreignMissingStatus, _ := h.do(t, "GET", scimUsers+"/orgb/ghost", boss, "")              // exists nowhere
	ownMissingStatus, _ := h.do(t, "GET", scimUsers+"/hanzo/ghost", boss, "")                 // missing in own org

	if foreignExistsStatus != 404 || foreignMissingStatus != 404 || ownMissingStatus != 404 {
		t.Fatalf("VULN: read status leaks existence — foreign-exists=%d foreign-missing=%d own-missing=%d, all must be 404",
			foreignExistsStatus, foreignMissingStatus, ownMissingStatus)
	}
	// The decisive oracle assertion: a row that DOES exist in another org must be
	// indistinguishable (by status) from one that exists nowhere.
	if foreignExistsStatus != foreignMissingStatus {
		t.Fatalf("VULN: cross-org existence oracle — orgb/bob (exists) returned %d but orgb/ghost (missing) returned %d",
			foreignExistsStatus, foreignMissingStatus)
	}
	// And no orgb resource ever leaks in the body (the lookup was re-scoped to hanzo).
	if strings.Contains(foreignExistsBody, `"owner":"orgb"`) || strings.Contains(foreignExistsBody, `"userName"`) {
		t.Fatalf("VULN: cross-org GET leaked an orgb user resource; body=%s", foreignExistsBody)
	}
}

// TestRed_scimMutations_noCrossOrgReachOrOracle proves the SAME collapse holds on
// the mutating verbs the iam-v1 fix covered (Delete/Patch): a non-super's attempt
// to reach a foreign row is re-scoped to its own org, so orgb/bob is never touched
// and a foreign-existing vs foreign-missing target is the same outcome. It asserts
// the cross-org row SURVIVES (no cross-tenant mutation) and that the two verbs do
// not distinguish foreign-exists from foreign-missing.
func TestRed_scimMutations_noCrossOrgReachOrOracle(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	// DELETE: foreign-existing and foreign-missing must yield the same status, and
	// orgb/bob must still exist afterward (the delete hit hanzo/bob, which is absent).
	delExists, _ := h.do(t, "DELETE", scimUsers+"/orgb/bob", boss, "")
	delMissing, _ := h.do(t, "DELETE", scimUsers+"/orgb/ghost", boss, "")
	if delExists != delMissing {
		t.Fatalf("VULN: cross-org DELETE oracle — orgb/bob=%d orgb/ghost=%d must match", delExists, delMissing)
	}
	if u, _ := store.GetUserByName(context.Background(), h.db, "orgb", "bob"); u == nil {
		t.Fatalf("VULN: hanzo's admin DELETED orgb/bob across the tenant boundary")
	}

	// PATCH: same — a cross-org patch attempt is re-scoped to hanzo (absent), so
	// foreign-exists and foreign-missing are the same, and orgb/bob is untouched.
	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
		"Operations":[{"op":"replace","path":"displayName","value":"pwned"}]}`
	patchExists, _ := h.do(t, "PATCH", scimUsers+"/orgb/bob", boss, patch)
	patchMissing, _ := h.do(t, "PATCH", scimUsers+"/orgb/ghost", boss, patch)
	if patchExists != patchMissing {
		t.Fatalf("VULN: cross-org PATCH oracle — orgb/bob=%d orgb/ghost=%d must match", patchExists, patchMissing)
	}
	if u, _ := store.GetUserByName(context.Background(), h.db, "orgb", "bob"); u != nil && u.DisplayName == "pwned" {
		t.Fatalf("VULN: hanzo's admin PATCHED orgb/bob's displayName across the tenant boundary")
	}
}
