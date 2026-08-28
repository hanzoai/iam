// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

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
// (scim/users.go) resolves the requested owner through principal.Scope for every
// non-super, on every verb, BEFORE the store is touched. So the outcome is
// decided without a lookup, and "exists in another org" and "does not exist" are
// the SAME answer with no branch that could distinguish them. This test pins that
// invariant so a regression toward the iam-v1 shape (resolve-then-scope, which
// splits 404 from 403) FAILS here.
//
// WHAT CHANGED, AND WHY THE ANSWER MOVED FROM 404 TO 403. Scope used to close the
// oracle by REWRITING the foreign owner to the caller's own — /Users/orgb/bob
// silently became a lookup of hanzo/bob. That collapsed the two probes, but only
// because it answered a different question than the one asked, and the collapse
// held ONLY while the name was absent from the caller's own org. Give hanzo a
// `bob` and the same request returns 200 carrying HANZO's bob under orgb's URL —
// a DIFFERENT HUMAN, correctly authorized, wrongly attributed. A caller that then
// deactivates "orgb/bob" deactivates a hanzo employee. The rewrite was never a
// safe answer; it was an answer whose danger this file happened not to sample.
// Scope now REFUSES a foreign owner instead (principal.Scope: honoured or refused,
// never silently reinterpreted), so the collapse no longer depends on what the
// caller's own org happens to contain.
//
// The oracle stays closed, for the reason that always mattered: the refusal is
// computed from the verified principal alone and never touches the store, so
// foreign-exists and foreign-missing are the identical 403. Own-org-missing stays
// 404 — that distinguishes "your org" from "not your org", which the caller
// already knows, and discloses nothing about any tenant but its own.
//
// Reuses the scim_test.go harness: newHarness seeds {admin/root super, hanzo/boss
// admin, hanzo/alice regular, orgb/bob admin}; h.token / h.do / scimUsers.

package scim_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// TestRed_scimGet_noCrossOrgExistenceOracle proves the read path is not an
// existence oracle: for a non-super (hanzo's org-admin), a FOREIGN-existing id
// (orgb/bob — a real row in another tenant) and a FOREIGN-missing id (orgb/ghost)
// are the identical refusal with no resource body. If scopedTarget regressed to
// iam-v1's resolve-globally-then-scope shape, orgb/bob would resolve and split the
// two statuses — this test would fail on the mismatch.
func TestRed_scimGet_noCrossOrgExistenceOracle(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss") // org-admin of hanzo, NOT super

	foreignExistsStatus, foreignExistsBody := h.do(t, "GET", scimUsers+"/orgb/bob", boss, "") // bob EXISTS in orgb
	foreignMissingStatus, _ := h.do(t, "GET", scimUsers+"/orgb/ghost", boss, "")              // exists nowhere
	ownMissingStatus, _ := h.do(t, "GET", scimUsers+"/hanzo/ghost", boss, "")                 // missing in own org

	// The decisive oracle assertion: a row that DOES exist in another org must be
	// indistinguishable from one that exists nowhere.
	if foreignExistsStatus != foreignMissingStatus {
		t.Fatalf("VULN: cross-org existence oracle — orgb/bob (exists) returned %d but orgb/ghost (missing) returned %d",
			foreignExistsStatus, foreignMissingStatus)
	}
	// Both are the refusal a foreign org earns, decided without a lookup.
	if foreignExistsStatus != 403 {
		t.Fatalf("VULN: cross-org read returned %d, want 403 — a foreign org is refused, "+
			"never re-aimed at the caller's own; body=%s", foreignExistsStatus, foreignExistsBody)
	}
	// Own-org absence stays a genuine 404: it is the honest answer to a request
	// the caller was entitled to make.
	if ownMissingStatus != 404 {
		t.Fatalf("own-org missing id returned %d, want 404", ownMissingStatus)
	}
	// And no orgb resource ever leaks in the body.
	if strings.Contains(foreignExistsBody, `"owner":"orgb"`) || strings.Contains(foreignExistsBody, `"userName"`) {
		t.Fatalf("VULN: cross-org GET leaked an orgb user resource; body=%s", foreignExistsBody)
	}
}

// THE CASE THE 404 COLLAPSE WAS BLIND TO. Re-pinning a foreign owner to the
// caller's own org looks safe exactly as long as the requested NAME is absent
// from the caller's org. When it is present — and a `bob`, an `admin`, an `ops`
// exists in nearly every tenant — the same request returns 200 carrying the
// caller's own row under the foreign tenant's URL. That is not a leak (no orgb
// data crosses) and that is what makes it dangerous: it is a confident, correctly
// authorized answer about the WRONG PERSON, and every downstream verb — PATCH
// active:false, DELETE — then lands on that person.
func TestRed_scimGet_foreignIdNeverResolvesToASameNamedLocalUser(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "bob", false) // the name collision that exists in real tenants
	boss := h.token(t, "hanzo/boss")

	status, body := h.do(t, "GET", scimUsers+"/orgb/bob", boss, "")
	if status == 200 {
		t.Fatalf("VULN: GET /Users/orgb/bob returned 200 — it resolved hanzo/bob and "+
			"presented it as orgb/bob; body=%s", body)
	}
	if strings.Contains(body, `"hanzo/bob"`) || strings.Contains(body, `"owner":"hanzo"`) {
		t.Fatalf("VULN: a request naming tenant orgb was answered with a hanzo identity; body=%s", body)
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
