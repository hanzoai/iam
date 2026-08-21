// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz_test

import "testing"

// ONE CLIENT, ONE PRINCIPAL, TWO TRANSPORTS.
//
// A confidential client may present its credential two ways: client_secret_basic
// on the request, or the bearer it minted from that identical secret with
// client_credentials. Both are the same identity, so both must resolve to the
// same authority. They did not: the Basic path built the app Principal (App,
// AppOwner, Org = the tenant served), while a machine BEARER fell through to a
// subject-only principal with App empty and Org set to the app row's OWNER half.
//
// The result was a client that could not exercise the capability it is
// allowlisted for: an org-admin app answered 403 to its own org read and to a
// membership grant when it presented its BEARER, and 200 to the same read over
// Basic — the same identity, two answers. This pins that both resolve to one
// principal.
func TestMachineBearerIsTheSamePrincipalAsBasic(t *testing.T) {
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")

	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-console", "s3cret", signingKid)

	// The subject a client_credentials token carries: "<appOwner>/<appName>".
	bearer := h.token(t, "admin/hanzo-console")

	const own = "/v1/iam/get-application?id=admin%2Fhanzo-console"
	if got := h.do(t, "GET", own, bearer, nil); got != 200 {
		t.Errorf("self-read over the machine bearer = %d, want 200 (Basic already answers 200)", got)
	}

	// The capability itself: an org read the allowlist exists to permit.
	const org = "/v1/iam/get-organization?id=admin%2Fhanzo"
	if got := h.do(t, "GET", org, bearer, nil); got == 403 {
		t.Errorf("CapOrgAdmin read over the machine bearer = 403; the allowlisted capability must apply on both transports")
	}
}

// The fix grants nothing new. A bearer whose subject names neither a live user
// nor a live application carries no app authority at all — the phantom subject
// stays inert, which is what keeps "mint a token for admin/<anything>" from
// being an escalation.
func TestMachineBearerForAnUnregisteredAppHasNoAuthority(t *testing.T) {
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")

	h := newHarness(t)
	seedAppRow(t, h.db, "admin", "hanzo-console", "s3cret", signingKid)

	ghost := h.token(t, "admin/not-an-app")
	if got := h.do(t, "GET", "/v1/iam/get-application?id=admin%2Fhanzo-console", ghost, nil); got != 403 {
		t.Errorf("unregistered subject reading another app = %d, want 403", got)
	}
}

// A TENANT-owned application named like a platform one holds nothing on the
// bearer transport either: capabilities are pinned to a reserved signing owner,
// and that pin is in the shared principal both transports now build.
func TestMachineBearerForATenantOwnedLookalikeHoldsNothing(t *testing.T) {
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")

	h := newHarness(t)
	seedAppRow(t, h.db, "hanzo", "hanzo-console", "s3cret", signingKid)

	impostor := h.token(t, "hanzo/hanzo-console")
	if got := h.do(t, "GET", "/v1/iam/get-organization?id=admin%2Fhanzo", impostor, nil); got != 403 {
		t.Errorf("tenant-owned lookalike exercising CapOrgAdmin = %d, want 403", got)
	}
}
