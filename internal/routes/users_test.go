// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// How a person is addressed, through the REAL router: the address arrives in the
// query string, the Guard authorizes it there, and the typed op decodes it.
// Exercising it end to end is the point — the defect this pins was never in the
// resolution, it was that the request shape the caller sends had no field to land
// in, so it died at validation before any handler ran.

import (
	"strings"
	"testing"
)

// cloud's team invite (apps/team/invite.go, iamGetUserByEmail) resolves a person
// by their ADDRESS, which is a QUERY over the collection rather than an item
// read: GET /v1/iam/users?owner=<org>&email=<addr>. An email is not the natural
// key — two rows in one org can carry one — so the answer is a page and the
// caller sees both, where an item read would have to pick one.
func TestUsers_ByEmail_IsTheInviteHop(t *testing.T) {
	h := newHarness(t)
	seedUserEmail(t, h, "hanzo", "dana", "Dana@Hanzo.Ai")

	status, body := h.get(t, "/v1/iam/users?owner=hanzo&email=dana@hanzo.ai", h.token(t, "hanzo/boss"))
	if status != 200 {
		t.Fatalf("the invite's own request answered %d: %s", status, body)
	}
	if !strings.Contains(body, `"name":"dana"`) {
		t.Fatalf("the address did not resolve to dana: %s", body)
	}
	// It is the SAME read, so it redacts the same way.
	if strings.Contains(body, secretUserHash) {
		t.Fatalf("the address read leaked a password digest: %s", body)
	}
}

// The tenant bound is the org the caller states, and an org-admin may not state
// somebody else's. Refused BEFORE the store is touched, so it is the same answer
// whether or not that address exists over there.
func TestUsers_ByEmail_RefusesAForeignOrg(t *testing.T) {
	h := newHarness(t)
	seedUserEmail(t, h, "orgb", "bob2", "bob2@orgb.test")

	status, body := h.get(t, "/v1/iam/users?owner=orgb&email=bob2@orgb.test", h.token(t, "hanzo/boss"))
	if status != 403 {
		t.Fatalf("hanzo's admin read orgb by address: %d %s", status, body)
	}
	// Existence-independent: an address nobody holds in that org answers identically.
	absent, _ := h.get(t, "/v1/iam/users?owner=orgb&email=nobody@orgb.test", h.token(t, "hanzo/boss"))
	if absent != status {
		t.Fatalf("present and absent addresses in a foreign org differ (%d vs %d) — an existence oracle", status, absent)
	}
}

// AN ITEM CANNOT BE ADDRESSED HALF-WAY. Resolving one person used to take a
// lookup carrying owner plus exactly one of name or email, checked by the
// handler — a rule that had to be remembered, and a request naming neither
// reached the handler to be refused there. The item lives at
// /v1/iam/users/{owner}/{name} now, so a request missing either half is not an
// under-specified read: it is a different address, and the ROUTER answers it.
func TestAnItemCannotBeAddressedHalfWay(t *testing.T) {
	h := newHarness(t)
	seedUserEmail(t, h, "hanzo", "erin", "erin@hanzo.ai")
	tok := h.token(t, "hanzo/boss")

	// The whole address resolves.
	if status, body := h.get(t, "/v1/iam/users/hanzo/erin", tok); status != 200 {
		t.Fatalf("the item address answered %d: %s", status, body)
	}
	// Half of it is the COLLECTION, which is a listing and not this person.
	status, body := h.get(t, "/v1/iam/users/hanzo", tok)
	if status == 200 && strings.Contains(body, `"name":"erin"`) {
		t.Fatalf("a half-spelled address resolved to a person: %s", body)
	}
}
