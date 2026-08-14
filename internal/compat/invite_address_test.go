// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package compat_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// seedUserEmail is seedUser plus the address, stored the way every write path
// stores one — normalized — so the read is matching what a real row holds.
func seedUserEmail(t *testing.T, h *harness, owner, name, email string) {
	t.Helper()
	u := orm.New[schema.User](h.db)
	u.Owner, u.Name = owner, name
	u.Email = store.NormalizeEmail(email)
	u.PasswordHash = secretUserHash
	u.PasswordType = "argon2id"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

// The hop that adds somebody to a team, through the REAL router: the address
// arrives in the query string, the Guard authorizes it there, and the typed op
// decodes it. Exercising it end to end is the point — the defect this pins was
// never in the resolution, it was that the request shape the caller sends had no
// field to land in, so it died at validation before any handler ran.
//
// cloud's team invite (apps/team/invite.go, iamGetUserByEmail) sends exactly
// this: GET /v1/iam/users/get?owner=<org>&email=<addr>.

func TestUsersGet_ByEmail_IsTheInviteHop(t *testing.T) {
	h := newHarness(t)
	seedUserEmail(t, h, "hanzo", "dana", "Dana@Hanzo.Ai")

	status, body := h.get(t, "/v1/iam/users/get?owner=hanzo&email=dana@hanzo.ai", h.token(t, "hanzo/boss"))
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
func TestUsersGet_ByEmail_RefusesAForeignOrg(t *testing.T) {
	h := newHarness(t)
	seedUserEmail(t, h, "orgb", "bob2", "bob2@orgb.test")

	status, body := h.get(t, "/v1/iam/users/get?owner=orgb&email=bob2@orgb.test", h.token(t, "hanzo/boss"))
	if status != 403 {
		t.Fatalf("hanzo's admin read orgb by address: %d %s", status, body)
	}
	// Existence-independent: an address nobody holds in that org answers identically.
	absent, _ := h.get(t, "/v1/iam/users/get?owner=orgb&email=nobody@orgb.test", h.token(t, "hanzo/boss"))
	if absent != status {
		t.Fatalf("present and absent addresses in a foreign org differ (%d vs %d) — an existence oracle", status, absent)
	}
}

// One handle addresses one person. Both, or neither, is a request that does not
// say who it means.
func TestUsersGet_RefusesBothHandlesAndNeither(t *testing.T) {
	h := newHarness(t)
	seedUserEmail(t, h, "hanzo", "erin", "erin@hanzo.ai")

	for _, q := range []string{
		"/v1/iam/users/get?owner=hanzo",
		"/v1/iam/users/get?owner=hanzo&name=erin&email=erin@hanzo.ai",
	} {
		status, body := h.get(t, q, h.token(t, "hanzo/boss"))
		if status == 200 {
			t.Fatalf("%s was accepted: %s", q, body)
		}
	}
}
