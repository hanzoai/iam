// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz_test

// F1 (half 1) — the token-forgery privilege-escalation, proven closed at the REST
// seam through the REAL mounted router (the harness the eight core cases use).
//
// addToken/updateToken mass-assigned the whole schema.Token from the request body,
// so an org admin — authorized by the seam to write any row it OWNS — could forge a
// refresh-token row naming ANOTHER user (admin/root), with a chosen refreshTokenHash
// and a set codeChallenge, then redeem it through the refresh grant into a
// platform-signed SuperAdmin token. The write routes are REMOVED: mint is the one
// and only write path (internal/oidc grant handlers write the store directly).

import (
	"errors"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// tokenExists reports whether a token row (owner, name) is persisted — the real
// security property: a forged write must leave NOTHING behind.
func (h *harness) tokenExists(t *testing.T, owner, name string) bool {
	t.Helper()
	_, err := orm.Get[schema.Token](h.db, owner+"/"+name)
	if err == nil {
		return true
	}
	if errors.Is(err, orm.ErrNotFound) {
		return false
	}
	t.Fatalf("lookup token %s/%s: %v", owner, name, err)
	return false
}

// The tokens entity has NO mass-assign write surface. An org admin's forge attempt
// is refused on every write verb AND persists nothing. Fail-before: addToken
// accepted it (200) and hanzo/forged persisted with user=admin/root.
func TestTokenWriteCrudRemoved(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss") // org admin of hanzo — authorized to write hanzo-OWNED rows

	// owner is the attacker's OWN org (which the seam authorizes for its admin), but the
	// row names admin/root and carries an attacker-set refresh hash + PKCE challenge — a
	// redeemable SuperAdmin refresh row if it landed.
	forge := map[string]any{
		"owner": "hanzo", "name": "forged",
		"user": "admin/root", "application": "hanzo/app",
		"refreshTokenHash": "attacker-known-hash",
		"codeChallenge":    "attacker-set-challenge",
	}
	for _, w := range []struct{ name, path string }{
		{"create", "/v1/iam/tokens"},
		{"update", "/v1/iam/tokens/update"},
		{"delete", "/v1/iam/tokens/delete"},
	} {
		t.Run(w.name, func(t *testing.T) {
			if got := h.do(t, "POST", w.path, boss, forge); got >= 200 && got < 300 {
				t.Fatalf("POST %s = %d, want a rejection — a token write CRUD is REACHABLE", w.path, got)
			}
		})
	}
	if h.tokenExists(t, "hanzo", "forged") {
		t.Fatal("a forged token row PERSISTED — the mass-assign write surface is OPEN")
	}
}
