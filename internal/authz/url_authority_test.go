// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz_test

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// THE URL IS THE ADDRESSING AUTHORITY, AND THIS IS THE ONLY TEST THAT PROVES IT.
//
// Every other case that writes through an item address sends a body agreeing
// with the path, so all of them pass whether the URL is read or ignored. The
// property only becomes visible when the two DISAGREE.
//
// It is not hypothetical. Measured on the shape this replaced, a PUT to
// /v1/iam/users/hanzo/alice carrying {"user":{"owner":"zoo","name":"eve",…}}
// wrote zoo/eve and left hanzo/alice untouched: the URL was decorative and the
// body chose its own target. zip's bindURL walks wireFields, which promotes
// only ANONYMOUS embedded structs, so it never descends into a named field —
// and UpdateInput nests the record under `user`. The fix is a pair of top-level
// fields carrying `json:"-" url:"owner"`, which keeps the body's shape and puts
// the target where the binder can reach it.
//
// This matters beyond a mis-write: AuthzTarget feeds the Guard. If the body
// picks the target, then the row AUTHORIZED and the row WRITTEN are chosen by
// different values, and a caller authorized for one record can edit another.
func TestURLOutranksTheBodyOnAnItemWrite(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "alice", false, false, false)
	seedUser(t, h.db, "hanzo", "bystander", false, false, false)
	root := h.token(t, "admin/root") // SuperAdmin: authorized for both rows

	// The body names bystander; the URL names alice. One of them wins.
	body := map[string]any{"user": map[string]any{
		"owner": "hanzo", "name": "bystander", "displayName": "WROTE-THE-BODY-TARGET",
	}}
	if got := h.do(t, "PUT", "/v1/iam/users/hanzo/alice", root, body); got != 200 {
		t.Fatalf("PUT /v1/iam/users/hanzo/alice = %d, want 200", got)
	}

	alice, bystander := load(t, h.db, "hanzo", "alice"), load(t, h.db, "hanzo", "bystander")
	if alice.DisplayName != "WROTE-THE-BODY-TARGET" {
		t.Errorf("the URL named alice and alice was not written (displayName=%q) — "+
			"the address is decorative", alice.DisplayName)
	}
	if bystander.DisplayName != "" {
		t.Errorf("the body named bystander and bystander WAS written (displayName=%q) — "+
			"a body can redirect a write away from the row the URL named, which is the "+
			"row the Guard authorized", bystander.DisplayName)
	}
}

// And the same disagreement must not let a caller reach a row it may not touch.
// hanzo's own admin is authorized for hanzo/alice and for nothing in zoo; a body
// naming zoo must not carry the write there.
func TestABodyCannotCarryAWriteIntoAnotherOrg(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "alice", false, false, false)
	seedUser(t, h.db, "zoo", "eve", false, false, false)
	boss := h.token(t, "hanzo/boss") // admin OF hanzo, nothing in zoo

	body := map[string]any{"user": map[string]any{
		"owner": "zoo", "name": "eve", "displayName": "CROSSED-THE-TENANT",
	}}
	// Whatever the status, the one thing that must not happen is a write to zoo.
	_ = h.do(t, "PUT", "/v1/iam/users/hanzo/alice", boss, body)
	if eve := load(t, h.db, "zoo", "eve"); eve.DisplayName != "" {
		t.Errorf("a hanzo admin wrote zoo/eve (displayName=%q) by naming it in a body "+
			"while addressing hanzo/alice", eve.DisplayName)
	}
}

// load reads one user row straight from the store, so the assertion is about what
// was WRITTEN rather than about what a response said.
func load(t *testing.T, db orm.DB, owner, name string) *schema.User {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), db, owner, name)
	if err != nil {
		t.Fatalf("load %s/%s: %v", owner, name, err)
	}
	if u == nil {
		t.Fatalf("%s/%s is gone", owner, name)
	}
	return u
}
