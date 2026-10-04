// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package memberships_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// trail is every audit row filed under org for action, oldest first.
func trail(t *testing.T, db orm.DB, org, action string) []*schema.AuditLog {
	t.Helper()
	rows, err := orm.TypedQuery[schema.AuditLog](db).
		Filter("Owner=", org).Filter("Action=", action).Order("createdTime").GetAll(context.Background())
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	return rows
}

func object(t *testing.T, row *schema.AuditLog) map[string]any {
	t.Helper()
	var o map[string]any
	if err := json.Unmarshal([]byte(row.Object), &o); err != nil {
		t.Fatalf("object %q: %v", row.Object, err)
	}
	return o
}

// An org admin's grant, its repeat and its revoke each leave one row in that org's
// own trail naming the actor, the account, the role and what the store did.
func TestMembershipChanges_areAudited(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")
	grant := map[string]string{"user": "orgb/bob", "org": "hanzo", "role": "admin"}

	if _, e := h.post(t, "/v1/iam/memberships", grant, boss); e.Status != "ok" || !parseBool(t, e) {
		t.Fatalf("grant env=%+v, want ok added=true", e)
	}
	if _, e := h.post(t, "/v1/iam/memberships", grant, boss); e.Status != "ok" || parseBool(t, e) {
		t.Fatalf("repeat grant env=%+v, want ok added=false", e)
	}
	rows := trail(t, h.db, "hanzo", schema.ActionMembershipGrant)
	if len(rows) != 2 {
		t.Fatalf("grant rows = %d, want 2", len(rows))
	}
	for i, want := range []bool{true, false} {
		r, o := rows[i], object(t, rows[i])
		if r.User != "hanzo/boss" || r.Organization != "hanzo" || r.Method != "POST" ||
			r.RequestUri != "/v1/iam/memberships" || r.StatusCode != 200 {
			t.Fatalf("grant row %d = %+v", i, r)
		}
		if o["user"] != "orgb/bob" || o["org"] != "hanzo" || o["role"] != "admin" || o["added"] != want {
			t.Fatalf("grant row %d object = %v, want added=%v", i, o, want)
		}
	}

	if _, e := h.post(t, "/v1/iam/delete-membership", grant, boss); e.Status != "ok" || !parseBool(t, e) {
		t.Fatalf("revoke env=%+v, want ok removed=true", e)
	}
	rows = trail(t, h.db, "hanzo", schema.ActionMembershipRevoke)
	if len(rows) != 1 || rows[0].User != "hanzo/boss" || object(t, rows[0])["removed"] != true {
		t.Fatalf("revoke rows = %+v, want one by hanzo/boss removed=true", rows)
	}
}

// A refused grant changes nothing and records nothing in the org it named.
func TestRefusedGrant_writesNoRow(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")
	_, e := h.post(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/boss", "org": "orgb", "role": "admin"}, boss)
	if e.Status != "error" {
		t.Fatalf("cross-tenant grant env=%+v, want refused", e)
	}
	if rows := trail(t, h.db, "orgb", schema.ActionMembershipGrant); len(rows) != 0 {
		t.Fatalf("refused grant wrote %d rows", len(rows))
	}
}

// The trail cannot be forged: the audit-log CRUD refuses a membership row.
func TestMembershipRows_areNotForgeable(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")
	status, _ := h.post(t, "/v1/iam/audit-logs", map[string]any{
		"owner": "hanzo", "name": "forged", "organization": "hanzo", "user": "hanzo/boss",
		"action": schema.ActionMembershipGrant, "object": `{"user":"x/y","org":"hanzo"}`,
	}, boss)
	if status == 200 {
		t.Fatal("the audit-log CRUD accepted a forged membership-grant row")
	}
	if rows := trail(t, h.db, "hanzo", schema.ActionMembershipGrant); len(rows) != 0 {
		t.Fatalf("forged row landed: %d rows", len(rows))
	}
}
