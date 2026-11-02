// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package memberships_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
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
	bob := h.token(t, "orgb/bob")
	grant := map[string]string{"user": "hanzo/boss", "org": "orgb", "role": "admin"}

	if _, e := h.post(t, "/v1/iam/memberships", grant, bob); e.Status != "ok" || !parseBool(t, e) {
		t.Fatalf("grant env=%+v, want ok added=true", e)
	}
	if _, e := h.post(t, "/v1/iam/memberships", grant, bob); e.Status != "ok" || parseBool(t, e) {
		t.Fatalf("repeat grant env=%+v, want ok added=false", e)
	}
	rows := trail(t, h.db, "orgb", schema.ActionMembershipGrant)
	if len(rows) != 2 {
		t.Fatalf("grant rows = %d, want 2", len(rows))
	}
	for i, want := range []bool{true, false} {
		r, o := rows[i], object(t, rows[i])
		if r.User != "orgb/bob" || r.Organization != "orgb" || r.Method != "POST" ||
			r.RequestUri != "/v1/iam/memberships" || r.StatusCode != 200 {
			t.Fatalf("grant row %d = %+v", i, r)
		}
		if o["user"] != "hanzo/boss" || o["org"] != "orgb" || o["role"] != "admin" || o["added"] != want {
			t.Fatalf("grant row %d object = %v, want added=%v", i, o, want)
		}
	}

	if _, e := h.post(t, "/v1/iam/delete-membership", grant, bob); e.Status != "ok" || !parseBool(t, e) {
		t.Fatalf("revoke env=%+v, want ok removed=true", e)
	}
	rows = trail(t, h.db, "orgb", schema.ActionMembershipRevoke)
	if len(rows) != 1 || rows[0].User != "orgb/bob" || object(t, rows[0])["removed"] != true ||
		object(t, rows[0])["role"] != "admin" {
		t.Fatalf("revoke rows = %+v, want one by orgb/bob removed=true role=admin", rows)
	}
	// The removal voided what the account held, and says so in the same org.
	if rows := trail(t, h.db, "orgb", schema.ActionVoid); len(rows) != 1 || object(t, rows[0])["target"] != "hanzo/boss" {
		t.Fatalf("void rows = %+v, want one for hanzo/boss", rows)
	}
}

// A brand's admin does not make an admin of the brand: hanzo is run by the
// platform, so an admin membership there is a SuperAdmin's to grant, and the
// refusal writes nothing.
func TestBrandAdminMembership_isTheSuperAdmins(t *testing.T) {
	h := newHarness(t)
	grant := map[string]string{"user": "orgb/bob", "org": "hanzo", "role": "admin"}
	status, e := h.post(t, "/v1/iam/memberships", grant, h.token(t, "hanzo/boss"))
	if status != 403 || e.Status != "error" {
		t.Fatalf("brand admin grant = %d %+v, want 403", status, e)
	}
	if rows := trail(t, h.db, "hanzo", schema.ActionMembershipGrant); len(rows) != 0 {
		t.Fatalf("refused grant wrote %d rows", len(rows))
	}
	owner := map[string]string{"user": "orgb/bob", "org": "hanzo", "role": "owner"}
	if status, e := h.post(t, "/v1/iam/memberships", owner, h.token(t, "hanzo/boss")); status != 403 {
		t.Fatalf("brand owner grant = %d %+v, want 403", status, e)
	}
	if _, e := h.post(t, "/v1/iam/memberships", grant, h.token(t, "admin/root")); e.Status != "ok" {
		t.Fatalf("SuperAdmin grant env=%+v, want ok", e)
	}
}

// The last admin of an org is not taken away by an org admin: removing the only
// other admin of orgb is refused while it would leave orgb with none.
func TestLastAdminMembership_stays(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	// orgb's only admin is bob; demote bob's flag so its admin is carol, by membership.
	seedUser(t, h.db, "acme", "carol", false)
	if _, err := store.EnsureMembership(ctx, h.db, "acme/carol", "orgb", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	bob, err := store.GetUserByName(ctx, h.db, "orgb", "bob")
	if err != nil || bob == nil {
		t.Fatal(err)
	}
	bob.IsAdmin = false
	if err := bob.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	revoke := map[string]string{"user": "acme/carol", "org": "orgb"}
	status, e := h.post(t, "/v1/iam/delete-membership", revoke, h.token(t, "acme/carol"))
	if status != 409 || e.Status != "error" {
		t.Fatalf("last admin removing themselves = %d %+v, want 409", status, e)
	}
	if m, _ := store.GetMembership(ctx, h.db, "acme/carol", "orgb"); m == nil {
		t.Fatal("the refused revoke removed the membership")
	}
	if _, e := h.post(t, "/v1/iam/delete-membership", revoke, h.token(t, "admin/root")); e.Status != "ok" {
		t.Fatalf("SuperAdmin revoke env=%+v, want ok", e)
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
