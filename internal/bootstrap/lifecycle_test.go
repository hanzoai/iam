// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// The declaration's semantics are unchanged: it grants org-admin only to a row it
// creates and may lower it on any. What the admin lifecycle adds is that both are
// recorded, and that a lowering voids the account's tokens like every revoke.
func TestUpsertUser_grantAndLoweringAreRecorded(t *testing.T) {
	app, db := boot(t)
	ctx := context.Background()
	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"acme","name":"ops","password":"s3cret","isAdmin":true}`); st != 200 || m["action"] != "created" {
		t.Fatalf("create: status=%d body=%v", st, m)
	}
	if st, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"acme","name":"ops","password":"s3cret","isAdmin":false}`); st != 200 || m["action"] != "updated" {
		t.Fatalf("lower: status=%d body=%v", st, m)
	}
	after := row(t, db, "acme", "ops")
	if after.IsAdmin || after.Epoch == 0 {
		t.Fatalf("after lowering isAdmin=%v epoch=%d, want false and a void", after.IsAdmin, after.Epoch)
	}
	rows, err := orm.TypedQuery[schema.AuditLog](db).Filter("Owner=", "acme").Filter("Action=", schema.ActionOrgAdmin).
		Order("createdTime").GetAll(ctx)
	if err != nil || len(rows) != 2 || rows[0].User != "service" ||
		!strings.Contains(rows[0].Object, `"to":true`) || !strings.Contains(rows[1].Object, `"to":false`) {
		t.Fatalf("org-admin rows = %+v (%v), want the grant then the lowering, by the service token", rows, err)
	}
	// Raising it again on the row that now exists is still refused.
	if st, _ := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"acme","name":"ops","isAdmin":true}`); st != 400 {
		t.Fatalf("re-raise status = %d, want 400", st)
	}
}
