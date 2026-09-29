// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// SuperAdmin is ONE predicate: a person whose own org is "admin". Every
// SuperAdmin-only surface of IAM is asked here, through the real router with a
// genuine bearer, of four callers: two SuperAdmins (with and without the admin
// org's own org-admin bit), a brand org's admin holding an admin-org membership,
// and a machine that lives in the admin org. The first two get in everywhere and
// the last two nowhere, and every request a SuperAdmin makes is on the trail.

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/testdb"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// gate is one SuperAdmin-only request and how to read its answer.
type gate struct {
	name, method, path, body string
	// admitted reports whether the answer is the act performed.
	admitted func(status int, body string) bool
}

func ok(status int, body string) bool {
	return status == 200 && !strings.Contains(body, `"status":"error"`)
}

var superAdminGates = []gate{
	{"list every tenant's certs", "GET", "/v1/iam/certs", "",
		func(s int, b string) bool { return s == 200 && strings.Contains(b, signingKid) }},
	{"read another tenant's users", "GET", "/v1/iam/users?owner=orgb", "",
		func(s int, b string) bool { return s == 200 && strings.Contains(b, `"bob"`) }},
	{"read the admin org's users", "GET", "/v1/iam/users?owner=admin", "",
		func(s int, b string) bool { return s == 200 && strings.Contains(b, `"root"`) }},
	{"write another tenant's user", "PUT", "/v1/iam/users/orgb/bob", `{"user":{"displayName":"Changed"}}`, ok},
	{"write an admin-org account", "PUT", "/v1/iam/users/admin/root", `{"user":{"displayName":"Changed"}}`, ok},
	{"read the admin org's registry row", "GET", "/v1/iam/organizations/admin/admin", "", ok},
	{"edit the admin org's registry row", "POST", "/v1/iam/organizations/avatar", `{"owner":"admin","name":"admin","emoji":"🦊"}`, ok},
	{"read another tenant's registry row", "GET", "/v1/iam/organizations/admin/orgb", "", ok},
	{"grant a membership of a reserved org", "POST", "/v1/iam/memberships", `{"user":"hanzo/alice","org":"built-in"}`, ok},
	{"read another tenant's keys", "GET", "/v1/iam/keys?owner=orgb", "", ok},
}

// gateFixtures seeds the admin and orgb registry rows, a SuperAdmin without the
// org-admin bit, a brand org's admin holding an admin-org membership, and two
// machines in the admin org.
func gateFixtures(t *testing.T, h *harness) {
	t.Helper()
	ctx := context.Background()
	for _, name := range []string{"admin", "orgb"} {
		o := orm.New[schema.Organization](h.db)
		o.Owner, o.Name = "admin", name
		o.SetId("admin/" + name)
		if err := o.CreateCtx(ctx); err != nil {
			t.Fatalf("seed org %s: %v", name, err)
		}
	}
	seedUser(t, h.db, "admin", "ops", false)
	seedUser(t, h.db, "hanzo", "op", true)
	if err := testdb.Member(ctx, h.db, "hanzo/op", "admin", store.RoleAdmin); err != nil {
		t.Fatalf("grant: %v", err)
	}
	for _, typ := range []string{schema.ServiceAccount, schema.Program} {
		seedUser(t, h.db, "admin", "svc-"+typ, true)
		u, err := store.GetUserByName(ctx, h.db, "admin", "svc-"+typ)
		if err != nil || u == nil {
			t.Fatalf("read svc-%s: %v", typ, err)
		}
		u.Type = typ
		if err := u.UpdateCtx(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// trail counts the SuperAdmin trail rows naming user.
func trail(t *testing.T, h *harness, user string) []*schema.AuditLog {
	t.Helper()
	rows, err := orm.TypedQuery[schema.AuditLog](h.db).
		Filter("Action=", schema.ActionSuperAdmin).Filter("User=", user).GetAll(context.Background())
	if err != nil {
		t.Fatalf("read trail: %v", err)
	}
	return rows
}

func TestEverySuperAdminGateAdmitsTheAdminOrgsPeopleOnly(t *testing.T) {
	for _, c := range []struct {
		sub  string
		want bool
	}{
		{"admin/root", true},
		{"admin/ops", true},
		{"hanzo/op", false},
		{"admin/svc-" + schema.ServiceAccount, false},
		{"admin/svc-" + schema.Program, false},
	} {
		for _, g := range superAdminGates {
			t.Run(c.sub+"/"+g.name, func(t *testing.T) {
				h := newHarness(t)
				gateFixtures(t, h)
				status, body := h.send(t, h.person(t, c.sub), g.method, g.path, g.body)
				if got := g.admitted(status, body); got != c.want {
					t.Fatalf("%s %s as %s: admitted=%v, want %v (status=%d body=%s)",
						g.method, g.path, c.sub, got, c.want, status, body)
				}
				// A refusal is an AUTHORIZATION refusal, never a request some other
				// rule happened to reject first.
				if !c.want && status != 403 && !strings.Contains(body, "Unauthorized") {
					t.Fatalf("%s %s as %s was refused for another reason: %d %s", g.method, g.path, c.sub, status, body)
				}
				// Every request made with platform authority is on the trail, with
				// its answer; a caller without it leaves no SuperAdmin row.
				rows := trail(t, h, c.sub)
				if !c.want {
					if len(rows) != 0 {
						t.Fatalf("a non-SuperAdmin left %d SuperAdmin trail rows", len(rows))
					}
					return
				}
				if len(rows) != 1 {
					t.Fatalf("SuperAdmin trail rows = %d, want 1", len(rows))
				}
				r := rows[0]
				if r.Owner != "admin" || r.Method != g.method || r.RequestUri != g.path || r.StatusCode != status {
					t.Fatalf("trail row %+v does not record %s %s -> %d", r, g.method, g.path, status)
				}
			})
		}
	}
}

// A refusal downstream of the Guard is recorded with the status it answered, so
// the trail says what platform authority tried and did not get.
func TestTheSuperAdminTrailRecordsARefusalsStatus(t *testing.T) {
	h := newHarness(t)
	status, _ := h.send(t, h.person(t, "admin/root"), "POST", "/v1/iam/keys", `{"owner":"admin","name":"k","user":"root"}`)
	if status != 403 {
		t.Fatalf("a secret key for a SuperAdmin answered %d, want 403", status)
	}
	rows := trail(t, h, "admin/root")
	if len(rows) != 1 || rows[0].StatusCode != 403 || rows[0].Method != "POST" || rows[0].RequestUri != "/v1/iam/keys" {
		t.Fatalf("trail = %+v, want one POST /v1/iam/keys row answered 403", rows)
	}
}

// The trail is the platform's to write: the audit-log surface can neither forge
// nor remove a row of it, a SuperAdmin included.
func TestTheSuperAdminTrailIsReserved(t *testing.T) {
	h := newHarness(t)
	root := h.person(t, "admin/root")
	if status, body := h.send(t, root, "POST", "/v1/iam/audit-logs",
		`{"owner":"admin","name":"forged","action":"`+schema.ActionSuperAdmin+`"}`); status != 403 {
		t.Fatalf("a forged SuperAdmin trail row answered %d: %s", status, body)
	}
	rows := trail(t, h, "admin/root")
	if len(rows) != 1 {
		t.Fatalf("trail rows = %d, want only the refused request", len(rows))
	}
	path := "/v1/iam/audit-logs/" + rows[0].Owner + "/" + rows[0].Name
	if status, body := h.send(t, root, "DELETE", path, ""); status != 403 {
		t.Fatalf("deleting a SuperAdmin trail row answered %d: %s", status, body)
	}
}
