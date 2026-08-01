// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz_test

// Tenant isolation on the LIST routes, driven through the real registered router.
//
// The bug this pins was a confused deputy, and it was invisible from either half
// alone. The Guard authorizes on the query string — asking for a foreign org is
// correctly refused — and then the handler filtered on `in.Owner` instead of on
// the principal. A zip typed GET binds NOTHING from the request (a body is read
// only for non-GET), so `in.Owner` arrived EMPTY on every REST call, took the
// "empty owner lists everything" branch, and returned every tenant's rows.
//
// So the shape was: name someone else's org and get 403; name YOUR OWN org and
// get the whole table. A status-code assertion passes throughout — only the body
// shows it, which is why every case here reads the response.
//
// certs was the one lister that already resolved the owner via authz.Scope, and
// it is included as the control: if the others ever regress, certs still passes
// and the diff points straight at the cause.

import (
	"context"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/orm"
)

func seedRole(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	r := orm.New[schema.Role](db)
	r.Owner, r.Name = owner, name
	r.SetId(owner + "/" + name)
	if err := r.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed role %s/%s: %v", owner, name, err)
	}
}

func seedInvitation(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	i := orm.New[schema.Invitation](db)
	i.Owner, i.Name = owner, name
	i.SetId(owner + "/" + name)
	if err := i.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed invitation %s/%s: %v", owner, name, err)
	}
}

func seedToken(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	tk := orm.New[schema.Token](db)
	tk.Owner, tk.Name = owner, name
	tk.SetId(owner + "/" + name)
	if err := tk.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed token %s/%s: %v", owner, name, err)
	}
}

func seedWebauthn(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	w := orm.New[schema.WebauthnCredential](db)
	w.Owner, w.Name = owner, name
	w.SetId(owner + "/" + name)
	if err := w.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed webauthn %s/%s: %v", owner, name, err)
	}
}

func seedAuditLog(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	a := orm.New[schema.AuditLog](db)
	a.Owner, a.Name = owner, name
	a.Organization = owner
	a.SetId(owner + "/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed auditlog %s/%s: %v", owner, name, err)
	}
}

// TestListRoutesNeverLeakAnotherTenant is the regression. Each lister gets one
// row in the caller's org and one in a foreign org; an org admin listing its own
// org must see its own row and MUST NOT see the foreign one.
//
// The marker names are deliberately distinctive so a match cannot be incidental.
func TestListRoutesNeverLeakAnotherTenant(t *testing.T) {
	h := newHarness(t)

	seedRole(t, h.db, "hanzo", "role-mine-hanzo")
	seedRole(t, h.db, "orgb", "role-secret-orgb")
	seedInvitation(t, h.db, "hanzo", "invite-mine-hanzo")
	seedInvitation(t, h.db, "orgb", "invite-secret-orgb")
	seedAuditLog(t, h.db, "hanzo", "audit-mine-hanzo")
	seedAuditLog(t, h.db, "orgb", "audit-secret-orgb")
	seedCert(t, h.db, "orgb", "cert-secret-orgb", "")
	seedToken(t, h.db, "hanzo", "token-mine-hanzo")
	seedToken(t, h.db, "orgb", "token-secret-orgb")
	seedWebauthn(t, h.db, "hanzo", "wa-mine-hanzo")
	seedWebauthn(t, h.db, "orgb", "wa-secret-orgb")

	boss := h.token(t, "hanzo/boss") // org admin of hanzo, and of nothing else

	for _, c := range []struct {
		route   string
		mine    string
		foreign string
	}{
		{"/v1/iam/roles?owner=hanzo", "role-mine-hanzo", "role-secret-orgb"},
		{"/v1/iam/invitations?owner=hanzo", "invite-mine-hanzo", "invite-secret-orgb"},
		{"/v1/iam/audit-logs?owner=hanzo", "audit-mine-hanzo", "audit-secret-orgb"},
		{"/v1/iam/tokens?owner=hanzo", "token-mine-hanzo", "token-secret-orgb"},
		{"/v1/iam/webauthn-credentials?owner=hanzo", "wa-mine-hanzo", "wa-secret-orgb"},
		// organizations is the tenant registry — authz treats it as the ONE
		// exception to the reserved-owner gate, and the route is SuperAdmin-only,
		// so this case should refuse rather than list. Included so a future change
		// that opens it to tenants shows up here rather than silently.
		{"/v1/iam/organizations?owner=hanzo", "", "orgb"},
		{"/v1/iam/certs?owner=hanzo", "", "cert-secret-orgb"}, // control: already scoped
	} {
		t.Run(c.route, func(t *testing.T) {
			status, body := h.doBody(t, "GET", c.route, boss, nil)
			if status != 200 {
				t.Skipf("route answered %d, not a listing to check here", status)
			}
			if strings.Contains(body, c.foreign) {
				t.Errorf("LEAK: hanzo/boss listing its OWN org received orgb's %q.\n"+
					"The guard refuses ?owner=orgb, so the only way this row crosses the wire is a "+
					"handler that ignored the principal and listed every tenant.\nbody: %s",
					c.foreign, body)
			}
			if c.mine != "" && !strings.Contains(body, c.mine) {
				t.Errorf("scoping is too tight: hanzo/boss cannot see its OWN row %q.\nbody: %s", c.mine, body)
			}
		})
	}
}

// A foreign org must still be refused outright — the fix must not have moved the
// refusal from the guard into a silently-empty listing.
func TestListRoutesStillRefuseAForeignOrg(t *testing.T) {
	h := newHarness(t)
	boss := h.token(t, "hanzo/boss")

	for _, route := range []string{
		"/v1/iam/roles?owner=orgb",
		"/v1/iam/invitations?owner=orgb",
		"/v1/iam/audit-logs?owner=orgb",
		"/v1/iam/certs?owner=orgb",
	} {
		status, body := h.doBody(t, "GET", route, boss, nil)
		if status == 200 {
			t.Errorf("%s returned 200 for a foreign org; want a refusal.\nbody: %s", route, body)
		}
	}
}
