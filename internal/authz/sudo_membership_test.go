// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package authz_test

// Platform authority is a PERSON whose own org is the reserved one, and these
// drive it through the real router so the claim is about what a request gets, not
// about a struct. A membership of the reserved org held from a brand org is not
// it, and neither is a machine that lives there.

import (
	"context"
	"strings"
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/testdb"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// grant puts user IN org with role, the way an existing SuperAdmin does.
func grant(t *testing.T, h *harness, user, org, role string) {
	t.Helper()
	if err := testdb.Member(context.Background(), h.db, user, org, role); err != nil {
		t.Fatalf("grant %s in %s: %v", user, org, err)
	}
}

// listsEveryTenant reports whether sub reaches the cross-tenant certs listing —
// the SuperAdmin-only surface, since Scope binds everyone else to their own org.
func listsEveryTenant(t *testing.T, h *harness, sub string) bool {
	t.Helper()
	status, body := h.doBody(t, "GET", "/v1/iam/certs", h.token(t, sub), nil)
	return status == 200 && strings.Contains(body, signingKid)
}

// A brand org's person holding a membership in the reserved org is an ordinary
// person of that brand org: the membership opens nothing.
func TestAnAdminMembershipIsNotSudo(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "op", true, false, false)
	grant(t, h, "hanzo/op", policy.AdminOrg, store.RoleAdmin)

	if listsEveryTenant(t, h, "hanzo/op") {
		t.Fatal("a brand org's person holding an admin-org membership reached every tenant")
	}
}

// The reserved org's own people hold it, whether or not they administer it.
func TestAPersonInTheReservedOrgIsSudo(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, policy.AdminOrg, "ops", false, false, false)
	for _, sub := range []string{"admin/root", "admin/ops"} {
		if !listsEveryTenant(t, h, sub) {
			t.Fatalf("%s, a person in the reserved org, lost platform scope", sub)
		}
	}
}

// A machine that lives in the reserved org is never an operator.
func TestAMachineInTheReservedOrgIsNotSudo(t *testing.T) {
	h := newHarness(t)
	for _, typ := range []string{schema.ServiceAccount, schema.Program} {
		name := "svc-" + typ
		seedUser(t, h.db, policy.AdminOrg, name, true, false, false)
		u, err := store.GetUserByName(context.Background(), h.db, policy.AdminOrg, name)
		if err != nil || u == nil {
			t.Fatalf("read %s: %v", name, err)
		}
		u.Type = typ
		if err := u.UpdateCtx(context.Background()); err != nil {
			t.Fatal(err)
		}
		if listsEveryTenant(t, h, "admin/"+name) {
			t.Fatalf("a %s in the reserved org reached every tenant", typ)
		}
	}
}

// ONE reserved org confers it, not the reserved SET. built-in owns signing certs
// and app owns service principals — both are platform trust material and neither
// is the operator scope, so widening the predicate to IsReservedOrg would hand
// platform sudo to every identity filed under a system org.
func TestOnlyTheReservedAdminOrgConfersIt(t *testing.T) {
	h := newHarness(t)
	if listsEveryTenant(t, h, "built-in/svc") {
		t.Fatal("a built-in-org account reached every tenant — the reserved SET is not the operator scope")
	}

	seedUser(t, h.db, "hanzo", "sideways", false, false, false)
	grant(t, h, "hanzo/sideways", "built-in", store.RoleAdmin)
	if listsEveryTenant(t, h, "hanzo/sideways") {
		t.Fatal("a membership in built-in conferred platform scope")
	}

	seedUser(t, h.db, "hanzo", "neighbour", false, false, false)
	grant(t, h, "hanzo/neighbour", "orgb", store.RoleAdmin)
	if listsEveryTenant(t, h, "hanzo/neighbour") {
		t.Fatal("a membership in another tenant conferred platform scope")
	}
}
