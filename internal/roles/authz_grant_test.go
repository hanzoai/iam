// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package roles

// A role NAMES the people, groups and roles it bundles. None of them is the role's
// own (Owner, Name), so the op-invoke seam that authorizes the row does not
// authorize what the row points at — the write has to authorize the members
// itself. These drive the handlers directly with a bound principal.

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// asAdmin is an admin of org — it may name members in its own organization, and in
// no other, and never in a reserved one.
func asAdmin(org string) context.Context {
	return principal.Bind(context.Background(), &policy.Principal{Org: org, User: "boss", Admin: true})
}

// asSuper is the only cross-tenant scope.
func asSuper() context.Context {
	return principal.Bind(context.Background(), &policy.Principal{Org: "admin", User: "root", Sudo: true})
}

// A role bundling a reserved-org member is refused, and nothing lands.
func TestCreate_refusesAReservedMember(t *testing.T) {
	db := store(t)
	h := &Handler{db: db}
	for _, tc := range []struct {
		name string
		in   *Input
	}{
		{"users", &Input{Owner: "hanzo", Name: "forge", Users: []string{"admin/root"}}},
		{"roles", &Input{Owner: "hanzo", Name: "forge", Roles: []string{"admin/operators"}}},
		{"teams", &Input{Owner: "hanzo", Name: "forge", Teams: []string{"admin/staff"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.Create(asAdmin("hanzo"), tc.in)
			if err == nil {
				t.Fatal("a role bundling a reserved-org member must be refused")
			}
			wantStatus(t, err, 403)
			if _, gerr := orm.Get[schema.Role](db, "hanzo/forge"); gerr == nil {
				t.Fatal("a refused role persisted a row")
			}
		})
	}
}

// A role bundling ANOTHER tenant's member is refused the same way.
func TestCreate_refusesAForeignMember(t *testing.T) {
	h := &Handler{db: store(t)}
	_, err := h.Create(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "reach", Users: []string{"victim/ceo"},
	})
	if err == nil {
		t.Fatal("a role bundling another tenant's member must be refused")
	}
	wantStatus(t, err, 403)
}

// An update cannot widen a stored role onto a reserved member either.
func TestUpdate_refusesAReservedMember(t *testing.T) {
	db := store(t)
	h := &Handler{db: db}
	if _, err := h.Create(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "engineers", Users: []string{"hanzo/alice"},
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := h.Update(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "engineers", Users: []string{"hanzo/alice", "admin/root"},
	})
	if err == nil {
		t.Fatal("widening a role onto a reserved-org member must be refused")
	}
	wantStatus(t, err, 403)

	stored, gerr := orm.Get[schema.Role](db, "hanzo/engineers")
	if gerr != nil {
		t.Fatalf("load stored: %v", gerr)
	}
	if len(stored.Users) != 1 || stored.Users[0] != "hanzo/alice" {
		t.Fatalf("a refused update changed the stored members: %v", stored.Users)
	}
}

// The legitimate role still passes: an org's own admin bundles its own people, by
// their qualified name or by a bare one read in the role's own organization.
func TestCreate_allowsAnOwnOrgRole(t *testing.T) {
	h := &Handler{db: store(t)}
	out, err := h.Create(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "admins",
		Users: []string{"hanzo/alice", "bob"}, Teams: []string{"hanzo/eng"},
		Roles: []string{"hanzo/engineers"}, Domains: []string{"hanzo.ai"}, IsEnabled: true,
	})
	if err != nil {
		t.Fatalf("an own-org role must be allowed: %v", err)
	}
	if len(out.Users) != 2 || out.Users[1] != "bob" {
		t.Fatalf("the stored members lost a name: %v", out.Users)
	}
	if _, err := h.Update(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "admins", Users: []string{"hanzo/carol"},
	}); err != nil {
		t.Fatalf("an own-org update must be allowed: %v", err)
	}
}

// A SuperAdmin is the one scope that reaches across organizations.
func TestCreate_allowsASuperAdminAnyMember(t *testing.T) {
	h := &Handler{db: store(t)}
	if _, err := h.Create(asSuper(), &Input{
		Owner: "admin", Name: "operators", Users: []string{"admin/root", "hanzo/alice"},
	}); err != nil {
		t.Fatalf("a SuperAdmin must be able to file a platform role: %v", err)
	}
}

// With no principal there is nobody to authorize the members for, so the write is
// refused rather than admitted as a trusted internal caller.
func TestCreate_refusesWithNoPrincipal(t *testing.T) {
	h := &Handler{db: store(t)}
	_, err := h.Create(context.Background(), &Input{
		Owner: "hanzo", Name: "forge", Users: []string{"admin/root"},
	})
	if err == nil {
		t.Fatal("an unauthenticated role must be refused")
	}
	wantStatus(t, err, 403)
}
