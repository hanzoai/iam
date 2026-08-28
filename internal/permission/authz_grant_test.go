// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package permission

// A permission NAMES the people, groups and roles it is evaluated for. None of
// them is the grant's own (Owner, Name), so the op-invoke seam that authorizes
// the row does not authorize what the row points at — the write has to authorize
// the subjects itself. These drive the handlers directly with a bound principal,
// the way the sibling entity surfaces test their own field gates.

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// asAdmin is an admin of org — it may name subjects in its own organization, and
// in no other, and never in a reserved one.
func asAdmin(org string) context.Context {
	return principal.Bind(context.Background(), &policy.Principal{Org: org, User: "boss", Admin: true})
}

// asSuper is the only cross-tenant scope.
func asSuper() context.Context {
	return principal.Bind(context.Background(), &policy.Principal{Org: "admin", User: "root", Sudo: true})
}

// A grant naming a reserved-org subject is refused, and nothing lands.
func TestAdd_refusesAReservedSubject(t *testing.T) {
	h, db := newHandlers(t)
	for _, tc := range []struct {
		name string
		in   *schema.Permission
	}{
		{"users", &schema.Permission{Owner: "hanzo", Name: "forge", Users: []string{"admin/root"}}},
		{"roles", &schema.Permission{Owner: "hanzo", Name: "forge", Roles: []string{"admin/operators"}}},
		{"groups", &schema.Permission{Owner: "hanzo", Name: "forge", Groups: []string{"admin/staff"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.Add(asAdmin("hanzo"), tc.in)
			if err == nil {
				t.Fatal("a grant naming a reserved-org subject must be refused")
			}
			wantStatus(t, err, 403)
			if _, gerr := orm.Get[schema.Permission](db, "hanzo/forge"); gerr == nil {
				t.Fatal("a refused grant persisted a row")
			}
		})
	}
}

// A grant naming ANOTHER tenant's subject is refused the same way.
func TestAdd_refusesAForeignSubject(t *testing.T) {
	h, _ := newHandlers(t)
	_, err := h.Add(asAdmin("hanzo"), &schema.Permission{
		Owner: "hanzo", Name: "reach", Users: []string{"victim/ceo"},
	})
	if err == nil {
		t.Fatal("a grant naming another tenant's subject must be refused")
	}
	wantStatus(t, err, 403)
}

// An update cannot widen a stored grant onto a reserved subject either — adding
// someone to an existing grant is the same authority as making one.
func TestUpdate_refusesAReservedSubject(t *testing.T) {
	h, _ := newHandlers(t)
	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "editor", Users: []string{"hanzo/alice"}})

	_, err := h.Update(asAdmin("hanzo"), &schema.Permission{
		Owner: "hanzo", Name: "editor", Users: []string{"hanzo/alice", "admin/root"},
	})
	if err == nil {
		t.Fatal("widening a grant onto a reserved-org subject must be refused")
	}
	wantStatus(t, err, 403)

	stored, gerr := orm.Get[schema.Permission](h.db, "hanzo/editor")
	if gerr != nil {
		t.Fatalf("load stored: %v", gerr)
	}
	if len(stored.Users) != 1 || stored.Users[0] != "hanzo/alice" {
		t.Fatalf("a refused update changed the stored subjects: %v", stored.Users)
	}
}

// The legitimate grant still passes: an org's own admin grants to its own people,
// by their qualified name or by a bare one read in the grant's own organization.
func TestAdd_allowsAnOwnOrgGrant(t *testing.T) {
	h, _ := newHandlers(t)
	out, err := h.Add(asAdmin("hanzo"), &schema.Permission{
		Owner: "hanzo", Name: "editor", Effect: "allow",
		Users: []string{"hanzo/alice", "bob"}, Groups: []string{"hanzo/eng"},
		Roles: []string{"hanzo/engineers"}, Domains: []string{"hanzo.ai"},
		Actions: []string{"read", "write"},
	})
	if err != nil {
		t.Fatalf("an own-org grant must be allowed: %v", err)
	}
	if len(out.Users) != 2 || out.Users[1] != "bob" {
		t.Fatalf("the stored subjects lost a name: %v", out.Users)
	}
	if _, err := h.Update(asAdmin("hanzo"), &schema.Permission{
		Owner: "hanzo", Name: "editor", Users: []string{"hanzo/carol"},
	}); err != nil {
		t.Fatalf("an own-org update must be allowed: %v", err)
	}
}

// A SuperAdmin is the one scope that reaches across organizations, so it may file
// a platform grant.
func TestAdd_allowsASuperAdminAnySubject(t *testing.T) {
	h, _ := newHandlers(t)
	if _, err := h.Add(asSuper(), &schema.Permission{
		Owner: "admin", Name: "platform", Users: []string{"admin/root", "hanzo/alice"},
	}); err != nil {
		t.Fatalf("a SuperAdmin must be able to file a platform grant: %v", err)
	}
}

// With no principal there is nobody to authorize the subjects for, so the write is
// refused rather than admitted as a trusted internal caller: the guarded route is
// this surface's only caller, and it always carries one.
func TestAdd_refusesWithNoPrincipal(t *testing.T) {
	h, _ := newHandlers(t)
	_, err := h.Add(context.Background(), &schema.Permission{
		Owner: "hanzo", Name: "forge", Users: []string{"admin/root"},
	})
	if err == nil {
		t.Fatal("an unauthenticated grant must be refused")
	}
	wantStatus(t, err, 403)
}
