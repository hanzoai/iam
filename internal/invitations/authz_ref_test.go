// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package invitations

// An invitation NAMES what whoever redeems it arrives with: the application they
// arrive through, and the group they arrive holding. Neither is the invitation's
// own (Owner, Name), so the seam that authorizes the row authorized where the
// invitation is filed and not what it hands out.

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

func asAdmin(org string) context.Context {
	return principal.Bind(context.Background(), &policy.Principal{Org: org, User: "boss", Admin: true})
}

func asSuper() context.Context {
	return principal.Bind(context.Background(), &policy.Principal{Org: "admin", User: "root", Sudo: true})
}

// An invitation naming a platform application, or a platform group, is refused —
// and nothing lands.
func TestCreate_refusesAReservedReferent(t *testing.T) {
	h, db := newHandler(t)
	for _, tc := range []struct {
		name string
		in   *Input
	}{
		{"application", &Input{Owner: "hanzo", Name: "forge", Application: "admin/hanzo-console"}},
		{"signupGroup", &Input{Owner: "hanzo", Name: "forge", SignupGroup: "admin/operators"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := h.Create(asAdmin("hanzo"), tc.in)
			if err == nil {
				t.Fatal("an invitation naming a platform referent must be refused")
			}
			wantStatus(t, err, 403)
			if _, gerr := orm.Get[schema.Invitation](db, "hanzo/forge"); gerr == nil {
				t.Fatal("a refused invitation persisted a row")
			}
		})
	}
}

// Naming ANOTHER tenant's application is refused the same way.
func TestCreate_refusesAForeignReferent(t *testing.T) {
	h, _ := newHandler(t)
	_, err := h.Create(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "reach", Application: "victim/console",
	})
	if err == nil {
		t.Fatal("an invitation naming another tenant's application must be refused")
	}
	wantStatus(t, err, 403)
}

// An update cannot re-point a stored invitation at a platform application either.
func TestUpdate_refusesAReservedReferent(t *testing.T) {
	h, db := newHandler(t)
	if _, err := h.Create(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "join", Application: "console",
	}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, err := h.Update(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "join", Application: "admin/hanzo-console",
	})
	if err == nil {
		t.Fatal("re-pointing an invitation at a platform application must be refused")
	}
	wantStatus(t, err, 403)

	stored, gerr := orm.Get[schema.Invitation](db, "hanzo/join")
	if gerr != nil {
		t.Fatalf("load stored: %v", gerr)
	}
	if stored.Application != "console" {
		t.Fatalf("a refused update changed the stored application to %q", stored.Application)
	}
}

// The ordinary invitation still passes: an organization invites people through its
// own application and into its own group, named plainly or in full, and an
// invitation that names neither is untouched.
func TestCreate_allowsAnOwnOrgInvitation(t *testing.T) {
	h, _ := newHandler(t)
	if _, err := h.Create(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "plain", Application: "console", SignupGroup: "engineers",
		Email: "new@hanzo.ai", Quota: 5,
	}); err != nil {
		t.Fatalf("a plainly-named own-org invitation must be allowed: %v", err)
	}
	if _, err := h.Create(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "full", Application: "hanzo/console", SignupGroup: "hanzo/engineers",
	}); err != nil {
		t.Fatalf("a fully-named own-org invitation must be allowed: %v", err)
	}
	if _, err := h.Create(asAdmin("hanzo"), &Input{
		Owner: "hanzo", Name: "bare", Email: "someone@hanzo.ai",
	}); err != nil {
		t.Fatalf("an invitation naming neither must be allowed: %v", err)
	}
}

// A SuperAdmin is the one scope that reaches across organizations, so the platform
// can still issue an invitation through its own console.
func TestCreate_allowsASuperAdminAnyReferent(t *testing.T) {
	h, _ := newHandler(t)
	if _, err := h.Create(asSuper(), &Input{
		Owner: "hanzo", Name: "platform", Application: "admin/hanzo-console",
	}); err != nil {
		t.Fatalf("a SuperAdmin must be able to invite through the platform console: %v", err)
	}
}
