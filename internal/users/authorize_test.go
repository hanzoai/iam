// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package users

import (
	"context"
	"errors"
	"net/http"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
)

// An account in the admin org is written only by a SuperAdmin. An org admin, an
// org admin holding an admin-org membership, and an application are all refused
// it — including a name nobody holds yet — while every other account is left to
// the ordinary gates.
func TestAuthorizeKeepsTheAdminOrgToSuperAdmins(t *testing.T) {
	as := func(p *principal.Principal) context.Context { return principal.Bind(context.Background(), p) }
	boss := as(&principal.Principal{Org: "hanzo", User: "boss", Admin: true})
	member := as(&principal.Principal{Org: "hanzo", User: "z", Admin: true, Orgs: map[string]policy.Role{policy.AdminOrg: policy.Admin}})
	app := as(&principal.Principal{Org: "hanzo", App: &policy.App{Name: "hanzo-visor", Owner: policy.AdminOrg}})
	super := as(&principal.Principal{Org: policy.AdminOrg, User: "z", Sudo: true})

	for name, ctx := range map[string]context.Context{"org admin": boss, "admin-org member": member, "application": app} {
		err := Authorize(ctx, policy.AdminOrg)
		var he *zip.HTTPError
		if !errors.As(err, &he) || he.Status != http.StatusForbidden {
			t.Errorf("%s writing an admin-org account: %v, want 403", name, err)
		}
		if err := Authorize(ctx, "hanzo"); err != nil {
			t.Errorf("%s writing a hanzo account: %v, want the ordinary gates to decide", name, err)
		}
	}
	if err := Authorize(super, policy.AdminOrg); err != nil {
		t.Errorf("a SuperAdmin writing an admin-org account: %v", err)
	}
	if err := Authorize(context.Background(), "Admin"); err != nil {
		t.Errorf("a look-alike org read as the admin org: %v", err)
	}
}
