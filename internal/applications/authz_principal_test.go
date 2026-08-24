// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications

// The two fields an application carries beyond its own key — the organization it
// SERVES and the cert it SIGNS with — are refused to a caller there is no
// principal for. These handlers are reached from the router and nowhere else (the
// boot paths write their rows through the store), so a call arriving without one is
// a door left open, and admitting it would make both gates vanish exactly where
// they are needed.

import (
	"context"
	"errors"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// hanzoAdmin is an org admin of hanzo — it may link its own organization's
// providers and the platform's, and no other tenant's. (asSuper lives beside it in
// secret_preserve_test.go.)
func hanzoAdmin() context.Context {
	return principal.Bind(context.Background(), &policy.Principal{Org: "hanzo", User: "boss", Admin: true})
}

func statusOf(t *testing.T, err error) int {
	t.Helper()
	var he *zip.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("error %v is not a *zip.HTTPError", err)
	}
	return he.Status
}

func TestWrite_refusesAnOrganizationWithNoPrincipal(t *testing.T) {
	db := memDB(t)
	_, err := Create(db)(context.Background(), &schema.Application{
		Owner: "hanzo", Name: "app", ClientId: "app", Organization: "admin",
	})
	if err == nil {
		t.Fatal("an unauthenticated write must not point an application at an organization")
	}
	if got := statusOf(t, err); got != 403 {
		t.Fatalf("status=%d, want 403", got)
	}
	if _, gerr := orm.Get[schema.Application](db, "hanzo/app"); gerr == nil {
		t.Fatal("a refused write persisted a row")
	}
}

// An application naming no organization mints no cross-tenant identity, so it is
// not what this gate is about and is left to the row's own key.
func TestWrite_allowsAnOrglessApplication(t *testing.T) {
	db := memDB(t)
	if _, err := Create(db)(context.Background(), &schema.Application{
		Owner: "hanzo", Name: "orgless", ClientId: "orgless",
	}); err != nil {
		t.Fatalf("an org-less application must be allowed: %v", err)
	}
}

// An application LINKS identity providers, and the sign-in leg runs on the linked
// record's own client id and secret. The platform's connectors are shared — that is
// what "sign in with Google" is, and a link naming no owner resolves there — so any
// application may name one. Another TENANT's provider is that tenant's credentials,
// and no application may name it.
func TestWrite_refusesAForeignTenantProviderLink(t *testing.T) {
	db := memDB(t)
	_, err := Create(db)(hanzoAdmin(), &schema.Application{
		Owner: "hanzo", Name: "app", ClientId: "app", Organization: "hanzo",
		Providers: []*schema.ProviderItem{{Owner: "victim", Name: "okta", CanSignIn: true}},
	})
	if err == nil {
		t.Fatal("linking another tenant's identity provider must be refused")
	}
	if got := statusOf(t, err); got != 403 {
		t.Fatalf("status=%d, want 403", got)
	}
	if _, gerr := orm.Get[schema.Application](db, "hanzo/app"); gerr == nil {
		t.Fatal("a refused write persisted a row")
	}
}

// The links an application legitimately carries still land: the platform's shared
// connector, named in full or named by nothing at all, and the application's own.
func TestWrite_allowsSharedAndOwnProviderLinks(t *testing.T) {
	db := memDB(t)
	if _, err := Create(db)(hanzoAdmin(), &schema.Application{
		Owner: "hanzo", Name: "app", ClientId: "app", Organization: "hanzo",
		Providers: []*schema.ProviderItem{
			{Name: "provider_google", CanSignIn: true},                 // resolves to the platform's
			{Owner: "admin", Name: "provider_github", CanSignIn: true}, // the same, named in full
			{Owner: "hanzo", Name: "our-okta", CanSignIn: true},        // its own organization's
		},
	}); err != nil {
		t.Fatalf("the ordinary links must be allowed: %v", err)
	}
}

// A SuperAdmin is the one scope that reaches across organizations.
func TestWrite_allowsASuperAdminAnyProviderLink(t *testing.T) {
	db := memDB(t)
	if _, err := Create(db)(asSuper(), &schema.Application{
		Owner: "admin", Name: "console", ClientId: "console", Organization: "hanzo",
		Providers: []*schema.ProviderItem{{Owner: "hanzo", Name: "our-okta", CanSignIn: true}},
	}); err != nil {
		t.Fatalf("a SuperAdmin must be able to link any provider: %v", err)
	}
}
