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

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
)

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
