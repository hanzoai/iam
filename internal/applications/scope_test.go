// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package applications

// A listing is scoped by the CALLER, never by the input.
//
// The op's Authorize hook re-checks the decoded target, so a foreign owner is
// already refused before this handler runs — but that is a second gate, not this
// one's. The handler filters on the owner principal.Scope returns, so the rows it
// reads are the caller's own whatever the input asked for, and it stands alone if
// it is ever called from anywhere but a guarded route.

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

func asTenant(org string) context.Context {
	return principal.Bind(context.Background(), &policy.Principal{Org: org, User: "someone"})
}

func seed(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	if _, err := Create(db)(context.Background(),
		&schema.Application{Owner: owner, Name: name, ClientId: owner + "-" + name}); err != nil {
		t.Fatalf("seed %s/%s: %v", owner, name, err)
	}
}

// A tenant asking for another tenant's applications is refused by this handler,
// not merely by the gate above it. An application row carries the client
// credential the tenant authenticates with, so its listing is a credential index.
func TestList_refusesAForeignOwner(t *testing.T) {
	db := memDB(t)
	seed(t, db, "victim", "console")

	if _, err := listApplications(db)(asTenant("attacker"), &ApplicationQuery{Owner: "victim"}); err == nil {
		t.Fatal("a tenant listed another tenant's applications")
	}
}

// With no principal at all there is no scope to read, so the listing is refused
// rather than answered.
func TestList_refusesWithoutPrincipal(t *testing.T) {
	db := memDB(t)
	seed(t, db, "hanzo", "console")

	if _, err := listApplications(db)(context.Background(), &ApplicationQuery{Owner: "hanzo"}); err == nil {
		t.Fatal("a listing with no principal was answered")
	}
}

// The rows a caller gets are its own: the owner the handler filters on is the one
// Scope returned.
func TestList_filtersOnTheScopedOwner(t *testing.T) {
	db := memDB(t)
	seed(t, db, "hanzo", "console")
	seed(t, db, "victim", "console")

	out, err := listApplications(db)(asTenant("hanzo"), &ApplicationQuery{Owner: "hanzo"})
	if err != nil {
		t.Fatalf("list own org: %v", err)
	}
	for _, a := range out.Applications {
		if a.Owner != "hanzo" {
			t.Errorf("listing leaked %s/%s", a.Owner, a.Name)
		}
	}
	if len(out.Applications) != 1 {
		t.Errorf("got %d applications, want 1", len(out.Applications))
	}
}
