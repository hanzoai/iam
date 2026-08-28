// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package permission

// A listing is scoped by the CALLER, never by the input.
//
// The op's Authorize hook re-checks the decoded target, so a foreign owner is
// already refused before a handler runs — but that is a second gate, not this
// one's. The handler filters on the owner principal.Scope returns, so the rows it
// reads are the caller's own whatever the input asked for, and it stands alone if
// it is ever called from anywhere but a guarded route.

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

func asTenant(org string) context.Context {
	return principal.Bind(context.Background(), &policy.Principal{Org: org, User: "someone"})
}

// A tenant asking for another tenant's permissions is refused by this handler,
// not merely by the gate above it.
func TestList_refusesAForeignOwner(t *testing.T) {
	h, _ := newHandlers(t)
	mustAdd(t, h, &schema.Permission{Owner: "victim", Name: "secret-grant"})

	if _, err := h.List(asTenant("attacker"), &ListRequest{Owner: "victim"}); err == nil {
		t.Fatal("a tenant listed another tenant's permissions")
	}
}

// With no principal at all there is no scope to read, so the listing is refused
// rather than answered with every tenant's rows.
func TestList_refusesWithoutPrincipal(t *testing.T) {
	h, _ := newHandlers(t)
	if _, err := h.List(context.Background(), &ListRequest{Owner: "hanzo"}); err == nil {
		t.Fatal("a listing with no principal was answered")
	}
}

// The rows a caller gets are its own. The owner the handler filters on is the one
// Scope returned, so a tenant reads its own permissions and sees no other's.
func TestList_filtersOnTheScopedOwner(t *testing.T) {
	h, _ := newHandlers(t)
	mustAdd(t, h, &schema.Permission{Owner: "hanzo", Name: "mine"})
	mustAdd(t, h, &schema.Permission{Owner: "victim", Name: "theirs"})

	out, err := h.List(asTenant("hanzo"), &ListRequest{Owner: "hanzo"})
	if err != nil {
		t.Fatalf("list own org: %v", err)
	}
	for _, p := range out.Permissions {
		if p.Owner != "hanzo" {
			t.Errorf("listing leaked %s/%s", p.Owner, p.Name)
		}
	}
	if len(out.Permissions) != 1 {
		t.Errorf("got %d permissions, want 1", len(out.Permissions))
	}
}
