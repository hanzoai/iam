// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package authz

import (
	"context"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
)

// A HANDLER-AUTHORIZED READ STILL NEEDS A CALLER.
//
// pathAuthorized reads (SCIM, memberships, the project/workspace switcher lists)
// carry their target in the path and let the HANDLER authorize the row, so the
// op-invoke seam skips the target check. Skipping the target is not skipping the
// caller: reaching this seam with no principal means a door let an unauthenticated
// request through, and a discovery handler that discards ctx then runs for nobody.
// The principal is required BEFORE the early return, not after.
func TestAuthorize_HandlerAuthorizedReadStillRequiresAPrincipal(t *testing.T) {
	// A SCIM read — a handler-authorized subtree.
	op := zip.Op{Method: "GET", Path: "/v1/iam/scim/v2/Users"}
	in := &struct{ Owner, Name string }{}

	if !pathAuthorized(op.Path) {
		t.Fatalf("%s is not handler-authorized — the test no longer exercises the early return", op.Path)
	}
	if err := Authorize(context.Background(), op, in); err == nil {
		t.Fatal("a handler-authorized read was admitted with no principal attached")
	}
	// With a principal, the early return admits it — the handler authorizes the row.
	p := &principal.Principal{Org: "acme", User: "alice"}
	if err := Authorize(principal.Bind(context.Background(), p), op, in); err != nil {
		t.Fatalf("a handler-authorized read refused a present principal: %v", err)
	}
}

// GATING A DOOR DOES NOT LET A CAPABILITY APP BIND A FOREIGN ROW.
//
// Once authz.Control gates the graph, MCP and call-plane doors, an authenticated
// capability app reaches the op-invoke seam with the target decoded from the body
// — the one place a by-name transport carries it, since no URL binds it. The
// entity pin is what keeps that from authorizing another tenant's row: a NAMED read
// is admitted only for the tenant the app serves. An empty target names no row, so
// it can never be a foreign one — it reaches the collection, whose tenant the list
// handler pins from the same served org (principal.Scope), never this seam.
func TestAuthorize_CapAppCannotBindAForeignRowOverADoor(t *testing.T) {
	t.Setenv(policy.CapKeyMint.Env, "hanzo-console")
	// The credential administrator: admin-owned (the pin), serving "hanzo".
	console := &principal.Principal{App: &policy.App{Name: "hanzo-console", Owner: "admin"}, Org: "hanzo"}
	ctx := principal.Bind(context.Background(), console)
	type ref struct{ Owner, Name string }
	item := zip.Op{Method: "GET", Path: "/v1/iam/keys/:owner/:name"}
	list := zip.Op{Method: "GET", Path: "/v1/iam/keys"}

	// The empty target the coupling warns of: a body that binds nothing decodes to
	// ("",""). It names no row.
	if o, n := decodedTarget(&ref{}); o != "" || n != "" {
		t.Fatalf("an empty body decoded to a bound target %q/%q", o, n)
	}

	// The exploit shape a call plane makes reachable: a NAMED foreign row in the body.
	// The pin refuses it, so gating the door binds no other tenant's row.
	if Authorize(ctx, item, &ref{Owner: "lux", Name: "x"}) == nil {
		t.Fatal("the console bound a NAMED foreign key row over the op seam")
	}
	// Its own served tenant's named row it may bind.
	if err := Authorize(ctx, item, &ref{Owner: "hanzo", Name: "x"}); err != nil {
		t.Fatalf("the console cannot bind a named row of the tenant it serves: %v", err)
	}
	// The collection is admitted here and pinned in the handler; gating the door does
	// not turn an empty target into a foreign LIST either — principal.Scope refuses a
	// foreign owner there, and defaults an empty one to the served org.
	if err := Authorize(ctx, list, &ref{}); err != nil {
		t.Fatalf("the console was refused a collection the list handler pins: %v", err)
	}
}
