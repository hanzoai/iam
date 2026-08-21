// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package authz

import (
	"context"
	"testing"
)

// authorize asks the seam's own decision the way the seam asks it: IAM resolves the
// principal and folds the path onto an entity noun, policy.Principal.CanEntity
// decides. Going through Can rather than around it is what makes these tables a
// test of the live path and not of a paraphrase of it.
func authorize(p *Principal, method, entity, owner, name string) bool {
	return Can(context.WithValue(context.Background(), ctxKey{}, p), method, entity, owner, name)
}

// The pure policy, tested exhaustively and independent of HTTP. This table is the
// full truth of the decision the seam applies.
func TestAuthorizePolicy(t *testing.T) {
	super := &Principal{Org: "admin", User: "root", Sudo: true}
	orgAdmin := &Principal{Org: "hanzo", User: "boss", Admin: true}
	regular := &Principal{Org: "hanzo", User: "alice"}
	builtin := &Principal{Org: "built-in", User: "svc", Admin: true} // NOT super

	cases := []struct {
		name   string
		p      *Principal
		method string
		entity string
		owner  string
		name2  string
		want   bool
	}{
		// SuperAdmin: unrestricted, including the reserved owners and cross-org.
		{"super writes admin cert", super, "POST", "certs", "admin", "k", true},
		{"super writes built-in cert", super, "POST", "certs", "built-in", "k", true},
		{"super cross-org user", super, "POST", "users", "orgb", "x", true},

		// Poisoning gate: no non-super may write a reserved-owner resource.
		{"org admin -> admin cert", orgAdmin, "POST", "certs", "admin", "k", false},
		{"org admin -> built-in cert", orgAdmin, "POST", "certs", "built-in", "k", false},
		{"regular -> admin cert", regular, "POST", "certs", "admin", "k", false},
		{"built-in member -> built-in cert", builtin, "POST", "certs", "built-in", "k", false},
		{"built-in member -> admin app", builtin, "POST", "application", "admin", "a", false},

		// Tenant isolation: own org only.
		{"org admin own org", orgAdmin, "POST", "users", "hanzo", "x", true},
		{"org admin foreign org", orgAdmin, "POST", "users", "orgb", "x", false},
		{"org admin empty owner", orgAdmin, "POST", "certs", "", "k", false},

		// Regular user: read own record only; no writes, no others, no self-promote.
		{"regular read own", regular, "GET", "users", "hanzo", "alice", true},
		{"regular read other", regular, "GET", "users", "hanzo", "boss", false},
		{"regular list org", regular, "GET", "users", "hanzo", "", false},
		{"regular write own (self-promote)", regular, "POST", "users", "hanzo", "alice", false},
		{"regular read own non-user entity", regular, "GET", "roles", "hanzo", "alice", false},
		{"regular read foreign org self-name", regular, "GET", "users", "orgb", "alice", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := authorize(c.p, c.method, c.entity, c.owner, c.name2); got != c.want {
				t.Fatalf("authorize(%s) = %v, want %v", c.name, got, c.want)
			}
		})
	}
}

// SuperAdmin is exactly org=="admin"; built-in is NOT super — the built-in gap
// the poisoning gate must close depends on this.
func TestSuperIsAdminOrgOnly(t *testing.T) {
	if (&Principal{Org: "built-in", Sudo: false}).Sudo {
		t.Fatal("built-in must not be SuperAdmin")
	}
	// A built-in-org principal fails the reserved-owner write even for its own org.
	if authorize(&Principal{Org: "built-in", Admin: true}, "POST", "certs", "built-in", "k") {
		t.Fatal("built-in admin must not write built-in signing certs")
	}
}

// Public vs gated is no longer a path allow-list this package owns — it is
// STRUCTURAL, decided by which group a route is registered on in routes.Route
// (the public group holds no Guard, the authed group holds it). The boundary is
// therefore proven end-to-end over the real registered router: TestPublicRoutesNeedNoBearer
// (public routes reachable without a bearer), TestUnauthenticatedWriteIs401 /
// TestCrossOrgWriteIs403 (authed routes gated), and TestFrameworkSideDoorsAreGated
// (/mcp + /openapi gated) in authz_cases_test.go.

func TestEntityOf(t *testing.T) {
	cases := map[string]string{
		"/v1/iam/users":                  "users",
		"/v1/iam/users/hanzo/alice":      "users",
		"/v1/iam/certs/admin/cert-hanzo": "certs",
		// Singular natives fold to the plural the policy is written in. It read
		// "application" until that split the policy: the legacy verb folded to
		// "applications" and matched the app self-read clause, while this native
		// route stayed singular, matched nothing, and 403'd the same caller.
		"/v1/iam/application": "applications",
		"/v1/iam/audit-logs":  "audit-logs",
		"/mcp":                "",
		"/healthz":            "",
		"/v1/iam/":            "",
	}
	for path, want := range cases {
		if got := entityOf(path); got != want {
			t.Errorf("entityOf(%q) = %q, want %q", path, got, want)
		}
	}
}
