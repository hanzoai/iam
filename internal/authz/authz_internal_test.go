// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz

import "testing"

// The pure policy, tested exhaustively and independent of HTTP. authorize IS the
// security decision; this table is its full truth.
func TestAuthorizePolicy(t *testing.T) {
	super := &Principal{Org: "admin", User: "root", Super: true}
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
	if (&Principal{Org: "built-in", Super: false}).Super {
		t.Fatal("built-in must not be SuperAdmin")
	}
	// A built-in-org principal fails the reserved-owner write even for its own org.
	if authorize(&Principal{Org: "built-in", Admin: true}, "POST", "certs", "built-in", "k") {
		t.Fatal("built-in admin must not write built-in signing certs")
	}
}

// Public vs gated is no longer a path allow-list this package owns — it is
// STRUCTURAL, decided by which group a route is registered on in routes.Route
// (the public group before the Guard, everything else after it). The boundary is
// therefore proven end-to-end over the real registered router: TestPublicRoutesNeedNoBearer
// (public routes reachable without a bearer), TestUnauthenticatedWriteIs401 /
// TestCrossOrgWriteIs403 (authed routes gated), and TestFrameworkSideDoorsAreGated
// (/mcp + /openapi gated) in authz_cases_test.go.

func TestEntityOf(t *testing.T) {
	cases := map[string]string{
		// Collection and member resolve to the SAME entity — the policy is written
		// per entity, so the member URL that replaced the POST sub-verbs must not
		// change which clause governs it.
		"/v1/iam/users":                 "users",
		"/v1/iam/users/hanzo/alice":     "users",
		"/v1/iam/certs":                 "certs",
		"/v1/iam/certs/admin/cert-sign": "certs",
		"/v1/iam/applications":          "applications",
		"/v1/iam/applications/admin/x":  "applications",
		"/v1/iam/audit-logs":            "audit-logs",
		// The Casdoor verb spellings fold onto the same entity noun.
		"/v1/iam/get-user":         "users",
		"/v1/iam/add-organization": "organizations",
		"/mcp":                     "",
		"/healthz":                 "",
		"/v1/iam/":                 "",
	}
	for path, want := range cases {
		if got := entityOf(path); got != want {
			t.Errorf("entityOf(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestMemberTarget pins the ONE rule the Guard uses to find a member route's
// authorization target: EXACTLY two segments after the entity. One segment short is
// a collection, one long is a sub-resource, and neither may be mistaken for an
// (owner, name) — a false positive here would hand the authorizer a target the
// handler never acts on.
func TestMemberTarget(t *testing.T) {
	cases := []struct {
		path        string
		owner, name string
		ok          bool
	}{
		{"/v1/iam/users/hanzo/alice", "hanzo", "alice", true},
		{"/v1/iam/certs/admin/cert-sign", "admin", "cert-sign", true},
		// A collection: no target in the path.
		{"/v1/iam/users", "", "", false},
		// One segment too few and one too many.
		{"/v1/iam/users/hanzo", "", "", false},
		{"/v1/iam/service-accounts/bot/keys/extra", "", "", false},
		// Empty segments never form a target.
		{"/v1/iam/users//alice", "", "", false},
		{"/v1/iam/users/hanzo/", "", "", false},
		// Outside the subsystem prefix entirely.
		{"/v1/ai/users/hanzo/alice", "", "", false},
		{"/healthz", "", "", false},
	}
	for _, c := range cases {
		o, n, ok := memberTarget(c.path)
		if o != c.owner || n != c.name || ok != c.ok {
			t.Errorf("memberTarget(%q) = (%q,%q,%v), want (%q,%q,%v)",
				c.path, o, n, ok, c.owner, c.name, c.ok)
		}
	}
}
