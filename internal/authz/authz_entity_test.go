// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz

import "testing"

// entityOf is the resolver both authorization seams read the entity from, so a
// Casdoor verb alias and its REST twin are governed by ONE rule only if it maps
// them to ONE entity. These tests are that proof, in three parts: parity over
// every registered compat route, an EXHAUSTIVE bound on what may carry authority,
// and the live signup case driven through authorize() itself.

// twins pairs every compat verb route registered in internal/compat (plus the two
// compound reads) with the REST route it aliases. Both sides are real registered
// paths — compat from aliases.go/writes.go, REST from each entity package's Route.
var twins = []struct{ verb, rest string }{
	// organizations — the tenant registry (internal/organizations, orgBase).
	{"/v1/iam/get-organizations", "/v1/iam/organizations"},
	{"/v1/iam/get-organization", "/v1/iam/organizations/get"},
	{"/v1/iam/add-organization", "/v1/iam/organizations"},
	{"/v1/iam/update-organization", "/v1/iam/organizations/update"},
	{"/v1/iam/delete-organization", "/v1/iam/organizations/delete"},

	// users (internal/users).
	{"/v1/iam/get-users", "/v1/iam/users"},
	{"/v1/iam/get-global-users", "/v1/iam/users"}, // same owner-scoped lister as get-users
	{"/v1/iam/get-user", "/v1/iam/users/get"},
	{"/v1/iam/add-user", "/v1/iam/users"},
	{"/v1/iam/update-user", "/v1/iam/users/update"},
	{"/v1/iam/delete-user", "/v1/iam/users/delete"},

	// applications (internal/applications) — the REST surface spells the collection
	// plural and the item singular; both must reach one entity, or a capability could
	// later attach to half of it.
	{"/v1/iam/get-applications", "/v1/iam/applications"},
	{"/v1/iam/get-application", "/v1/iam/application"},
	{"/v1/iam/add-application", "/v1/iam/application"},
	{"/v1/iam/update-application", "/v1/iam/application"},
	{"/v1/iam/delete-application", "/v1/iam/application"},

	// providers (internal/providers).
	{"/v1/iam/get-providers", "/v1/iam/providers"},
	{"/v1/iam/get-provider", "/v1/iam/providers/get"},
	{"/v1/iam/add-provider", "/v1/iam/providers"},
	{"/v1/iam/update-provider", "/v1/iam/providers/update"},
	{"/v1/iam/delete-provider", "/v1/iam/providers/delete"},

	// roles (internal/roles).
	{"/v1/iam/get-roles", "/v1/iam/roles"},
	{"/v1/iam/get-role", "/v1/iam/roles/get"},
	{"/v1/iam/add-role", "/v1/iam/roles"},
	{"/v1/iam/update-role", "/v1/iam/roles/update"},
	{"/v1/iam/delete-role", "/v1/iam/roles/delete"},

	// projects / workspaces (internal/projects, internal/workspaces). The compound
	// reads belong HERE, against the child collection — not against organizations.
	{"/v1/iam/get-organization-projects", "/v1/iam/projects"},
	{"/v1/iam/add-project", "/v1/iam/projects"},
	{"/v1/iam/delete-project", "/v1/iam/projects/delete"},
	{"/v1/iam/get-organization-workspaces", "/v1/iam/workspaces"},
	{"/v1/iam/add-workspace", "/v1/iam/workspaces"},
	{"/v1/iam/delete-workspace", "/v1/iam/workspaces/delete"},

	// Read-only aliases with no write verb registered.
	{"/v1/iam/get-certs", "/v1/iam/certs"},
	{"/v1/iam/get-cert", "/v1/iam/certs/get"},
	{"/v1/iam/get-permissions", "/v1/iam/permissions"},
	{"/v1/iam/get-permission", "/v1/iam/permissions/get"},
	{"/v1/iam/get-invitations", "/v1/iam/invitations"},
	{"/v1/iam/get-records", "/v1/iam/audit-logs"}, // "records" is Casdoor's name for audit logs
}

// Every registered compat verb resolves to the SAME entity as the REST route it
// aliases. This is the whole intent: the alias layer reimplements no CRUD and no
// redaction, so it must reimplement no policy either.
func TestCompatVerbMatchesRestTwin(t *testing.T) {
	for _, c := range twins {
		t.Run(c.verb, func(t *testing.T) {
			got, want := entityOf(c.verb), entityOf(c.rest)
			if want == "" {
				t.Fatalf("REST twin %q resolves to no entity — the pair is wrong", c.rest)
			}
			if got != want {
				t.Fatalf("entityOf(%q) = %q, but its twin %q = %q", c.verb, got, c.rest, want)
			}
		})
	}
}

// The compat surface is covered: every entityFor key that is a verb spelling
// appears in the twins table, so no alias resolves to an entity no test pinned.
// (`application` is the singular REST route, not a verb, hence the exemption.)
func TestEveryTableEntryHasATwin(t *testing.T) {
	covered := map[string]bool{"application": true}
	for _, c := range twins {
		covered[c.verb[len("/v1/iam/"):]] = true
	}
	for seg := range entityFor {
		if !covered[seg] {
			t.Errorf("entityFor[%q] is resolved but no REST twin pins it", seg)
		}
	}
}

// The safety theorem, proven EXHAUSTIVELY rather than sampled.
//
// authorize() consults the entity in exactly three places — the reserved-owner
// gate (entity == "organizations"), the confidential-client gate (capFor, which
// maps ONLY organizations and users), and the regular-user self-read (entity ==
// "users"). Every other entity value denies at all three, so entityOf can widen
// authorization ONLY by yielding "organizations" or "users".
//
// entityOf yields exactly entityFor[seg] when the segment is listed and seg
// otherwise, so its whole pre-image of those two values is: the table entries
// mapping to them, plus the two literal REST segments. Iterating the table and
// checking the literals therefore covers EVERY possible path, not a sample of
// registered ones — no route added later can slip past this bound.
func TestOnlyOrgAndUserPathsCarryAuthority(t *testing.T) {
	want := map[string]map[string]bool{
		"organizations": {
			"get-organizations": true, "get-organization": true, "add-organization": true,
			"update-organization": true, "delete-organization": true,
			"organizations": true, // the REST collection itself
		},
		"users": {
			"get-users": true, "get-global-users": true, "get-user": true,
			"add-user": true, "update-user": true, "delete-user": true,
			"users": true, // the REST collection itself
		},
	}

	// Every table entry that resolves to an authority-carrying entity is expected.
	for seg, entity := range entityFor {
		if allowed, carries := want[entity]; carries && !allowed[seg] {
			t.Errorf("entityFor[%q] = %q grants authority but is not an %s route", seg, entity, entity)
		}
	}
	// And every expected segment really does resolve there — no silent omission.
	for entity, segs := range want {
		for seg := range segs {
			if got := entityOf("/v1/iam/" + seg); got != entity {
				t.Errorf("entityOf(/v1/iam/%s) = %q, want %q", seg, got, entity)
			}
		}
	}
	// The pass-through arm cannot invent authority: a segment reaches an
	// authority-carrying entity only via the table or by literally being one.
	for entity := range want {
		if e, listed := entityFor[entity]; listed && e != entity {
			t.Errorf("entityFor remaps the literal entity %q to %q", entity, e)
		}
	}
}

// The compound and non-entity paths, named explicitly because each is a plausible
// mis-resolution that would GRANT. A verb that names an org but addresses a child
// collection must never reach "organizations"; a self-authorizing raw handler and
// the public front door must never reach an entity at all.
func TestNonEntityPathsCarryNoAuthority(t *testing.T) {
	cases := map[string]string{
		// Compound reads: named for the parent, addressed at the child. Resolving
		// either to "organizations" hands every CapOrgAdmin client a grant on a
		// collection it holds no capability for.
		"/v1/iam/get-organization-projects":   "projects",
		"/v1/iam/get-organization-workspaces": "workspaces",

		// Raw handlers that authorize their own target through authz.Can. Neither
		// seam asks entityOf about them; if one ever did, they must deny.
		"/v1/iam/get-memberships":   "get-memberships",
		"/v1/iam/add-membership":    "add-membership",
		"/v1/iam/delete-membership": "delete-membership",
		"/v1/iam/delete-mfa":        "delete-mfa",
		"/v1/iam/set-preferred-mfa": "set-preferred-mfa",

		// The public front door — registered BEFORE the Guard, each handler resolving
		// its own caller. get-account in particular feeds the gateway admin-guard's
		// global-admin predicate, and get-app-login reads an application row; neither
		// may inherit the users or applications entity.
		"/v1/iam/get-account":            "get-account",
		"/v1/iam/get-app-login":          "get-app-login",
		"/v1/iam/update-preferences":     "update-preferences",
		"/v1/iam/issue-user-token":       "issue-user-token",
		"/v1/iam/mint-user-keys":         "mint-user-keys",
		"/v1/iam/revoke-user-keys":       "revoke-user-keys",
		"/v1/iam/send-verification-code": "send-verification-code",
		"/v1/iam/linked-accounts":        "linked-accounts",
		"/v1/iam/signup":                 "signup",
		"/v1/iam/onboard":                "onboard",
		"/v1/iam/whoami":                 "whoami",

		// Hyphenated REST ENTITIES — these spell their own entity and must pass
		// through untouched; a verb-stripping rule is what would maul them.
		"/v1/iam/audit-logs":           "audit-logs",
		"/v1/iam/webauthn-credentials": "webauthn-credentials",
		"/v1/iam/service-accounts":     "service-accounts",

		// Not registered in this service at all — cloud calls it and gets a 404. It is
		// pinned here so that if a handler is ever added, it inherits NO authority
		// from this resolver and must state its own.
		"/v1/iam/delete-everything": "delete-everything",

		// Outside the surface entirely.
		"/mcp":     "",
		"/healthz": "",
		"/v1/iam/": "",
	}
	for path, want := range cases {
		t.Run(path, func(t *testing.T) {
			got := entityOf(path)
			if got != want {
				t.Fatalf("entityOf(%q) = %q, want %q", path, got, want)
			}
			// The property that actually matters, restated per case.
			if got == "organizations" || got == "users" {
				t.Fatalf("entityOf(%q) = %q — a non-entity path reached an authority-carrying entity", path, got)
			}
		})
	}
}

// Every entity this table names is one the REST surface already produces, so the
// resolver invents no new entity name and capFor's mapping needs no companion
// change: its keys ("organizations", "users") are exactly the two authority-carrying
// values, and both were already reachable from REST before this table existed.
func TestTableInventsNoNewEntity(t *testing.T) {
	rest := map[string]bool{}
	for _, c := range twins {
		rest[entityOf(c.rest)] = true
	}
	for seg, entity := range entityFor {
		if !rest[entity] {
			t.Errorf("entityFor[%q] = %q is an entity no REST route produces", seg, entity)
		}
	}
	for _, entity := range []string{"organizations", "users"} {
		if capFor(entity) == (Cap{}) {
			t.Errorf("capFor(%q) is unmapped — the authority-carrying set drifted", entity)
		}
	}
}

// The live outage, end to end through the real policy: cloud's signup fallback
// posts /v1/iam/add-organization as the hanzo-console confidential client, and an
// org row is filed under the RESERVED admin owner — the one case the reserved-owner
// gate gets to refuse before the capability check. It must now authorize exactly as
// POST /v1/iam/organizations does, and every sibling verb at a reserved owner must
// still be refused, because that gate is what keeps signing material super-only.
func TestReservedOwnerParityForConfidentialClient(t *testing.T) {
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")
	t.Setenv("IAM_USER_ADMIN_APPS", "hanzo-console")
	console := &Principal{App: "hanzo-console", AppOwner: "admin", Org: "admin"}

	// The repair: the signup leg passes, and it passes for the SAME reason its REST
	// twin does — same principal, same target, same decision.
	for _, path := range []string{"/v1/iam/add-organization", "/v1/iam/organizations"} {
		if !authorize(console, "POST", entityOf(path), "admin", "acme") {
			t.Fatalf("POST %s at the reserved owner must be allowed for a CapOrgAdmin client", path)
		}
	}

	// The gate, still shut. Each of these is a verb whose entity is NOT organizations,
	// so the reserved-owner branch refuses it before any capability is consulted —
	// including add-user, which the same client MAY write in a tenant org.
	for _, path := range []string{
		"/v1/iam/add-user", "/v1/iam/update-user", "/v1/iam/delete-user",
		"/v1/iam/add-application", "/v1/iam/update-application", "/v1/iam/delete-application",
		"/v1/iam/add-provider", "/v1/iam/add-role", "/v1/iam/add-project", "/v1/iam/add-workspace",
		"/v1/iam/get-users", "/v1/iam/get-global-users", "/v1/iam/get-certs",
		"/v1/iam/certs", "/v1/iam/users", "/v1/iam/application",
	} {
		for _, owner := range []string{"admin", "built-in", "app"} {
			if authorize(console, "POST", entityOf(path), owner, "x") {
				t.Fatalf("POST %s at reserved owner %q must stay refused", path, owner)
			}
		}
	}

	// The move-user leg of the same signup, in the TENANT org where it belongs: the
	// client holds CapUserAdmin, so it passes there and only there.
	if !authorize(console, "POST", entityOf("/v1/iam/update-user"), "acme", "founder") {
		t.Fatal("update-user in a tenant org must be allowed for a CapUserAdmin client")
	}
	// An app with neither capability is still inert on the repaired surface.
	rogue := &Principal{App: "rogue", AppOwner: "admin", Org: "admin"}
	for _, path := range []string{"/v1/iam/add-organization", "/v1/iam/update-user", "/v1/iam/get-users"} {
		if authorize(rogue, "POST", entityOf(path), "acme", "x") {
			t.Fatalf("%s must stay refused for an app in no allowlist", path)
		}
	}
}

// A tenant-owned app that registers the allow-listed console NAME gains nothing on
// the repaired verb surface either — the owner-pin denies every capability, so the
// aliases are as inert for it as the REST routes are.
func TestRepairedVerbsRespectTheOwnerPin(t *testing.T) {
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")
	t.Setenv("IAM_USER_ADMIN_APPS", "hanzo-console")
	attacker := &Principal{App: "hanzo-console", AppOwner: "evil", Org: "evil"}
	for _, path := range []string{
		"/v1/iam/add-organization", "/v1/iam/update-organization", "/v1/iam/delete-organization",
		"/v1/iam/add-user", "/v1/iam/update-user", "/v1/iam/get-users",
	} {
		if authorize(attacker, "POST", entityOf(path), "admin", "acme") {
			t.Fatalf("%s must stay refused for a tenant-owned app spoofing the console name", path)
		}
		if authorize(attacker, "POST", entityOf(path), "victim", "x") {
			t.Fatalf("%s must stay refused cross-tenant for a spoofing app", path)
		}
	}
}
