// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package authz

import "testing"

// The confidential-client authorization policy: an app principal's ENTIRE
// authority is its capability allowlist — never Super, never Admin, never a
// tenant. This is the v1 "every client credential is a global admin" hole, held
// closed. authorize() IS the decision; this table is its truth for app principals.
func TestAuthorizeAppCapabilities(t *testing.T) {
	// The allowlists reserve each capability to a named admin-owned app.
	t.Setenv("IAM_USER_ADMIN_APPS", "hanzo-console")
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-team")
	t.Setenv("IAM_SA_LIST_ALLOWED_APPS", "hanzo-reader")

	console := &Principal{App: "hanzo-console", AppOwner: "admin", Org: "admin"} // admin-owned: user+org admin caps
	nobody := &Principal{App: "rogue-app", AppOwner: "hanzo", Org: "hanzo"}      // in no allowlist
	// attacker: a tenant that registered <its-org>/hanzo-console — the SAME allow-listed
	// NAME, but owned by a NON-signing org. The owner-pin (cap.go) denies every capability,
	// so the public signup→onboard→register-app→Basic-auth escalation is inert.
	attacker := &Principal{App: "hanzo-console", AppOwner: "evil", Org: "evil"}

	cases := []struct {
		name   string
		p      *Principal
		method string
		entity string
		owner  string
		name2  string
		want   bool
	}{
		// A capability-holding app may act on its mapped entity — cross-tenant by
		// design (a platform console onboards any customer org).
		{"console writes users in any org", console, "POST", "users", "orgb", "x", true},
		{"console writes org (reserved-owner exception)", console, "POST", "organizations", "admin", "hanzo", true},
		{"console reads org", console, "GET", "organizations", "admin", "hanzo", true},

		// An app NEVER reaches signing material or unmapped entities, allowlisted
		// or not — capFor has no mapping, so the allowlist is vacuously empty.
		{"console -> certs denied", console, "POST", "certs", "admin", "k", false},
		{"console -> providers denied", console, "POST", "providers", "hanzo", "p", false},
		{"console -> tokens denied", console, "POST", "tokens", "hanzo", "t", false},

		// An app in NO allowlist holds nothing — a leaked credential is inert.
		{"rogue -> users denied", nobody, "POST", "users", "hanzo", "x", false},
		{"rogue -> orgs denied", nobody, "POST", "organizations", "admin", "hanzo", false},
		{"rogue -> own-org users denied", nobody, "POST", "users", "hanzo", "x", false},

		// A user under a reserved owner is NEVER writable by an app — provision,
		// never promote (no capability moves a user into the admin org).
		{"console -> admin-org user denied", console, "POST", "users", "admin", "x", false},
		{"console -> built-in user denied", console, "POST", "users", "built-in", "x", false},
		// [INFO] consistency: even the LEGIT admin-owned console may not land a user in
		// the reserved service-principal org "app" — a platform identity, super-only. The
		// raw CRUD now consults IsReservedOrg, the SAME predicate signup/onboarding use.
		{"console -> app-org user denied", console, "POST", "users", "app", "x", false},

		// RED PoC, now DENIED: a tenant-owned app spoofing the console NAME holds NOTHING.
		// The owner-pin refuses a non-signing owner BEFORE any allowlist name match, so a
		// leaked/forged tenant credential named like the console cannot act on any tenant.
		{"attacker spoof -> victim users denied", attacker, "POST", "users", "victim", "x", false},
		{"attacker spoof -> org write denied", attacker, "POST", "organizations", "admin", "victim", false},
		{"attacker spoof -> org delete denied", attacker, "DELETE", "organizations", "admin", "victim", false},
		{"attacker spoof -> org read denied", attacker, "GET", "organizations", "admin", "victim", false},
		{"attacker spoof -> own-org users denied", attacker, "POST", "users", "evil", "x", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := authorize(c.p, c.method, c.entity, c.owner, c.name2); got != c.want {
				t.Fatalf("authorize(App=%q,%s,%s,%s/%s) = %v, want %v",
					c.p.App, c.method, c.entity, c.owner, c.name2, got, c.want)
			}
		})
	}

	// An app principal is structurally never Super/Admin, so it can never take the
	// human privileged paths even if a future bug set the flags.
	if console.Super || console.Admin {
		t.Fatal("an app principal must never carry Super/Admin")
	}

	// RED's four assertions, VERBATIM — the exact PoC principal &Principal{App:"hanzo-console"}
	// (no owning signing org). Every one fired == true before the owner-pin; every one must
	// be false now. A bare app principal is inert regardless of the NAME it presents.
	red := &Principal{App: "hanzo-console"}
	for _, a := range []struct{ method, entity, owner, name string }{
		{"POST", "users", "victim", "x"},
		{"POST", "organizations", "admin", "victim"},
		{"DELETE", "organizations", "admin", "victim"},
		{"GET", "organizations", "admin", "victim"},
	} {
		if authorize(red, a.method, a.entity, a.owner, a.name) {
			t.Fatalf("RED PoC REOPENED: authorize(App=hanzo-console,%s,%s,%s/%s) GRANTED — the owner-pin failed",
				a.method, a.entity, a.owner, a.name)
		}
	}
}

// The capability primitives, fail-secure to the letter.
func TestCapabilityPrimitives(t *testing.T) {
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console, brand-console")

	t.Run("Allowed named", func(t *testing.T) {
		if !Allowed(&Principal{App: "hanzo-console", AppOwner: "admin"}, CapOrgAdmin) {
			t.Fatal("a named, admin-owned app must hold its capability")
		}
	})
	t.Run("Allowed unnamed denied", func(t *testing.T) {
		if Allowed(&Principal{App: "other", AppOwner: "admin"}, CapOrgAdmin) {
			t.Fatal("an unnamed app must hold nothing") // admin-owned, so the NAME check alone denies
		}
	})
	t.Run("Allowed unset env denied", func(t *testing.T) {
		if Allowed(&Principal{App: "hanzo-console", AppOwner: "admin"}, CapKeyMint) { // IAM_KEY_MINT_ALLOWED_APPS unset here
			t.Fatal("an unset allowlist must deny every app")
		}
	})
	t.Run("Allowed owner-pin denies a non-signing owner", func(t *testing.T) {
		// hanzo-console IS on IAM_ORG_ADMIN_APPS, but these rows are NOT admin/built-in owned.
		if Allowed(&Principal{App: "hanzo-console", AppOwner: "hanzo"}, CapOrgAdmin) {
			t.Fatal("a tenant-owned app must hold nothing even with an allow-listed name")
		}
		if Allowed(&Principal{App: "hanzo-console"}, CapOrgAdmin) { // AppOwner "" — no owning signing org at all
			t.Fatal("an app with no owning signing org must hold nothing")
		}
		// built-in is the other reserved signing owner — a built-in-owned allow-listed app is legit.
		if !Allowed(&Principal{App: "hanzo-console", AppOwner: "built-in"}, CapOrgAdmin) {
			t.Fatal("a built-in-owned allow-listed app must hold its capability")
		}
	})
	t.Run("Allowed non-app is vacuous", func(t *testing.T) {
		if !Allowed(&Principal{Org: "hanzo"}, CapOrgAdmin) {
			t.Fatal("a human holds capabilities vacuously; the org policy decides")
		}
	})
	t.Run("BoundToOrg prefix", func(t *testing.T) {
		p := &Principal{App: "hanzo-team"}
		if !BoundToOrg(p, "hanzo") {
			t.Fatal("hanzo-team must be bound to hanzo")
		}
		if BoundToOrg(p, "lux") {
			t.Fatal("hanzo-team must NOT be bound to lux")
		}
		if BoundToOrg(&Principal{App: "hanzo"}, "hanzo") {
			t.Fatal("an exact-name app (no agent segment) is bound to nothing")
		}
	})
	t.Run("capFor mapping", func(t *testing.T) {
		if capFor("organizations") != CapOrgAdmin || capFor("users") != CapUserAdmin {
			t.Fatal("org/user entities must map to their capability")
		}
		if capFor("certs") != (Cap{}) || capFor("providers") != (Cap{}) {
			t.Fatal("an unmapped entity must map to the empty (deny-all) capability")
		}
	})
}
