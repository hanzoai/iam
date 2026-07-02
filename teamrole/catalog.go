// Copyright 2026 The Hanzo Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package teamrole is the canonical, DB-free policy for app-scoped team roles.
//
// It defines the ONLY roles the shared Team-management surface
// (billing.hanzo.ai, console.hanzo.ai, and any future product on Hanzo IAM) may
// grant, change, or revoke, and the pure authorization function that decides
// whether a given caller is allowed to do so.
//
// The policy is deliberately decomplected from persistence: nothing here reads
// the database. The IAM `object` package supplies the caller's held role keys
// and the target role's owner, then calls CheckAssignment. This makes the
// security-critical decision a pure value-function — trivially unit-testable,
// deterministic, and free of I/O — which is exactly what an adversarial
// reviewer needs to reason about.
//
// Why this exists: IAM roles/permissions live co-mingled on the GLOBAL SQLite
// engine, keyed only by the `Owner` (org) column — there is no per-tenant
// cryptographic isolation for roles. The generic Casbin authz filter only gates
// "may this subject act on this org at all"; it does NOT encode app-scope or
// rank. Without this policy a billing:admin could call update-role to grant
// itself console:admin or org:owner in its own org (vertical + lateral
// privilege escalation), and nothing but the Owner-column would stop a crafted
// request from targeting another org (cross-tenant member manipulation). This
// package closes both holes.
package teamrole

import "fmt"

// App is a product surface that scopes a role. A caller with authority in one
// app has NO authority in another (org owners excepted).
type App string

const (
	AppBilling App = "billing"
	AppConsole App = "console"
	// AppOrg is the org-wide surface. Only org:owner lives here; it is
	// authoritative over every other app.
	AppOrg App = "org"
)

// Tier is the privilege level within an app.
type Tier string

const (
	TierViewer Tier = "viewer"
	TierAdmin  Tier = "admin"
	TierOwner  Tier = "owner"
)

// RankAdmin is the minimum effective rank required to manage team membership in
// an app. Below this (viewer) a caller may read but never mutate membership.
const RankAdmin = 20

// Role is one entry in the canonical catalog. Key is the stable identifier used
// everywhere (IAM Role.Name, the client role picker, and the wire): it is the
// exact "app:tier" string the CTO specified — billing:viewer, billing:admin,
// console:viewer, console:admin, console:owner, org:owner.
type Role struct {
	Key         string   `json:"key"`         // "app:tier", e.g. "billing:admin"
	App         App      `json:"app"`         // billing | console | org
	Tier        Tier     `json:"tier"`        // viewer | admin | owner
	Rank        int      `json:"rank"`        // strict order: viewer<admin<console-owner<org-owner
	Resource    string   `json:"resource"`    // Casbin resource this role grants on, e.g. "billing:*"
	Actions     []string `json:"actions"`     // Casbin actions this role grants
	DisplayName string   `json:"displayName"` // human label for the UI
	Description string   `json:"description"` // human help text for the UI
}

// catalog is the canonical, ordered role catalog. Ranks are STRICTLY ordered so
// the rank ceiling in the guard is total:
//
//	viewer(10) < admin(20) < console:owner(30) < org:owner(100)
//
// The gap to 100 for org:owner is intentional: no app-admin can ever reach it
// by accumulating app roles, so only an existing org:owner (or a platform
// superuser) can mint another org:owner.
var catalog = []Role{
	{
		Key: "billing:viewer", App: AppBilling, Tier: TierViewer, Rank: 10,
		Resource: "billing:*", Actions: []string{"read"},
		DisplayName: "Billing Viewer",
		Description:  "Read-only access to billing: invoices, usage, and team members.",
	},
	{
		Key: "billing:admin", App: AppBilling, Tier: TierAdmin, Rank: 20,
		Resource: "billing:*", Actions: []string{"read", "write", "manage"},
		DisplayName: "Billing Admin",
		Description:  "Manage billing: payment methods, plans, spend limits, and the billing team.",
	},
	{
		Key: "console:viewer", App: AppConsole, Tier: TierViewer, Rank: 10,
		Resource: "console:*", Actions: []string{"read"},
		DisplayName: "Console Viewer",
		Description:  "Read-only access to console projects and resources.",
	},
	{
		Key: "console:admin", App: AppConsole, Tier: TierAdmin, Rank: 20,
		Resource: "console:*", Actions: []string{"read", "write", "manage"},
		DisplayName: "Console Admin",
		Description:  "Manage console resources and the console team.",
	},
	{
		Key: "console:owner", App: AppConsole, Tier: TierOwner, Rank: 30,
		Resource: "console:*", Actions: []string{"read", "write", "manage", "own"},
		DisplayName: "Console Owner",
		Description:  "Full ownership of the console surface, including owner assignment.",
	},
	{
		Key: "org:owner", App: AppOrg, Tier: TierOwner, Rank: 100,
		Resource: "*", Actions: []string{"*"},
		DisplayName: "Organization Owner",
		Description:  "Full ownership of the organization: every app, billing, team, and ownership transfer.",
	},
}

// byKey indexes the catalog for O(1) lookup. Built once at init from the
// canonical slice; never mutated.
var byKey = func() map[string]Role {
	m := make(map[string]Role, len(catalog))
	for _, r := range catalog {
		m[r.Key] = r
	}
	return m
}()

// Catalog returns a defensive copy of the canonical role catalog, ordered by
// rank. Callers (e.g. the seed path, or an API that lists assignable roles) get
// a fresh slice they cannot use to mutate policy.
func Catalog() []Role {
	out := make([]Role, len(catalog))
	copy(out, catalog)
	return out
}

// Lookup returns the catalog role for an "app:tier" key and whether it is a
// managed team role. Unknown keys (any role name not in the catalog) return
// ok=false, which is how the IAM controllers decide a role mutation is NOT
// team-managed and falls through to the ordinary authz path unchanged.
func Lookup(key string) (Role, bool) {
	r, ok := byKey[key]
	return r, ok
}

// IsManaged reports whether a role name (the IAM Role.Name) is a managed
// catalog role. Role.Name is stored as the exact catalog Key.
func IsManaged(roleName string) bool {
	_, ok := byKey[roleName]
	return ok
}

// AppTiers returns the catalog roles for one app, ordered by rank ascending.
// The client role picker uses this to render only the tiers that exist for the
// surface it is mounted on (billing shows viewer/admin; console shows
// viewer/admin/owner).
func AppTiers(app App) []Role {
	out := []Role{}
	for _, r := range catalog {
		if r.App == app {
			out = append(out, r)
		}
	}
	return out
}

// String renders a role key for logs/errors.
func (r Role) String() string { return fmt.Sprintf("%s(rank=%d)", r.Key, r.Rank) }
