// Tenancy: the org parent chain and the authz that rides on it.
//
// Orgs used to be flat, so a white-label partner ("reseller") that onboards its own
// customers was indistinguishable from an unrelated tenant: no delegated admin, no
// usage rollup. Organization.Parent adds that edge. Everything that TRUSTS the edge
// goes through this file, because the edge is only safe while the graph is a forest:
// a cycle (A→B→A) would make each org an ancestor of the other and hand both sides
// the other's admin rights. So: the write path refuses cycles, and every read is
// depth-bounded and visited-set guarded — a corrupted row can never spin or escalate.

package object

import (
	"fmt"
	"strings"

	"github.com/hanzoai/iam/util"
)

// MaxOrgDepth bounds the reseller chain (tenant → reseller → distributor → …).
// It is a safety rail, not a product limit: it stops an unbounded/corrupt chain from
// turning an authz check into an unbounded walk.
const MaxOrgDepth = 8

// parentOfOrg resolves an org's parent. It is the ONE seam the ancestry walk reads
// through, so the walk (cycle + depth guards, the security-critical part) is testable
// against a graph without a database. Production resolves it from storage.
var parentOfOrg = func(orgName string) (string, error) {
	org, err := getOrganization("admin", orgName)
	if err != nil {
		return "", err
	}
	if org == nil {
		return "", nil
	}
	return org.Parent, nil
}

// OrgAncestors returns org's ancestors, nearest parent first, excluding org itself.
// The walk stops at the root, at MaxOrgDepth, or the moment it revisits an org (a
// cycle) — it never loops and never errors the caller into a fail-open.
func OrgAncestors(orgName string) ([]string, error) {
	if orgName == "" {
		return nil, nil
	}
	seen := map[string]bool{orgName: true}
	chain := make([]string, 0, 4)

	current := orgName
	for depth := 0; depth < MaxOrgDepth; depth++ {
		parent, err := parentOfOrg(current)
		if err != nil {
			return nil, err
		}
		if parent == "" {
			return chain, nil
		}
		if seen[parent] {
			// Cycle in persisted data: refuse to trust the chain rather than loop or
			// grant rights around the loop.
			return nil, fmt.Errorf("organization parent cycle detected at %q", parent)
		}
		seen[parent] = true
		chain = append(chain, parent)
		current = parent
	}
	return nil, fmt.Errorf("organization parent chain exceeds max depth %d (starting at %q)", MaxOrgDepth, orgName)
}

// IsAncestorOrg reports whether ancestor is at or above org in the tenancy chain.
// Same-org is true: an org trivially administers itself, which keeps callers from
// special-casing the self check and accidentally dropping it.
func IsAncestorOrg(ancestor, org string) (bool, error) {
	if ancestor == "" || org == "" {
		return false, nil
	}
	if ancestor == org {
		return true, nil
	}
	chain, err := OrgAncestors(org)
	if err != nil {
		return false, err
	}
	for _, a := range chain {
		if a == ancestor {
			return true, nil
		}
	}
	return false, nil
}

// CheckOrgParent validates a proposed Parent for org before it is persisted. It is
// the ONLY place the forest invariant is enforced: no self-parent, the parent must
// exist, the parent must not be a descendant of org (that closes a cycle), and the
// resulting chain must fit MaxOrgDepth.
func CheckOrgParent(orgName, parent string) error {
	if parent == "" {
		return nil
	}
	if parent == orgName {
		return fmt.Errorf("organization cannot be its own parent")
	}

	if err := requireOrgExists(parent); err != nil {
		return err
	}

	// Would this close a cycle? It does exactly when org is already an ancestor of
	// the proposed parent.
	loops, err := IsAncestorOrg(orgName, parent)
	if err != nil {
		return err
	}
	if loops {
		return fmt.Errorf("organization parent %q would create a cycle", parent)
	}

	chain, err := OrgAncestors(parent)
	if err != nil {
		return err
	}
	if len(chain)+2 > MaxOrgDepth { // +2: the parent itself and org
		return fmt.Errorf("organization parent chain would exceed max depth %d", MaxOrgDepth)
	}
	return nil
}

// AdministersOrg is the tenancy authz predicate: may user administer targetOrg?
//
//	super admin (owner == AdminOrg)       → everything
//	admin of an org at/above targetOrg    → that org and everything under it
//	anyone else                           → no
//
// This is what makes a reseller's admin a real admin of the customers it onboarded,
// without handing them the platform.
func AdministersOrg(user *User, targetOrg string) (bool, error) {
	if user == nil || targetOrg == "" {
		return false, nil
	}
	if user.IsSuperAdmin() {
		return true, nil
	}
	if !user.IsAdmin {
		return false, nil
	}
	return IsAncestorOrg(user.Owner, targetOrg)
}

// requireOrgExists is split out so CheckOrgParent's cycle/depth logic stays free of
// storage and testable alongside the walk.
var requireOrgExists = func(orgName string) error {
	org, err := getOrganization("admin", orgName)
	if err != nil {
		return err
	}
	if org == nil {
		return fmt.Errorf("parent organization %q does not exist", orgName)
	}
	return nil
}

// GetUserForLogin resolves the login user for an application whose organization is
// appOrg, allowing the user to live in a DESCENDANT tenant of appOrg.
//
// Signup now puts each founder in their own org (so commerce, which namespaces by org,
// bills THEM and not the parent), while the client application they authenticate
// against still belongs to the parent — the platform (or a white-label reseller). Login
// therefore has to look one way DOWN the tenancy chain:
//
//	exact match in appOrg          → the fast path, unchanged behaviour
//	unique match in a descendant   → the founder in their own tenant
//	several descendant matches     → refuse (ambiguous identity is never resolved)
//
// It only ever accepts a user the app's org is an ANCESTOR of, so a tenant client can
// never authenticate a user from an unrelated org (or from its own parent).
func GetUserForLogin(appOrg string, field string) (*User, error) {
	if appOrg == "" || field == "" {
		return nil, nil
	}

	// Fast path: the user lives directly in the app's org.
	if user, err := getUserByFieldsFn(appOrg, field); err != nil || user != nil {
		return user, err
	}

	candidates, err := findUsersUnderOrgFn(appOrg, field)
	if err != nil {
		return nil, err
	}

	var found *User
	for _, u := range candidates {
		if u == nil || u.Owner == appOrg {
			continue
		}
		below, err := IsAncestorOrg(appOrg, u.Owner)
		if err != nil {
			return nil, err
		}
		if !below {
			continue
		}
		if found != nil {
			// Two different tenants under this app share the identifier. Resolving one
			// of them arbitrarily would let whoever signs up second shadow the first.
			return nil, fmt.Errorf("ambiguous login identity %q across tenants of %q", field, appOrg)
		}
		found = u
	}
	return found, nil
}

// OrgChildren returns the orgs whose Parent is orgName.
var OrgChildren = func(orgName string) ([]string, error) {
	orgs := []*Organization{}
	if err := ormer.Engine.Where("parent = ?", orgName).Find(&orgs); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(orgs))
	for _, o := range orgs {
		names = append(names, o.Name)
	}
	return names, nil
}

// findUsersUnderOrg finds login candidates for field in the tenants BELOW appOrg.
//
// Two storage shapes, one contract. With a shared users table the subtree is one
// indexed query filtered by ancestry. With per-org SQLite isolation (orgIsolation=
// sqlite) each tenant has its own database, so the only correct read is per-org — we
// walk the subtree (breadth-first, depth-bounded, visited-guarded like every other
// walk here) and ask each tenant's own engine.
// The two storage seams the login resolver reads through, so the resolution RULES
// (subtree-only, no ambiguity) are tested against a graph rather than a database.
var (
	getUserByFieldsFn   = GetUserByFields
	findUsersUnderOrgFn = findUsersUnderOrg
)

func findUsersUnderOrg(appOrg string, field string) ([]*User, error) {
	if globalIsolationSqlite {
		return findUsersUnderOrgIsolated(appOrg, field)
	}

	field = strings.TrimSpace(field)
	users := []*User{}
	if err := ormer.Engine.Where("name = ?", field).Or("email = ?", strings.ToLower(field)).Find(&users); err != nil {
		return nil, err
	}
	return users, nil
}

func findUsersUnderOrgIsolated(appOrg string, field string) ([]*User, error) {
	found := []*User{}
	seen := map[string]bool{appOrg: true}
	frontier := []string{appOrg}

	for depth := 0; depth < MaxOrgDepth && len(frontier) > 0; depth++ {
		next := []string{}
		for _, org := range frontier {
			children, err := OrgChildren(org)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				if seen[child] {
					continue // corrupt edge; the forest invariant says this cannot happen
				}
				seen[child] = true
				next = append(next, child)

				user, err := GetUserByFields(child, field)
				if err != nil {
					return nil, err
				}
				if user != nil {
					found = append(found, user)
				}
			}
		}
		frontier = next
	}
	return found, nil
}

// TenantOrgForSignup returns the org a new user signing up against parentOrg should be
// created in, creating that tenant if needed.
//
// When parentOrg is a platform (SignupCreatesTenant), each signup gets its OWN org —
// its billing namespace, its balance, its payment methods — parented to the platform,
// so the platform's admins still administer it (AdministersOrg) and can roll usage up.
// Otherwise the user is created in parentOrg, exactly as before.
//
// The tenant is named after the user (slugged, collision-suffixed by the caller's
// uniqueness check), because at signup time we do not yet know the company name; the
// onboarding step renames/creates the org the founder actually wants.
func TenantOrgForSignup(parentOrg string, username string) (string, error) {
	if parentOrg == "" || username == "" {
		return parentOrg, nil
	}

	org, err := getOrganization("admin", parentOrg)
	if err != nil {
		return "", err
	}
	if org == nil || !org.SignupCreatesTenant {
		return parentOrg, nil // a plain tenant org: users live in it (unchanged)
	}

	tenant := slugForTenant(username)
	if tenant == "" {
		return parentOrg, nil
	}

	existing, err := getOrganization("admin", tenant)
	if err != nil {
		return "", err
	}
	if existing != nil {
		// Name taken by an unrelated org: fall back to the platform org rather than
		// silently dropping the founder into someone else's tenant.
		if existing.Parent != parentOrg {
			return parentOrg, nil
		}
		return tenant, nil
	}

	newOrg := &Organization{
		Owner:              "admin",
		Name:               tenant,
		CreatedTime:        util.GetCurrentTime(),
		DisplayName:        username,
		Parent:             parentOrg,
		PasswordType:       org.PasswordType,
		DefaultApplication: org.DefaultApplication,
		Languages:          org.Languages,
		Tags:               []string{},
		AccountItems:       org.AccountItems,
		EnableSoftDeletion: false,
		IsProfilePublic:    false,
	}
	if _, err := AddOrganization(newOrg); err != nil {
		return "", err
	}
	return tenant, nil
}

// slugForTenant derives a stable org name from a signup identifier. Org names are
// path/PK material, so anything outside [a-z0-9-] is folded to '-'.
func slugForTenant(username string) string {
	s := strings.ToLower(strings.TrimSpace(username))
	if at := strings.Index(s, "@"); at > 0 {
		s = s[:at] // an email signs up as its local part; the org is not a mailbox
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '-' || r == '_' || r == '.':
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}
