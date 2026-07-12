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

import "fmt"

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
