package object

import (
	"testing"

	"github.com/hanzoai/iam/conf"
)

// The tenancy chain is only safe while the graph is a forest. A cycle in a parent
// chain that authz trusts is a privilege-escalation primitive: with A parent of B and
// B parent of A, each org's admins administer the other. These tests pin the walk's
// guards and the delegation rule against a graph, with no database in the way.

// withOrgGraph points the ancestry seam at an in-memory parent map for one test.
func withOrgGraph(t *testing.T, parents map[string]string) {
	t.Helper()
	prevParent, prevExists := parentOfOrg, requireOrgExists
	parentOfOrg = func(org string) (string, error) { return parents[org], nil }
	requireOrgExists = func(org string) error { return nil }
	t.Cleanup(func() { parentOfOrg, requireOrgExists = prevParent, prevExists })
}

func TestOrgAncestors_WalksResellerChain(t *testing.T) {
	// customer → reseller → distributor
	withOrgGraph(t, map[string]string{"customer": "reseller", "reseller": "distributor"})

	got, err := OrgAncestors("customer")
	if err != nil {
		t.Fatalf("OrgAncestors: %v", err)
	}
	want := []string{"reseller", "distributor"}
	if len(got) != len(want) {
		t.Fatalf("OrgAncestors = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("OrgAncestors = %v, want %v (nearest parent first)", got, want)
		}
	}
}

func TestOrgAncestors_RefusesCycle(t *testing.T) {
	// A cycle must never loop the walk and never resolve into a chain authz trusts.
	withOrgGraph(t, map[string]string{"a": "b", "b": "a"})

	if _, err := OrgAncestors("a"); err == nil {
		t.Fatal("OrgAncestors must refuse a parent cycle, not resolve it")
	}
}

func TestOrgAncestors_RefusesOverlongChain(t *testing.T) {
	parents := map[string]string{}
	prev := "o0"
	for i := 1; i <= MaxOrgDepth+2; i++ {
		cur := "o" + string(rune('0'+i))
		parents[prev] = cur
		prev = cur
	}
	withOrgGraph(t, parents)

	if _, err := OrgAncestors("o0"); err == nil {
		t.Fatalf("OrgAncestors must refuse a chain deeper than MaxOrgDepth (%d)", MaxOrgDepth)
	}
}

func TestAdministersOrg_ResellerAdminReachesItsCustomers(t *testing.T) {
	withOrgGraph(t, map[string]string{"customer": "reseller"})

	admin := &User{Owner: "reseller", Name: "root", IsAdmin: true}

	ok, err := AdministersOrg(admin, "customer")
	if err != nil {
		t.Fatalf("AdministersOrg: %v", err)
	}
	if !ok {
		t.Fatal("a reseller's admin must administer the customers it onboarded")
	}

	// ...and no further. A sibling tenant is not below the reseller.
	ok, err = AdministersOrg(admin, "unrelated")
	if err != nil {
		t.Fatalf("AdministersOrg: %v", err)
	}
	if ok {
		t.Fatal("a reseller's admin must NOT administer an unrelated tenant")
	}
}

func TestAdministersOrg_CustomerAdminCannotClimbToReseller(t *testing.T) {
	// The edge is one-way. A customer's admin must never administer its reseller —
	// otherwise onboarding a customer would hand them the parent's tenancy.
	withOrgGraph(t, map[string]string{"customer": "reseller"})

	admin := &User{Owner: "customer", Name: "root", IsAdmin: true}
	ok, err := AdministersOrg(admin, "reseller")
	if err != nil {
		t.Fatalf("AdministersOrg: %v", err)
	}
	if ok {
		t.Fatal("a customer's admin must NOT administer its parent (no upward escalation)")
	}
}

func TestAdministersOrg_NonAdminNeverAdministers(t *testing.T) {
	withOrgGraph(t, map[string]string{})
	u := &User{Owner: "acme", Name: "bob", IsAdmin: false}
	ok, err := AdministersOrg(u, "acme")
	if err != nil {
		t.Fatalf("AdministersOrg: %v", err)
	}
	if ok {
		t.Fatal("a plain member must not administer its own org")
	}
}

func TestAdministersOrg_SuperAdminAdministersEverything(t *testing.T) {
	withOrgGraph(t, map[string]string{})
	u := &User{Owner: conf.AdminOrg, Name: "z", IsAdmin: true}
	ok, err := AdministersOrg(u, "any-tenant")
	if err != nil {
		t.Fatalf("AdministersOrg: %v", err)
	}
	if !ok {
		t.Fatal("super admin (owner == AdminOrg) must administer any org")
	}
}

func TestAdministersOrg_EmptyPrincipalNeverAdministers(t *testing.T) {
	withOrgGraph(t, map[string]string{})
	// An empty owner (malformed principal) must never act as a wildcard admin.
	u := &User{Owner: "", Name: "nobody", IsAdmin: true}
	ok, err := AdministersOrg(u, "acme")
	if err != nil {
		t.Fatalf("AdministersOrg: %v", err)
	}
	if ok {
		t.Fatal("an empty-owner principal must never administer any org")
	}
}

func TestCheckOrgParent_RejectsCycleAndSelf(t *testing.T) {
	withOrgGraph(t, map[string]string{"reseller": "customer"}) // customer is ABOVE reseller

	if err := CheckOrgParent("acme", "acme"); err == nil {
		t.Fatal("self-parent must be rejected (1-cycle)")
	}
	// customer → reseller would close the loop reseller → customer → reseller.
	if err := CheckOrgParent("customer", "reseller"); err == nil {
		t.Fatal("a parent that closes a cycle must be rejected")
	}
	if err := CheckOrgParent("acme", ""); err != nil {
		t.Fatalf("empty parent (top-level tenant) must be allowed: %v", err)
	}
}
