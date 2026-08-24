package authz

import (
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/principal"
)

// The "<org>-platform-kms" machine identity may READ its own org's projects —
// the grant that lets cloud's platform resolve a tenant's projects from THIS
// store instead of a second embedded database. Each wall of the grant gets its
// own negative: wrong method, wrong entity, wrong org, wrong identity.
func TestAuthorize_KMSMachineReadsOwnProjects(t *testing.T) {
	acme := &principal.Principal{Org: "acme", App: &policy.App{Name: "acme-platform-kms", Owner: "admin"}}

	if !authorize(acme, "GET", "projects", "acme", "web") {
		t.Fatal("the org's own platform-kms identity must read the org's projects")
	}
	if !authorize(acme, "GET", "projects", "acme", "") {
		t.Fatal("listing the org's projects is the same read")
	}

	// Wrong ORG: one tenant's identity can never walk another's list.
	if authorize(acme, "GET", "projects", "rival", "web") {
		t.Fatal("cross-org project read must be refused")
	}
	// Wrong METHOD: the grant is a read, never a write.
	for _, m := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if authorize(acme, m, "projects", "acme", "web") {
			t.Fatalf("%s on projects must be refused — the grant is read-only", m)
		}
	}
	// Wrong ENTITY: projects and nothing else.
	for _, e := range []string{"users", "organizations", "applications", "providers"} {
		if authorize(acme, "GET", e, "acme", "x") {
			t.Fatalf("the grant must not widen to %s", e)
		}
	}
	// Wrong IDENTITY: only the contract-named app. A sibling app in the same
	// org, and another org's platform-kms name, both stay refused.
	for _, app := range []string{"acme-console", "rival-platform-kms", "platform-kms"} {
		p := &principal.Principal{Org: "acme", App: &policy.App{Name: app, Owner: "admin"}}
		if authorize(p, "GET", "projects", "acme", "web") {
			t.Fatalf("app %q must not inherit the platform-kms grant", app)
		}
	}
	// An empty owner target is not admitted: the read must NAME the org so the
	// owner==p.Org pin has something to hold.
	if authorize(acme, "GET", "projects", "", "web") {
		t.Fatal("an owner-less project read must be refused")
	}
}
