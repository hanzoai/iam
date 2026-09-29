package oidc

import (
	"context"
	"slices"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// RED-1: an org admin (IsAdmin, homed in the org, no org-wide row) re-drives
// onboarding for its own org's slug and is written the owner role.
func TestRedAdminOnboardsIntoOwner(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, db, "landing", "alice", "alice@example.com")
	if _, err := provision(ctx, db, claim{owner: "landing", name: "alice", slug: "acme", display: "Acme"}); err != nil {
		t.Fatalf("alice provision: %v", err)
	}
	// bob: an admin of acme (IsAdmin), not an owner.
	seedUserIn(t, db, "acme", "bob", "bob@example.com")
	b, _ := store.GetUserByName(ctx, db, "acme", "bob")
	b.IsAdmin = true
	if err := b.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	if owners, _ := store.Owners(ctx, db, "acme"); slices.Contains(owners, "acme/bob") {
		t.Fatalf("precondition: bob already owns acme")
	}
	// POST /v1/iam/onboard {"name":"acme"} as bob.
	_, err := provision(ctx, db, claim{owner: "acme", name: "bob", slug: "acme", display: "Acme"})
	owners, _ := store.Owners(ctx, db, "acme")
	if slices.Contains(owners, "acme/bob") {
		t.Fatalf("ESCALATION: admin bob became an owner of acme via onboard (err=%v, owners=%v)", err, owners)
	}
}

// RED-2: the last owner of its home org, holding the role by row, cannot move to
// a new org: the move would leave the org it leaves with no owner.
func TestRedRekeyDropsLastOwner(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", "beta"
	o.SetId("admin/beta")
	if err := o.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedUserIn(t, db, "beta", "carol", "carol@example.com")
	if _, err := store.SetRole(ctx, db, "beta/carol", "beta", store.RoleOwner, ""); err != nil {
		t.Fatalf("carol owner: %v", err)
	}
	_, err := provision(ctx, db, claim{owner: "beta", name: "carol", slug: "carolco", display: "Carolco"})
	if ft, ok := err.(*fault); !ok || ft.status != 409 {
		t.Fatalf("the last owner's move: %v, want 409", err)
	}
	if owners, _ := store.Owners(ctx, db, "beta"); len(owners) == 0 {
		t.Fatalf("LAST OWNER REMOVED: beta has no owner after carol's onboarding move")
	}
}

// RED-3: an act-granted key of acme mints an as() token for a plain acme member
// who OWNS another org, beta. The token's orgs claim carries beta:owner, and the
// principal it projects owns beta.
func TestRedAsReachesOwnerOfAnotherOrg(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "app-secret"})
	seedActUser(t, db, "acme", "bob", "ext-bob")
	seedMembership(t, db, "acme/bob", "beta", "owner")
	seedActKey(t, db, "acme", "agent", "sk-live-acmeagent", "hanzo-app", true)

	resp, body := do(t, app, asReq("sk-live-acmeagent", "?id=acme/bob"))
	if resp.StatusCode == 403 {
		return
	}
	if resp.StatusCode != 200 {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	claims, err := verifyToken(context.Background(), db, dataMap(t, body)["accessToken"].(string))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	for _, o := range claims.Orgs {
		if o.Org == "beta" && o.Role == "owner" {
			t.Fatalf("ESCALATION: acme act key holds beta owner through as(acme/bob): orgs=%+v",
				claims.Orgs)
		}
	}
}

// RED-2b: an admin of y plants a member row for the id the owner will carry
// after a one-click personal onboarding (<name>/<name>); Rekey keeps the planted
// row and drops the owner row, so y's only owner is demoted to member.
func TestRedRekeyPlantedRowDemotesOwner(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = "admin", "yco"
	o.SetId("admin/yco")
	if err := o.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedUserIn(t, db, "landing", "xavier", "x@example.com")
	if _, err := store.SetRole(ctx, db, "landing/xavier", "yco", store.RoleOwner, ""); err != nil {
		t.Fatal(err)
	}
	// yco's admin, via POST /v1/iam/memberships {user: xavier/xavier, org: yco, role: member}
	if _, err := store.EnsureMembership(ctx, db, "xavier/xavier", "yco", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	if _, err := provision(ctx, db, claim{owner: "landing", name: "xavier", slug: "xavier", display: "xavier", personal: true}); err != nil {
		t.Fatalf("onboard: %v", err)
	}
	if owners, _ := store.Owners(ctx, db, "yco"); len(owners) == 0 {
		t.Fatalf("OWNER DEMOTED BY ADMIN: yco has no owner; xavier holds %q", func() string {
			m, _ := store.MembershipIn(ctx, db, "xavier/xavier", "yco", "", "")
			if m == nil {
				return ""
			}
			return m.Role
		}())
	}
}
