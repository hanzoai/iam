package memberships_test

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// RED-7: remove reads the first (user, org) row at ANY scope. An owner who holds
// a space row in the org, filed before the org-wide owner row, is addressed by
// that row: the admin passes the non-owner gate and removes the owner's space
// row and every key the owner holds in the org.
func TestRedRemoveReadsSpaceRowOfOwner(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	o := orm.New[schema.Organization](h.db)
	o.Owner, o.Name = "admin", "acme"
	o.SetId("admin/acme")
	if err := o.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedUser(t, h.db, "acme", "ann", false)
	seedUser(t, h.db, "acme", "cy", true)
	seedUser(t, h.db, "hanzo", "eve", false)
	if _, err := store.SetRole(ctx, h.db, "acme/ann", "acme", store.RoleOwner, ""); err != nil {
		t.Fatal(err)
	}
	// eve: first a space member, then made an owner of acme by ann.
	if _, err := store.EnsureMembershipIn(ctx, h.db, "hanzo/eve", "acme", "ws1", "", "member"); err != nil {
		t.Fatal(err)
	}
	if _, err := store.SetRole(ctx, h.db, "hanzo/eve", "acme", store.RoleOwner, ""); err != nil {
		t.Fatal(err)
	}
	k := orm.New[schema.Key](h.db)
	k.Owner, k.Name, k.User = "acme", "eve-key", "hanzo/eve"
	k.SetId("acme/eve-key")
	if err := k.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	cy := h.token(t, "acme/cy")
	_, e := h.post(t, "/v1/iam/delete-membership", map[string]string{"user": "hanzo/eve", "org": "acme"}, cy)
	if e.Status == "ok" {
		kk, _ := orm.Get[schema.Key](h.db, "acme/eve-key")
		ws, _ := store.MembershipIn(ctx, h.db, "hanzo/eve", "acme", "ws1", "")
		t.Fatalf("ADMIN ACTED ON OWNER: admin cy's revoke of owner eve answered ok (space row left=%v, key left=%v)", ws != nil, kk != nil)
	}
}
