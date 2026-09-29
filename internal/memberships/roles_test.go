// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package memberships_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// send drives one request with a bearer through the real router.
func (h *harness) send(t *testing.T, method, path string, body any, bearer string) (int, env) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearer)
	return h.do(t, req)
}

// acme: ann owns it, cy is its admin by her account, dee is a member of it; eve
// lives in hanzo.
func acme(t *testing.T, h *harness) {
	t.Helper()
	ctx := context.Background()
	o := orm.New[schema.Organization](h.db)
	o.Owner, o.Name = "admin", "acme"
	o.SetId("admin/acme")
	if err := o.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedUser(t, h.db, "acme", "ann", false)
	seedUser(t, h.db, "acme", "cy", true)
	seedUser(t, h.db, "acme", "dee", false)
	seedUser(t, h.db, "hanzo", "eve", false)
	if _, err := store.SetRole(ctx, h.db, "acme/ann", "acme", store.RoleOwner); err != nil {
		t.Fatal(err)
	}
}

func role(t *testing.T, h *harness, user, org string) string {
	t.Helper()
	m, err := store.MembershipIn(context.Background(), h.db, user, org, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if m == nil {
		return ""
	}
	return m.Role
}

func ok(e env) bool { return e.Status == "ok" }

// Owner > admin > member. An admin runs members and admins; the owner role is
// given, taken and handed over only by an owner or a SuperAdmin; the last owner
// never leaves; and every change is on the audit trail.
func TestOrgRoles(t *testing.T) {
	h := newHarness(t)
	acme(t, h)
	ann, cy, root := h.token(t, "acme/ann"), h.token(t, "acme/cy"), h.token(t, "admin/root")
	grant := func(tok, user, r string) env {
		_, e := h.post(t, "/v1/iam/memberships", map[string]string{"user": user, "org": "acme", "role": r}, tok)
		return e
	}
	set := func(tok, user, r string) env {
		_, e := h.send(t, "PUT", "/v1/iam/memberships", map[string]string{"user": user, "org": "acme", "role": r}, tok)
		return e
	}
	remove := func(tok, user string) env {
		_, e := h.post(t, "/v1/iam/delete-membership", map[string]string{"user": user, "org": "acme"}, tok)
		return e
	}

	if e := grant(cy, "hanzo/eve", store.RoleOwner); ok(e) {
		t.Fatalf("an admin made an owner: %+v", e)
	}
	if e := grant(cy, "hanzo/eve", store.RoleMember); !ok(e) {
		t.Fatalf("an admin could not add a member: %+v", e)
	}
	if e := set(cy, "hanzo/eve", store.RoleAdmin); !ok(e) || role(t, h, "hanzo/eve", "acme") != store.RoleAdmin {
		t.Fatalf("an admin could not make a member an admin: %+v", e)
	}
	if e := set(cy, "hanzo/eve", store.RoleOwner); ok(e) {
		t.Fatalf("an admin promoted someone to owner: %+v", e)
	}
	if e := set(cy, "acme/ann", store.RoleMember); ok(e) || role(t, h, "acme/ann", "acme") != store.RoleOwner {
		t.Fatalf("an admin demoted the owner: %+v", e)
	}
	if e := remove(cy, "acme/ann"); ok(e) {
		t.Fatalf("an admin removed the owner: %+v", e)
	}

	// Handing acme over: ann makes eve an owner, then steps down.
	if e := set(ann, "hanzo/eve", store.RoleOwner); !ok(e) {
		t.Fatalf("the owner could not make an owner: %+v", e)
	}
	if e := set(ann, "acme/ann", store.RoleAdmin); !ok(e) || role(t, h, "acme/ann", "acme") != store.RoleAdmin {
		t.Fatalf("the owner could not step down beside another owner: %+v", e)
	}
	eve := h.token(t, "hanzo/eve")
	if e := set(eve, "hanzo/eve", store.RoleMember); ok(e) || e.Msg != store.ErrLastOwner.Error() {
		t.Fatalf("the last owner stepped down: %+v", e)
	}
	if e := remove(eve, "hanzo/eve"); ok(e) || e.Msg != store.ErrLastOwner.Error() {
		t.Fatalf("the last owner left: %+v", e)
	}
	if role(t, h, "hanzo/eve", "acme") != store.RoleOwner {
		t.Fatal("the last owner's row changed")
	}

	// A SuperAdmin moves the owner role like an owner does.
	if e := set(root, "acme/dee", store.RoleOwner); !ok(e) {
		t.Fatalf("a SuperAdmin could not make an owner: %+v", e)
	}
	if e := remove(eve, "hanzo/eve"); !ok(e) {
		t.Fatalf("an owner beside another could not leave: %+v", e)
	}

	n, err := orm.TypedQuery[schema.AuditLog](h.db).Filter("Action=", schema.ActionOrgRole).Filter("Organization=", "acme").Count(context.Background())
	if err != nil || n != 6 {
		t.Fatalf("organization-role rows = %d (err=%v), want 6: eve added, made admin, made owner; ann stepped down; dee made owner; eve left", n, err)
	}
}

// An application that administers orgs for the platform adds members, and never
// gives the owner role: a machine owns nothing.
func TestAnApplicationGivesNoOwnerRole(t *testing.T) {
	h := newHarness(t)
	acme(t, h)
	seedClientApp(t, h.db, "hanzo-console", "console-secret")
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-console")
	if _, e := h.postBasic(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/eve", "org": "acme", "role": "owner"}, "hanzo-console", "console-secret"); ok(e) {
		t.Fatalf("an application gave the owner role: %+v", e)
	}
	if _, e := h.postBasic(t, "/v1/iam/memberships",
		map[string]string{"user": "hanzo/eve", "org": "acme", "role": "member"}, "hanzo-console", "console-secret"); !ok(e) {
		t.Fatalf("an application could not add a member: %+v", e)
	}
}

// Only an owner deletes an org; its admin does not, and the delete is recorded.
func TestOnlyAnOwnerDeletesAnOrg(t *testing.T) {
	h := newHarness(t)
	acme(t, h)
	if status, _ := h.send(t, "DELETE", "/v1/iam/organizations/admin/acme", nil, h.token(t, "acme/cy")); status != 403 {
		t.Fatalf("the admin's delete answered %d, want 403", status)
	}
	if o, _ := store.GetOrganizationByName(context.Background(), h.db, "acme"); o == nil {
		t.Fatal("the admin deleted the org")
	}
	if status, _ := h.send(t, "DELETE", "/v1/iam/organizations/admin/acme", nil, h.token(t, "acme/ann")); status != 200 {
		t.Fatalf("the owner's delete answered %d, want 200", status)
	}
	n, err := orm.TypedQuery[schema.AuditLog](h.db).Filter("Action=", schema.ActionOrgDelete).Filter("Organization=", "acme").Count(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("organization-delete rows = %d (err=%v), want 1", n, err)
	}
}

// A space's owner is not its org's: a workspace row admits its holder to the org
// as a member and administers nothing there.
func TestASpaceOwnerDoesNotRunTheOrg(t *testing.T) {
	h := newHarness(t)
	acme(t, h)
	if _, err := store.EnsureMembershipIn(context.Background(), h.db, "hanzo/eve", "acme", "ws1", "", store.RoleOwner); err != nil {
		t.Fatal(err)
	}
	eve := h.token(t, "hanzo/eve")
	if _, e := h.post(t, "/v1/iam/memberships", map[string]string{"user": "acme/dee", "org": "acme", "role": "admin"}, eve); ok(e) {
		t.Fatalf("a space owner granted an org role: %+v", e)
	}
	if status, _ := h.send(t, "DELETE", "/v1/iam/organizations/admin/acme", nil, eve); status != 403 {
		t.Fatalf("a space owner's org delete answered %d, want 403", status)
	}
}
