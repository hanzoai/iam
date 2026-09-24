// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// A SuperAdmin's account is written only by a SuperAdmin, through the real
// router. The operator here is hanzo/z: anchored in a brand org, made an
// operator by a membership in the reserved one — which is how operators are
// actually made, and why hanzo's own admin and any application allowed to
// administer hanzo's users were both able to reach them.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

const visorSecret = "visor-secret"

// operatorFixtures seeds hanzo/z as a SuperAdmin and hanzo-visor as an
// application holding the user-admin and org-admin capabilities.
func operatorFixtures(t *testing.T, h *harness) {
	t.Helper()
	t.Setenv("IAM_USER_ADMIN_APPS", "hanzo-visor")
	t.Setenv("IAM_ORG_ADMIN_APPS", "hanzo-visor")
	seedClientApp(t, h.db, "hanzo-visor", visorSecret)
	seedUser(t, h.db, "hanzo", "z", false)
	if _, err := store.EnsureMembership(context.Background(), h.db, "hanzo/z", "admin", store.RoleMember); err != nil {
		t.Fatalf("seed operator membership: %v", err)
	}
	if super, err := store.IsSuperAdmin(context.Background(), h.db, "hanzo", "z"); err != nil || !super {
		t.Fatalf("hanzo/z is not a SuperAdmin (%v, %v)", super, err)
	}
}

type caller func(*http.Request)

func (h *harness) person(t *testing.T, sub string) caller {
	tok := h.token(t, sub)
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func visor(r *http.Request) { r.SetBasicAuth("hanzo-visor", visorSecret) }

// send issues one request with a JSON body as who.
func (h *harness) send(t *testing.T, who caller, method, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	who(req)
	return h.do(t, req)
}

// digest is the stored password digest of owner/name; "" when the row is gone.
func digest(t *testing.T, h *harness, owner, name string) string {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), h.db, owner, name)
	if err != nil {
		t.Fatalf("read %s/%s: %v", owner, name, err)
	}
	if u == nil {
		return ""
	}
	return u.PasswordHash
}

const reset = `{"user":{"email":"taken@evil.test","phone":"+15550100"},"password":"a whole new password"}`

func TestAnAppWithUserAdminCannotWriteASuperAdmin(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)

	for _, path := range []string{"/v1/iam/users/hanzo/z", "/v1/iam/users/hanzo/Z"} {
		if status, body := h.send(t, visor, "PUT", path, reset); status != 403 {
			t.Fatalf("PUT %s as hanzo-visor answered %d: %s", path, status, body)
		}
	}
	if got := digest(t, h, "hanzo", "z"); got != secretUserHash {
		t.Fatalf("the operator's password changed under a refusal: %q", got)
	}
	if status, body := h.send(t, visor, "DELETE", "/v1/iam/users/hanzo/z", ""); status != 403 {
		t.Fatalf("DELETE hanzo/z as hanzo-visor answered %d: %s", status, body)
	}
	if digest(t, h, "hanzo", "z") == "" {
		t.Fatal("the operator's account was deleted under a refusal")
	}

	// The same application still administers everyone else.
	if status, body := h.send(t, visor, "PUT", "/v1/iam/users/hanzo/alice", reset); status != 200 {
		t.Fatalf("PUT hanzo/alice as hanzo-visor answered %d: %s", status, body)
	}
	if got := digest(t, h, "hanzo", "alice"); got == secretUserHash {
		t.Fatal("hanzo-visor's reset of a normal user did not land")
	}
	if status, body := h.send(t, visor, "DELETE", "/v1/iam/users/hanzo/alice", ""); status != 200 {
		t.Fatalf("DELETE hanzo/alice as hanzo-visor answered %d: %s", status, body)
	}
}

func TestAnOrgAdminCannotWriteItsSuperAdmin(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	boss := h.person(t, "hanzo/boss")

	if status, body := h.send(t, boss, "PUT", "/v1/iam/users/hanzo/z", reset); status != 403 {
		t.Fatalf("hanzo's admin reset the operator: %d %s", status, body)
	}
	if status, body := h.send(t, boss, "DELETE", "/v1/iam/users/hanzo/z", ""); status != 403 {
		t.Fatalf("hanzo's admin deleted the operator: %d %s", status, body)
	}
	if got := digest(t, h, "hanzo", "z"); got != secretUserHash {
		t.Fatalf("the operator's password changed under a refusal: %q", got)
	}
	if status, body := h.send(t, boss, "PUT", "/v1/iam/users/hanzo/alice", reset); status != 200 {
		t.Fatalf("hanzo's admin could not reset a member: %d %s", status, body)
	}
}

func TestASuperAdminWritesASuperAdmin(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)

	for _, sub := range []string{"admin/root", "hanzo/z"} {
		before := digest(t, h, "hanzo", "z")
		if status, body := h.send(t, h.person(t, sub), "PUT", "/v1/iam/users/hanzo/z", reset); status != 200 {
			t.Fatalf("%s could not reset the operator: %d %s", sub, status, body)
		}
		if digest(t, h, "hanzo", "z") == before {
			t.Fatalf("%s's reset of the operator did not land", sub)
		}
	}
}

func TestASuperAdminsFactorsAndCredentialsAreTheirs(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	boss := h.person(t, "hanzo/boss")

	for _, who := range []struct {
		name string
		c    caller
	}{{"hanzo-visor", visor}, {"hanzo/boss", boss}} {
		if status, body := h.send(t, who.c, "DELETE", "/v1/iam/mfa", `{"owner":"hanzo","name":"z"}`); status != 403 {
			t.Fatalf("%s dropped the operator's second factor: %d %s", who.name, status, body)
		}
		if status, body := h.send(t, who.c, "POST", "/v1/iam/mfa/setup/initiate", `{"owner":"hanzo","name":"z"}`); status != 403 {
			t.Fatalf("%s enrolled a factor on the operator: %d %s", who.name, status, body)
		}
	}
	if status, body := h.send(t, boss, "DELETE", "/v1/iam/mfa", `{"owner":"hanzo","name":"alice"}`); status != 200 {
		t.Fatalf("hanzo's admin could not manage a member's factors: %d %s", status, body)
	}

	if status, body := h.send(t, boss, "POST", "/v1/iam/webauthn-credentials",
		`{"owner":"hanzo","name":"planted","user":"hanzo/z"}`); status != 403 {
		t.Fatalf("hanzo's admin filed a passkey for the operator: %d %s", status, body)
	}
	if status, body := h.send(t, boss, "POST", "/v1/iam/webauthn-credentials",
		`{"owner":"hanzo","name":"member","user":"hanzo/alice"}`); status != 200 {
		t.Fatalf("hanzo's admin could not file a member's passkey: %d %s", status, body)
	}

	patch := `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"replace","path":"password","value":"a whole new password"}]}`
	if status, body := h.send(t, visor, "PATCH", "/v1/iam/scim/v2/Users/hanzo/z", patch); status != 403 {
		t.Fatalf("SCIM as hanzo-visor reset the operator: %d %s", status, body)
	}
	if got := digest(t, h, "hanzo", "z"); got != secretUserHash {
		t.Fatalf("the operator's password changed under a refusal: %q", got)
	}
}

func TestASuperAdminsMembershipsAreTheirs(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	bob := h.person(t, "orgb/bob")
	refused := func(status int, body string) bool { return status == 403 || strings.Contains(body, `"status":"error"`) }

	if status, body := h.send(t, bob, "POST", "/v1/iam/memberships", `{"user":"hanzo/z","org":"orgb"}`); !refused(status, body) {
		t.Fatalf("orgb's admin added the operator: %d %s", status, body)
	}
	if status, body := h.send(t, h.person(t, "admin/root"), "POST", "/v1/iam/memberships", `{"user":"hanzo/z","org":"orgb"}`); refused(status, body) {
		t.Fatalf("a SuperAdmin could not add the operator: %d %s", status, body)
	}
	if status, body := h.send(t, bob, "POST", "/v1/iam/delete-membership", `{"user":"hanzo/z","org":"orgb"}`); !refused(status, body) {
		t.Fatalf("orgb's admin removed the operator: %d %s", status, body)
	}
	if m, err := store.MembershipIn(context.Background(), h.db, "hanzo/z", "orgb", "", ""); err != nil || m == nil {
		t.Fatalf("the operator's membership did not survive the refusal (%v, %v)", m, err)
	}

	if status, body := h.send(t, bob, "POST", "/v1/iam/memberships", `{"user":"hanzo/alice","org":"orgb"}`); refused(status, body) {
		t.Fatalf("orgb's admin could not add a member: %d %s", status, body)
	}
	if status, body := h.send(t, bob, "POST", "/v1/iam/delete-membership", `{"user":"hanzo/alice","org":"orgb"}`); refused(status, body) {
		t.Fatalf("orgb's admin could not remove a member: %d %s", status, body)
	}
}
