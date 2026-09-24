// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// An org's people, through the real router, when the person asking lives
// somewhere else. josh founded webby from a personal account: his account is
// josh/josh and webby knows him by an owner membership. alice lives in hanzo and
// belongs to webby as a member. bob has nothing to do with webby.

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func webbyFixtures(t *testing.T, h *harness) {
	t.Helper()
	ctx := context.Background()
	seedUser(t, h.db, "josh", "josh", true)
	seedUser(t, h.db, "webby", "deploy", false)
	for _, m := range []struct{ user, role string }{{"josh/josh", store.RoleOwner}, {"hanzo/alice", store.RoleMember}} {
		if _, err := store.EnsureMembership(ctx, h.db, m.user, "webby", m.role); err != nil {
			t.Fatalf("seed membership %s: %v", m.user, err)
		}
	}
	for _, owner := range []string{"webby", "orgb"} {
		inv := orm.New[schema.Invitation](h.db)
		inv.Owner, inv.Name, inv.Code = owner, "join-"+owner, "code-"+owner
		inv.SetId(owner + "/" + inv.Name)
		if err := inv.CreateCtx(ctx); err != nil {
			t.Fatalf("seed invitation: %v", err)
		}
	}
}

// put writes body to path as the signed-in sub.
func (h *harness) put(t *testing.T, sub, path, body string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("PUT", path, strings.NewReader(body))
	req.Host = "hanzo.id"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
	return h.do(t, req)
}

func TestAMemberReadsTheRosterOfAnOrgTheyJoined(t *testing.T) {
	h := newHarness(t)
	webbyFixtures(t, h)

	for _, sub := range []string{"josh/josh", "hanzo/alice"} {
		status, body := h.get(t, "/v1/iam/memberships?org=webby", h.token(t, sub))
		if status != 200 || !strings.Contains(body, `"josh/josh"`) || !strings.Contains(body, `"hanzo/alice"`) {
			t.Fatalf("%s could not read webby's roster: %d %s", sub, status, body)
		}
	}
	status, body := h.get(t, "/v1/iam/memberships?org=webby", h.token(t, "orgb/bob"))
	if status == 200 && strings.Contains(body, "josh/josh") {
		t.Fatalf("a stranger read webby's roster: %s", body)
	}
}

func TestAnOwnerByMembershipReadsTheOrgsInvitations(t *testing.T) {
	h := newHarness(t)
	webbyFixtures(t, h)
	josh := h.token(t, "josh/josh")

	status, body := h.get(t, "/v1/iam/invitations?owner=webby", josh)
	if status != 200 || !strings.Contains(body, "join-webby") {
		t.Fatalf("webby's owner could not read its invitations: %d %s", status, body)
	}
	if strings.Contains(body, "join-orgb") {
		t.Fatalf("webby's invitations carried another org's: %s", body)
	}
	for _, c := range []struct{ sub, path string }{
		{"hanzo/alice", "/v1/iam/invitations?owner=webby"}, // a member, not an admin
		{"orgb/bob", "/v1/iam/invitations?owner=webby"},    // a stranger
		{"josh/josh", "/v1/iam/invitations?owner=orgb"},    // an admin of webby, not of orgb
	} {
		if status, body := h.get(t, c.path, h.token(t, c.sub)); status != 403 {
			t.Fatalf("%s read %s: %d %s", c.sub, c.path, status, body)
		}
	}
}

func TestAnOwnerByMembershipAdministersTheOrgsPeople(t *testing.T) {
	h := newHarness(t)
	webbyFixtures(t, h)
	edit := `{"user":{"displayName":"Deploy (CI)"}}`

	if status, body := h.get(t, "/v1/iam/users?owner=webby", h.token(t, "josh/josh")); status != 200 || !strings.Contains(body, `"deploy"`) {
		t.Fatalf("webby's owner could not list its people: %d %s", status, body)
	}
	if status, body := h.put(t, "josh/josh", "/v1/iam/users/webby/deploy", edit); status != 200 {
		t.Fatalf("webby's owner could not edit its people: %d %s", status, body)
	}
	for _, c := range []struct{ sub, path string }{
		{"hanzo/alice", "/v1/iam/users/webby/deploy"}, // a member edits nobody
		{"josh/josh", "/v1/iam/users/orgb/bob"},       // webby's owner is not orgb's
		{"josh/josh", "/v1/iam/users/admin/root"},     // nor the platform's
	} {
		if status, body := h.put(t, c.sub, c.path, edit); status != 403 {
			t.Fatalf("%s wrote %s: %d %s", c.sub, c.path, status, body)
		}
	}
}

// A write names its org through Scope, and belonging is not enough to name one:
// alice, a plain member of webby, cannot provision a person into it, while
// webby's owner by membership can.
func TestAPlainMemberCannotWriteIntoAnOrgTheyBelongTo(t *testing.T) {
	h := newHarness(t)
	webbyFixtures(t, h)
	hire := func(name string) string {
		return `{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"` + name +
			`","urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"webby"}}`
	}
	post := func(sub, body string) (int, string) {
		req := httptest.NewRequest("POST", "/v1/iam/scim/v2/Users", strings.NewReader(body))
		req.Host = "hanzo.id"
		req.Header.Set("Content-Type", "application/scim+json")
		req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
		return h.do(t, req)
	}

	if status, body := post("hanzo/alice", hire("by-alice")); status != 403 {
		t.Fatalf("a plain member of webby provisioned into it: %d %s", status, body)
	}
	if u, err := store.GetUserByName(context.Background(), h.db, "webby", "by-alice"); err != nil || u != nil {
		t.Fatalf("the refused write left a row (%v, %v)", u, err)
	}
	if status, body := post("josh/josh", hire("by-josh")); status != 201 {
		t.Fatalf("webby's owner by membership could not provision into it: %d %s", status, body)
	}
}

// The rest of the combination: an admin of hanzo by membership passes hanzo's
// org-admin gate, and still reaches none of what is the SuperAdmin's — no key
// that speaks for them, no factor dropped, no passkey filed.
func TestAnAdminByMembershipReachesNothingOfTheSuperAdmin(t *testing.T) {
	h := newHarness(t)
	operatorFixtures(t, h)
	if _, err := store.EnsureMembership(context.Background(), h.db, "mallory/mallory", "hanzo", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	seedUser(t, h.db, "mallory", "mallory", false)
	mallory := h.person(t, "mallory/mallory")

	for _, r := range []struct{ method, path, body string }{
		{"POST", "/v1/iam/keys", `{"owner":"hanzo","name":"mk","user":"z"}`},
		{"POST", "/v1/iam/keys", `{"owner":"hanzo","name":"mk2","user":"hanzo/Z"}`},
		{"DELETE", "/v1/iam/mfa", `{"owner":"hanzo","name":"z"}`},
		{"POST", "/v1/iam/webauthn-credentials", `{"owner":"hanzo","name":"planted","user":"hanzo/z"}`},
		{"DELETE", "/v1/iam/users/hanzo/z", ""},
	} {
		if status, body := h.send(t, mallory, r.method, r.path, r.body); status != 403 {
			t.Errorf("hanzo's admin by membership: %s %s %s = %d %s", r.method, r.path, r.body, status, body)
		}
	}
	// ...while running hanzo's ordinary people, which is what the membership grants.
	if status, body := h.send(t, mallory, "PUT", "/v1/iam/users/hanzo/alice", `{"user":{"displayName":"Alice"}}`); status != 200 {
		t.Fatalf("hanzo's admin by membership could not edit alice: %d %s", status, body)
	}
}
