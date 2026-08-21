// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

import (
	"encoding/json"
	"io"
	"net/http/httptest"
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/schema"
)

// listOrganizations answers the same question Search does — "which organizations
// may I see" — so it is held to the same three facts, and it is held here because
// it was not.
//
// It read no principal and treated an absent Owner selector as no filter, so a
// request with no credential was answered with the registry. It was reachable
// that way in production through the agent door, which carries a typed op to its
// handler without the edge in front of it: 670 organizations to an anonymous
// caller.
//
// The tests below are the ones whose absence let that ship. Search has each of
// them already; the endpoint beside it had none.

const listPath = "/v1/iam/organizations"

type listPage struct {
	Organizations []*schema.Organization `json:"organizations"`
	Count         int                    `json:"count"`
}

// list drives one read as sub. An empty sub sends no credential at all.
func (h *harness) list(t *testing.T, sub, query string) (int, listPage, string) {
	t.Helper()
	req := httptest.NewRequest("GET", listPath+query, nil)
	req.Host = "hanzo.id"
	if sub != "" {
		req.Header.Set("Authorization", "Bearer "+h.token(t, sub))
	}
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("GET %s: %v", query, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	var p listPage
	if resp.StatusCode == 200 {
		if err := json.Unmarshal(b, &p); err != nil {
			t.Fatalf("decode %s: %v", b, err)
		}
	}
	return resp.StatusCode, p, string(b)
}

// The regression itself: no credential, no answer. This is the exact request
// that returned the registry.
func TestList_unauthenticated(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "", "")
	if status == 200 {
		t.Fatalf("an unauthenticated request listed %d organizations: %s", len(p.Organizations), body)
	}
}

// A person who is not a platform operator is refused, whichever door they came
// through. Search is where "the organizations I can act in" is answered.
func TestList_aPersonIsRefused(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "hanzo/boss", "")
	if status == 200 {
		t.Fatalf("a tenant admin listed %d organizations: %s", len(p.Organizations), body)
	}
}

// Administering a tenant is not operating the platform — the two admin scopes
// are different facts and conflating them is the privilege escalation.
func TestList_aRegularMemberIsRefused(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "hanzo/nobody", "")
	if status == 200 {
		t.Fatalf("a regular member listed %d organizations: %s", len(p.Organizations), body)
	}
}

// The selector is not a way in. Naming a parent account does not make the read
// someone else's to do.
func TestList_theSelectorIsNotAWayIn(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "hanzo/boss", "?owner="+policy.AdminOrg)
	if status == 200 {
		t.Fatalf("naming an owner listed %d organizations: %s", len(p.Organizations), body)
	}
}

// A platform operator still sees every organization: this endpoint is how the
// operator surfaces enumerate tenants, and narrowing it for them would move the
// leak into a second endpoint rather than close it.
func TestList_anOperatorSeesEveryOrganization(t *testing.T) {
	h := newHarness(t)
	seedMany(t, h.db, 5)

	status, p, body := h.list(t, "admin/root", "")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if len(p.Organizations) < 5 {
		t.Fatalf("an operator saw %d organizations, want every one", len(p.Organizations))
	}
}
