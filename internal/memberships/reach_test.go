// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package memberships_test

// WHAT A PLAIN MEMBER CAN READ.
//
// A membership row says who may act where. Two questions reach it — an
// organization's roster, and one person's organizations — and they disclose
// different things, so they are measured separately here rather than assumed to
// be one answer.
//
// The roster of your own organization is the team you are on, and a member may
// read it. A PERSON's organizations is a different fact: it names the OTHER
// tenants that person works in, which is theirs and not their colleagues' to
// see. Only somebody who administers the account may ask it.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func seedMember(t *testing.T, db orm.DB, user, org, role string) {
	t.Helper()
	m := orm.New[schema.Membership](db)
	m.Owner, m.Name = store.AdminOrg, user+"|"+org
	m.User, m.Org, m.Role = user, org, role
	m.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	m.SetId(m.Owner + "/" + m.Name)
	if err := m.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

// The roster of the organization you are in is the team you are on.
func TestRoster_aMemberMayReadTheirOwnOrg(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "alice", false)
	seedMember(t, h.db, "hanzo/alice", "hanzo", store.RoleMember)
	seedMember(t, h.db, "hanzo/boss", "hanzo", store.RoleAdmin)

	status, body := h.read(t, "/v1/iam/memberships?org=hanzo", h.token(t, "hanzo/alice"))
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if !strings.Contains(body, "hanzo/alice") || !strings.Contains(body, "hanzo/boss") {
		t.Fatalf("the roster is missing somebody: %s", body)
	}
}

// ...and no other organization's.
func TestRoster_aMemberCannotReadAnotherOrg(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "alice", false)
	seedMember(t, h.db, "orgb/bob", "orgb", store.RoleAdmin)

	_, body := h.read(t, "/v1/iam/memberships?org=orgb", h.token(t, "hanzo/alice"))
	if strings.Contains(body, "orgb/bob") {
		t.Fatalf("a hanzo member read orgb's roster: %s", body)
	}
}

// WHICH ORGANIZATIONS A COLLEAGUE BELONGS TO IS NOT A COLLEAGUE'S TO READ.
//
// The answer names the other tenants that person works in. Anyone sharing their
// home organization could ask, because the gate bound the request to the home
// org of the NAMED user rather than to what the caller may know about them —
// which meant one colleague could enumerate another's employers.
func TestPersonOrgs_aMemberCannotReadAnother(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "alice", false)
	seedUser(t, h.db, "hanzo", "dave", false)
	seedMember(t, h.db, "hanzo/dave", "hanzo", store.RoleMember)
	seedMember(t, h.db, "hanzo/dave", "acme", store.RoleAdmin) // dave's other job

	_, body := h.read(t, "/v1/iam/memberships?user=hanzo/dave", h.token(t, "hanzo/alice"))
	if strings.Contains(body, "acme") {
		t.Fatalf("alice read which other organizations dave works in: %s", body)
	}
}

// Your own, always.
func TestPersonOrgs_aMemberReadsTheirOwn(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "alice", false)
	seedMember(t, h.db, "hanzo/alice", "hanzo", store.RoleMember)
	seedMember(t, h.db, "hanzo/alice", "acme", store.RoleMember)

	status, body := h.read(t, "/v1/iam/memberships?user=hanzo/alice", h.token(t, "hanzo/alice"))
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if !strings.Contains(body, "acme") {
		t.Fatalf("alice cannot see her own organizations: %s", body)
	}
}

// An admin of the account's organization may — that is the support path, and it
// is the same authority that governs reading the person's record.
func TestPersonOrgs_anOrgAdminMayReadTheirMember(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "dave", false)
	seedMember(t, h.db, "hanzo/dave", "hanzo", store.RoleMember)

	status, body := h.read(t, "/v1/iam/memberships?user=hanzo/dave", h.token(t, "hanzo/boss"))
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200", status, body)
	}
	if !strings.Contains(body, "hanzo/dave") {
		t.Fatalf("hanzo's admin cannot read their own member: %s", body)
	}
}

// An APPLICATION is bound to the tenant it serves, and that is unchanged. It is
// not a colleague — it is the tenant's own backend, and it is how a console
// renders an org switcher for the person signed into it. Narrowing it here would
// have broken that without closing anything: a machine credential is already
// confined to one tenant, and the leak above is between PEOPLE.
func TestPersonOrgs_anAppKeepsItsServedTenant(t *testing.T) {
	h := newHarness(t)
	seedUser(t, h.db, "hanzo", "dave", false)
	seedMember(t, h.db, "hanzo/dave", "hanzo", store.RoleMember)
	seedMember(t, h.db, "hanzo/dave", "acme", store.RoleAdmin)
	seedClientApp(t, h.db, "hanzo-console", "console-secret")

	status, body := h.readBasic(t, "/v1/iam/memberships?user=hanzo/dave", "hanzo-console", "console-secret")
	if status != 200 {
		t.Fatalf("status=%d body=%s, want 200 — the console must still resolve its own tenant's user", status, body)
	}
	if !strings.Contains(body, "hanzo/dave") {
		t.Fatalf("the app read nothing for its own tenant's user: %s", body)
	}

	// ...and still only its own tenant.
	seedUser(t, h.db, "orgb", "erin", false)
	seedMember(t, h.db, "orgb/erin", "orgb", store.RoleMember)
	_, foreign := h.readBasic(t, "/v1/iam/memberships?user=orgb/erin", "hanzo-console", "console-secret")
	if strings.Contains(foreign, "orgb/erin") {
		t.Fatalf("the app reached another tenant: %s", foreign)
	}
}
