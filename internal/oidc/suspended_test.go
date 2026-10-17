// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func suspend(t *testing.T, db orm.DB, id string) {
	t.Helper()
	u, err := orm.Get[schema.User](db, id)
	if err != nil {
		t.Fatal(err)
	}
	u.IsForbidden = true
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// A session outlives the suspension that ends its account, so the account is
// read on every call: a suspended person's live cookie founds no org and writes
// nothing, and neither does their bearer.
func TestAccount_aSuspendedAccountIsNobody(t *testing.T) {
	app, db := newServer(t)
	ctx := context.Background()
	twoApps(t, db)
	cookie := signInOn(t, app, "", "alice")
	_, value, _ := strings.Cut(cookie, "=")
	if owner, name, ok := callerFrom(ctx, db, value, ""); !ok || owner+"/"+name != "hanzo/alice" {
		t.Fatalf("alice's session resolved %s/%s %v", owner, name, ok)
	}

	suspend(t, db, "hanzo/alice")
	if owner, name, ok := callerFrom(ctx, db, value, ""); ok {
		t.Fatalf("a suspended account's session resolved %s/%s", owner, name)
	}
	req := jsonReq("POST", PathOnboard, map[string]any{"name": "Founded Suspended"})
	req.Header.Set("Cookie", cookie)
	if resp, raw := do(t, app, req); resp.StatusCode != 401 {
		t.Fatalf("a suspended account founding an org: %d %s, want 401", resp.StatusCode, raw)
	}
	if org, _ := store.GetOrganizationByName(ctx, db, "founded-suspended"); org != nil {
		t.Fatalf("a suspended account founded %+v", org)
	}
}

// A delegated token acts only where its subject is a tenant: a plain member of a
// brand org is no tenant of it, so no run is delegated there.
func TestDelegate_aPlainMemberIsNotDelegatedIntoABrandOrg(t *testing.T) {
	app, _ := delegationServer(t)
	if status, tok := delegated(t, app, url.Values{"org": {"hanzo"}}); status != 403 {
		t.Fatalf("a delegation into the brand org for a plain member: %d %v", status, tok)
	}
}

// groups carries the orgs a person is a tenant of: a directory and a brand org
// held as a plain member are none, and a relying party that maps groups onto
// access must not see them. A machine's grants are carried whole.
func TestSign_GroupsLeaveOutWhatMakesNoTenant(t *testing.T) {
	person := []schema.OrgRef{{Org: "hanzo-id", Role: "member"}, {Org: "alice", Role: "owner"}, {Org: "hanzo", Role: "member"}, {Org: "lux", Role: "admin"}}
	if got := strings.Join(groupsOf(person, ""), ","); got != "alice,lux" {
		t.Fatalf("groups = %s, want alice,lux", got)
	}
	machine := []schema.OrgRef{{Org: "hanzo", Role: "member"}}
	if got := strings.Join(groupsOf(machine, schema.Program), ","); got != "hanzo" {
		t.Fatalf("machine groups = %s, want hanzo", got)
	}
}
