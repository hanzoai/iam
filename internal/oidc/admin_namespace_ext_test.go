// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc_test

import (
	"context"
	"fmt"
	"testing"

	policy "github.com/hanzoai/authz"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// HIP-0527 §8 R5 for accepting an invitation with an account that already
// exists: the account gains the invitation's org and nothing else.
func TestAdminNamespace_invitationAccept(t *testing.T) {
	r := acceptRig(t)
	seedPerson(t, r.db, "hanzo", "ada", "ada@example.com", false)
	seedInvite(t, r.db, invite{owner: "acme", name: "link", code: "LINKCODE22", state: "Active", quota: 25})
	status, e := r.accept(t, r.as(t, "hanzo/ada"), `{"owner":"acme","code":"LINKCODE22"}`)
	if status != 200 || !e.Data.Joined {
		t.Fatalf("accept: %d %+v", status, e)
	}
	found, err := invariants.Created(context.Background(), r.db, "hanzo", "ada", invariants.Expect{Org: "acme"})
	if err != nil {
		t.Fatal(err)
	}
	invariants.Report(t, "I19 invitation-accept", found)
}

// R7 row 2 (I2), measured on IAM: a SuperAdmin's orgs names no org, and an assume
// leaves orgs as it was — the assumed org rides `assumed`, never a role.
func TestAdminNamespace_superAdminHoldsNoRole(t *testing.T) {
	r := newRig(t)
	ctx := context.Background()
	u, err := store.GetUserByName(ctx, r.db, policy.AdminOrg, "z")
	if err != nil || u == nil {
		t.Fatalf("admin/z: %v", err)
	}
	var found []string
	before := store.MemberOrgRefs(ctx, r.db, u)
	for _, ref := range before {
		if ref.Org == policy.AdminOrg {
			found = append(found, "orgs names admin for a SuperAdmin")
		} else {
			found = append(found, "orgs names an org for a SuperAdmin")
		}
	}
	status, body := r.post(t, assume, "admin/z", `{"org":"acme"}`)
	if status != 200 {
		t.Fatalf("assume: %d %s", status, body)
	}
	_, claims := answered(t, body)
	if fmt.Sprint(orgsOf(claims)) != fmt.Sprint(orgNames(before)) {
		found = append(found, "assume adds the assumed org to orgs")
	}
	invariants.Report(t, "I2", found)
}

func orgsOf(claims map[string]any) []string {
	var out []string
	list, _ := claims["orgs"].([]any)
	for _, x := range list {
		if m, ok := x.(map[string]any); ok {
			o, _ := m["org"].(string)
			out = append(out, o)
		}
	}
	return out
}

func orgNames(refs []schema.OrgRef) []string {
	var out []string
	for _, r := range refs {
		out = append(out, r.Org)
	}
	return out
}
