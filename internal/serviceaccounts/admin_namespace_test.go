// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package serviceaccounts_test

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/pkg/store"
)

// HIP-0527 §8 R5 for service accounts: the program an org admin creates is
// expected to act in exactly that org, and a SuperAdmin creating one in the admin
// org is the admits-admin violation (R7 row 7).
func TestAdminNamespace_serviceAccount(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if code, body := h.send(t, "POST", "/v1/iam/service-accounts", `{"organization":"hanzo","name":"deployer"}`, h.token(t, "hanzo/boss")); code != 200 {
		t.Fatalf("create: %d %s", code, body)
	}
	found, err := invariants.Created(ctx, h.db, "hanzo", "hanzo-deployer", invariants.Expect{Program: true, Org: "hanzo"})
	if err != nil {
		t.Fatal(err)
	}
	h.send(t, "POST", "/v1/iam/service-accounts", `{"organization":"admin","name":"robot"}`, h.token(t, "admin/root"))
	if u, _ := store.GetUserByName(ctx, h.db, "admin", "admin-robot"); u != nil {
		found = append(found, "admits-admin")
	}
	invariants.Report(t, "I19 service-account", found)
}
