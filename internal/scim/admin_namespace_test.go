// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package scim_test

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/pkg/store"
)

// HIP-0527 §8 R5 for SCIM: the accounts an org admin and a SuperAdmin provision
// are measured, and a SuperAdmin provisioning into the admin org is the
// admits-admin violation (R7 row 7).
func TestAdminNamespace_scim(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	var found []string
	for _, c := range []struct{ sub, body, owner, name string }{
		{"hanzo/boss", `{"userName":"sally","emails":[{"value":"sally@hanzo.test"}]}`, "hanzo", "sally"},
		{"admin/root", `{"userName":"ivan","urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"hanzo","isAdmin":true}}`, "hanzo", "ivan"},
	} {
		if code, body := h.do(t, "POST", scimUsers, h.token(t, c.sub), c.body); code != 201 {
			t.Fatalf("%s provisions %s: %d %s", c.sub, c.name, code, body)
		}
		got, err := invariants.Created(ctx, h.db, c.owner, c.name, invariants.Expect{})
		if err != nil {
			t.Fatal(err)
		}
		found = append(found, got...)
	}
	h.do(t, "POST", scimUsers, h.token(t, "admin/root"),
		`{"userName":"intruder","urn:ietf:params:scim:schemas:extension:hanzo:2.0:User":{"owner":"admin"}}`)
	if u, _ := store.GetUserByName(ctx, h.db, "admin", "intruder"); u != nil {
		found = append(found, "admits-admin")
	}
	invariants.Report(t, "I19 scim", found)
}
