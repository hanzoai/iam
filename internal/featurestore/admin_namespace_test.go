// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package featurestore

import (
	"context"
	"testing"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/pkg/model"
	"github.com/hanzoai/iam/pkg/store"
)

// HIP-0527 §8 R5 for the enterprise modules' user seam: the account AddUser makes
// is measured, and an AddUser naming the admin org is the admits-admin violation
// (R7 row 7).
func TestAdminNamespace_enterprise(t *testing.T) {
	db, fs := openStore(t)
	ctx := context.Background()
	if _, err := fs.AddUser(ctx, &model.User{Owner: "hanzo", Name: "eve", Email: "eve@hanzo.test"}); err != nil {
		t.Fatal(err)
	}
	found, err := invariants.Created(ctx, db, "hanzo", "eve", invariants.Expect{})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fs.AddUser(ctx, &model.User{Owner: "admin", Name: "intruder"})
	if u, _ := store.GetUserByName(ctx, db, "admin", "intruder"); u != nil {
		found = append(found, "admits-admin")
	}
	invariants.Report(t, "I19 enterprise", found)
}
