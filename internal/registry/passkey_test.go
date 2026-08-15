// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package registry

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// seedMembershipInAdmin puts an existing user in the reserved org — the way an
// operator is actually provisioned, and the reason skipping reserved org NAMES
// here is not the same rule as asking who the operator is.
func seedMembershipInAdmin(t *testing.T, db orm.DB, org, name string) {
	t.Helper()
	m := orm.New[schema.Membership](db)
	m.Owner = "admin"
	m.Name = "m-" + org + "-" + name
	m.User = org + "/" + name
	m.Org = "admin"
	m.Role = "admin"
	m.SetId("admin/m-" + org + "-" + name)
	if err := m.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
}

// A docker login with an operator's correct password resolves nobody.
//
// The loop this sits in already skips the reserved ORGS, and that is why the
// operator gets this far: they are anchored in "hanzo", which is a candidate org
// and not a reserved one. The password is right; a docker client simply has no way
// to present the credential this identity signs in with.
func TestRegistryPasswordResolvesNoOperator(t *testing.T) {
	db := openTestDB(t)
	h := &handler{db: db}
	seedUser(t, db, "hanzo", "z", "correct-horse", false)
	seedMembershipInAdmin(t, db, "hanzo", "z")

	if u := h.userByPassword(context.Background(), "z", "correct-horse"); u != nil {
		t.Fatalf("an operator's password resolved a registry identity: %s/%s", u.Owner, u.Name)
	}
}

// The control: the same call, the same org, an ordinary account — still resolves.
// Without this a broken resolver would look like a working rule.
func TestRegistryPasswordStillResolvesAnOrdinaryAccount(t *testing.T) {
	db := openTestDB(t)
	h := &handler{db: db}
	seedUser(t, db, "hanzo", "dana", "correct-horse", false)

	u := h.userByPassword(context.Background(), "dana", "correct-horse")
	if u == nil {
		t.Fatal("an ordinary account's password resolved nobody")
	}
	if u.Name != "dana" {
		t.Fatalf("resolved the wrong identity: %s/%s", u.Owner, u.Name)
	}
}
