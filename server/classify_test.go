// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package server_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	iamstore "github.com/hanzoai/iam/pkg/store"
	"github.com/hanzoai/iam/server"
)

// The boot step every host runs classes the admin directory's people first, even
// when the rest of the seed has nothing to read.
func TestSeed_classesTheAdminDirectoryFirst(t *testing.T) {
	db, err := iamstore.Open("sqlite", filepath.Join(t.TempDir(), "iam.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = "admin", "woo", "woo@hanzo.test"
	u.SetId("admin/woo")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, _ = server.Seed(context.Background(), db, filepath.Join(t.TempDir(), "absent.json"))
	got, err := iamstore.GetUserByName(context.Background(), db, "admin", "woo")
	if err != nil || got == nil {
		t.Fatalf("admin/woo: %v", err)
	}
	if got.Type != "normal-user" {
		t.Fatalf("admin/woo is %q after the boot step, want normal-user", got.Type)
	}
}
