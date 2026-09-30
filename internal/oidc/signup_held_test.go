// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"fmt"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A sign-up whose handle is a held name founds the next free variant of it, and
// never leaves the account in the application's own org. The walk and provision
// ask one question, so a name the walk calls free is one provision founds.
func TestSignup_heldHandleNeverStrandsTheAccount(t *testing.T) {
	ctx := context.Background()
	db, app, prov, binding := federatedApp(t)

	if free, err := orgSlugFree(ctx, db, "hanzoai"); err != nil || free {
		t.Fatalf("orgSlugFree(hanzoai) = %v %v, want held", free, err)
	}
	id := federatedIdentity{subject: "idp-red", email: "hanzoai@example.com", emailVerified: true}
	u, err := provisionFederatedUser(ctx, db, app, prov, binding, id)
	if err != nil {
		t.Fatalf("sign-in: %v", err)
	}
	if u.Owner == "hanzo" || u.Owner == "hanzoai" {
		t.Fatalf("account lives in %q", u.Owner)
	}
	if left, _ := store.GetUserByName(ctx, db, "hanzo", "hanzoai"); left != nil {
		t.Fatal("an account was left in the brand org")
	}
}

// When founding the account's org fails, the account the sign-up just made is
// removed: an account that stayed would live in the application's org, a member of
// whichever tenant that application belongs to.
func TestSignup_failedFoundingRemovesTheAccount(t *testing.T) {
	ctx := context.Background()
	db, app, prov, binding := federatedApp(t)
	for i := 1; i <= nameAttempts; i++ {
		slug := "zed"
		if i > 1 {
			slug = fmt.Sprintf("zed%d", i)
		}
		o := orm.New[schema.Organization](db)
		o.Owner, o.Name = "admin", slug
		o.SetId("admin/" + slug)
		if err := o.CreateCtx(ctx); err != nil {
			t.Fatal(err)
		}
	}
	id := federatedIdentity{subject: "idp-zed", email: "zed@example.com", emailVerified: true}
	if _, err := provisionFederatedUser(ctx, db, app, prov, binding, id); err == nil {
		t.Fatal("founding cannot succeed when every name is taken")
	}
	if left, _ := store.GetUserByName(ctx, db, "hanzo", "zed"); left != nil {
		t.Fatal("the account outlived the failed founding")
	}
}
