// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keys

import (
	"context"
	"testing"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func presetOrg(t *testing.T, db orm.DB, name string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name, o.DisplayName = policy.AdminOrg, name, name
	o.SetId(policy.AdminOrg + "/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func presetClient(t *testing.T, db orm.DB, clientID, org string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.ClientId, a.Organization = policy.AdminOrg, clientID, clientID, org
	a.SetId(policy.AdminOrg + "/" + clientID)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

// Boot gives every tenant org its public application and the publishable key
// naming it, keeps an org's own application of that name as it is, skips the
// reserved orgs, names the org whose client id another org holds, and does
// nothing the second time.
func TestPresets(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	for _, o := range []string{"acme", "hanzo", "clash", policy.AdminOrg} {
		presetOrg(t, db, o)
	}
	presetClient(t, db, "hanzo-app", "hanzo")
	presetClient(t, db, "clash-app", "other")

	for boot := 0; boot < 2; boot++ {
		made, refused, err := Presets(ctx, db)
		if err != nil {
			t.Fatal(err)
		}
		if boot == 0 && (len(made) != 2 || made[0] != "acme" || made[1] != "hanzo") {
			t.Fatalf("boot 0 made %v, want [acme hanzo]", made)
		}
		if boot == 1 && len(made) != 0 {
			t.Fatalf("boot 1 made %v, want none", made)
		}
		if len(refused) != 1 {
			t.Fatalf("boot %d refused %v, want clash alone", boot, refused)
		}
	}
	acme, err := store.GetApplicationByClientId(ctx, db, "acme-app")
	if err != nil || acme == nil || acme.Organization != "acme" || acme.ClientSecret != "" || acme.IsShared || acme.EnableSignUp {
		t.Fatalf("acme-app = %+v (err=%v), want a public app confined to acme", acme, err)
	}
	for _, org := range []string{"acme", "hanzo"} {
		k, err := orm.Get[schema.Key](db, id(org, App(org)))
		if err != nil || k.Application != App(org) || schema.ClassOf(k.Scope) != schema.KeyScopePublish || k.AccessSecretDigest != "" {
			t.Fatalf("%s key = %+v (err=%v), want a publishable key naming %s", org, k, err, App(org))
		}
		got, err := store.PublishableKeyByAccessKey(ctx, db, k.AccessKey, time.Now())
		if err != nil || got.Owner != org {
			t.Fatalf("%s pk does not resolve: %v", org, err)
		}
	}
	if _, err := Preset(ctx, db, policy.AdminOrg, ""); err == nil {
		t.Fatal("the admin org was given a preset")
	}
}
