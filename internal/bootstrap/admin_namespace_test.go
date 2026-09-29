// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/invariants"
	"github.com/hanzoai/iam/internal/provision"
	"github.com/hanzoai/iam/internal/testhttp"
	"github.com/hanzoai/iam/pkg/store"
)

// HIP-0527 §8 R5 for the service-token upsert and for the declared accounts the
// provision document converges through it. A declaration naming the admin org is
// the admits-admin violation (R7 row 7).
func TestAdminNamespace_upsert(t *testing.T) {
	app, db := boot(t)
	ctx := context.Background()
	if code, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken,
		`{"owner":"acme","name":"ops","email":"ops@acme.test","isAdmin":true}`); code != 200 {
		t.Fatalf("upsert: %d %v", code, m)
	}
	found, err := invariants.Created(ctx, db, "acme", "ops", invariants.Expect{})
	if err != nil {
		t.Fatal(err)
	}
	post(t, app, "/v1/iam/admin/users/upsert", svcToken, `{"owner":"admin","name":"intruder"}`)
	if u, _ := store.GetUserByName(ctx, db, "admin", "intruder"); u != nil {
		found = append(found, "admits-admin")
	}
	invariants.Report(t, "I19 upsert", found)
}

// router carries a reconciler's requests to the served app in process.
type router struct{ app *zip.App }

func (r router) RoundTrip(req *http.Request) (*http.Response, error) { return testhttp.Do(r.app, req) }

func TestAdminNamespace_declared(t *testing.T) {
	app, db := boot(t)
	ctx := context.Background()
	rec := &provision.Reconciler{BaseURL: "https://hanzo.id", Token: svcToken, HTTP: &http.Client{Transport: router{app}}}
	for _, res := range rec.ApplyAccounts(ctx, []provision.OrgAccount{
		{Org: "acme", Account: provision.Account{Name: "ops", Type: provision.AccountOwner, Email: "ops@acme.test"}},
		{Org: "admin", Account: provision.Account{Name: "robot", Type: provision.AccountService}},
	}) {
		if res.Err != nil && res.Account.Org != "admin" {
			t.Fatalf("declare %s/%s: %v", res.Account.Org, res.Account.Account.Name, res.Err)
		}
	}
	found, err := invariants.Created(ctx, db, "acme", "ops", invariants.Expect{})
	if err != nil {
		t.Fatal(err)
	}
	if u, _ := store.GetUserByName(ctx, db, "admin", "robot"); u != nil {
		found = append(found, "admits-admin")
	}
	invariants.Report(t, "I19 declared", found)
}
