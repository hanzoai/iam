// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package bootstrap_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/provision"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func seedRow(t *testing.T, db orm.DB, owner, name, kind, hash string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Type, u.PasswordHash = owner, name, kind, hash
	if hash != "" {
		u.PasswordType = "argon2id"
	}
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func rowOf(t *testing.T, db orm.DB, owner, name string) *schema.User {
	t.Helper()
	u, err := store.GetUserByName(context.Background(), db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("%s/%s: %v", owner, name, err)
	}
	return u
}

// A declared machine is filed as one. The provision document declares
// admin/provisioner `type: service`; the upsert used to write it with no class,
// which read it as a person of the admin directory — a SuperAdmin.
func TestUpsert_filesTheDeclaredClass(t *testing.T) {
	app, db := boot(t)
	ctx := context.Background()
	rec := &provision.Reconciler{BaseURL: "https://hanzo.id", Token: svcToken, HTTP: &http.Client{Transport: router{app}}}
	seedRow(t, db, "admin", "provisioner", "", "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$aGFzaA")
	for _, res := range rec.ApplyAccounts(ctx, []provision.OrgAccount{
		{Org: "admin", Account: provision.Account{Name: "provisioner", Type: provision.AccountService}},
		{Org: "acme", Account: provision.Account{Name: "robot", Type: provision.AccountService}},
		{Org: "acme", Account: provision.Account{Name: "ops", Type: provision.AccountOwner, Email: "ops@acme.test"}},
	}) {
		if res.Err != nil {
			t.Fatalf("declare %s/%s: %v", res.Account.Org, res.Account.Account.Name, res.Err)
		}
	}
	if p := rowOf(t, db, "admin", "provisioner"); p.Type != schema.ServiceAccount || p.SuperAdmin() {
		t.Errorf("admin/provisioner is %q (SuperAdmin %v), want a machine", p.Type, p.SuperAdmin())
	}
	if r := rowOf(t, db, "acme", "robot"); r.Type != schema.ServiceAccount {
		t.Errorf("a declared service account was created as %q", r.Type)
	}
	if o := rowOf(t, db, "acme", "ops"); o.Type != "normal-user" {
		t.Errorf("a declared owner was created as %q", o.Type)
	}
}

// A declared machine converges again once it is classed; a key-minted agent,
// which holds no password, is still answered by name; and a declaration does not
// re-class an account.
func TestUpsert_classRules(t *testing.T) {
	app, db := boot(t)
	seedRow(t, db, "acme", "declared", schema.ServiceAccount, "$argon2id$v=19$m=65536,t=1,p=4$c2FsdA$aGFzaA")
	seedRow(t, db, "acme", "acme-agent", schema.ServiceAccount, "")
	seedRow(t, db, "acme", "person", "normal-user", "")
	for _, c := range []struct {
		body string
		want int
	}{
		{`{"owner":"acme","name":"declared","type":"service-account"}`, 200},
		{`{"owner":"acme","name":"acme-agent","type":"service-account","password":"a long password here"}`, 400},
		{`{"owner":"acme","name":"person","type":"service-account"}`, 400},
		{`{"owner":"acme","name":"newbie","type":"application"}`, 400},
	} {
		if code, m := post(t, app, "/v1/iam/admin/users/upsert", svcToken, c.body); code != c.want {
			t.Errorf("%s: %d %v, want %d", c.body, code, m, c.want)
		}
	}
	if rowOf(t, db, "acme", "person").Type != "normal-user" {
		t.Error("a declaration re-classed a person")
	}
}

// An application of the admin directory never takes a name an account there
// holds: that account would answer to the application's machine tokens.
func TestUpsertApplication_refusesAnAdminAccountsName(t *testing.T) {
	app, db := boot(t)
	seedRow(t, db, "admin", "ops", "normal-user", "")
	if code, m := post(t, app, "/v1/iam/admin/applications/upsert", svcToken,
		`{"organization":"hanzo","name":"ops","clientId":"ops","grantTypes":["client_credentials"]}`); code != 409 {
		t.Fatalf("an application named like admin/ops = %d %v, want 409", code, m)
	}
}
