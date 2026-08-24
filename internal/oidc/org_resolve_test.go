// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// A sign-in asks the organization what it demands: which algorithm verifies the
// password, and whether a second factor is owed. It asks by NAME — the name on the
// user's row — so a name has to resolve to one organization. It is the admin owner
// that makes it one: every organization is filed there, and the resolver reads
// there, so a row carrying the same name under any other owner answers for
// nothing.

import (
	"context"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// fileOrg writes an organization row verbatim, under whatever owner is named —
// the level below the create handler, which now files only under the registry
// owner. It is how a row that shares a tenant's name gets into the store at all.
func fileOrg(t *testing.T, db orm.DB, owner, name string, items []*schema.MfaItem) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = owner, name
	o.MfaItems = items
	o.SetId(owner + "/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("file %s/%s: %v", owner, name, err)
	}
}

// A row sharing an organization's name does not answer for it. The organization
// demands an authenticator; the row that shares its name demands nothing and is
// written FIRST, so a resolver that matched on the name alone would reach it
// first and let the sign-in finish with no second factor.
func TestLogin_ANameResolvesToTheOrganizationItNames(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw") // enrolled in no factor

	fileOrg(t, db, "acme", "hanzo", nil)                                                      // shares the name
	fileOrg(t, db, "admin", "hanzo", []*schema.MfaItem{{Name: factor.App, Rule: "Required"}}) // the organization

	// The resolver answers with the organization, and with its mandate.
	got, err := store.GetOrganizationByName(tctx(), db, "hanzo")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got == nil || got.Owner != "admin" {
		t.Fatalf("a name resolved to a row that only shares it: %+v", got)
	}
	if len(got.MfaItems) != 1 {
		t.Fatalf("the resolved organization lost its mandate: %+v", got.MfaItems)
	}

	// And the sign-in still owes the factor.
	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "alice", "password": "pw",
		"type": "code", "clientId": "hanzo-app",
	}))
	m := decode(t, body)
	if m["data"] != RequiredMfa {
		t.Fatalf("a row sharing the name answered for the organization: data = %#v, want %q — the mandated factor was skipped", m["data"], RequiredMfa)
	}
	if n := tokens(t, db); n != 0 {
		t.Fatalf("%d token row(s) persisted while a required factor was missing", n)
	}
}

// The positive control: with no row sharing the name, the organization answers
// exactly as before — the mandate holds and an organization with none does not
// invent one.
func TestLogin_TheOrganizationStillAnswersForItself(t *testing.T) {
	db := openTestDB(t)
	app := newApp(t, db)
	seedApp(t, db, appOpts{clientID: "hanzo-app", secret: "s3cret"})
	seedUser(t, db, "bob", "bob@hanzo.ai", "pw")

	fileOrg(t, db, "admin", "hanzo", nil) // no mandate

	_, body := do(t, app, jsonReq("POST", PathLogin, map[string]string{
		"organization": "hanzo", "username": "bob", "password": "pw",
		"type": "code", "clientId": "hanzo-app",
	}))
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("an ordinary sign-in was refused: %v", m["msg"])
	}
	if code, _ := m["data"].(string); code == "" || code == NextMfa || code == RequiredMfa {
		t.Fatalf("data = %q, want an authorization code", m["data"])
	}
}
