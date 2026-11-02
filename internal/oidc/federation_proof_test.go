// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// A federated provision records the address proof its provider gave, on the
// create's own field (users.CreateInput.EmailVerified), and a second identity on
// that verified address signs in to the same account.

import (
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A genuine federated provision records the proof its provider gave and carries
// no password, and another provider's identity on the same verified address
// resolves to the account rather than being refused or duplicated.
func TestFederation_ProvisionRecordsTheProviderProof(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	runOIDCLogin(t, app, db, m, "webapp", nil)

	provisioned, err := store.GetUserByEmail(tctx(), db, "hanzo", m.email)
	if err != nil || provisioned == nil {
		t.Fatalf("read back the provisioned account: %v", err)
	}
	if !provisioned.EmailVerified {
		t.Fatal("the provider proved the address and the row does not say so")
	}
	if provisioned.PasswordHash != "" {
		t.Fatal("a federated account must carry no password")
	}

	before := countUsers(t, db)
	app2, _ := store.GetApplicationByClientId(tctx(), db, "webapp")
	prov, _ := store.GetProvider(tctx(), db, "admin", fedProvGoogle)
	github := &schema.Provider{Type: "GitHub"}
	github.Owner, github.Name = prov.Owner, "github"
	linked, link, err := linkOrProvision(tctx(), db, app2, github, federatedIdentity{
		subject: "github-sub-second-identity", email: m.email, emailVerified: true,
	})
	if err != nil {
		t.Fatalf("a verified address refused a second identity: %v", err)
	}
	if linked.Name != provisioned.Name || link == nil {
		t.Fatalf("linked onto %q (link %+v), want the existing account %q", linked.Name, link, provisioned.Name)
	}
	if countUsers(t, db) != before {
		t.Fatal("a second row was created on an address one account already holds")
	}
}
