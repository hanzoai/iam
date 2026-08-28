// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// The broker links a social identity onto an existing local account only when
// that account's address was PROVEN, or when it carries no password anybody
// could already sign in with. Both halves of that decision read one bit, so the
// bit has to mean "the server watched a provider prove this address" and nothing
// else — in particular it must not mean "the request that created the row said
// so". These run the whole chain: the row is created through the same CRUD path
// an org admin reaches, and the broker then decides about it.

import (
	"errors"
	"testing"

	"github.com/hanzoai/iam/internal/users"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A create body cannot buy a link. An org admin writes a row on a colleague's
// address, with a password of their own choosing and the body asserting the
// address was proven; the person who actually holds the address then arrives
// with a verified identity. Adopting that row would leave both parties holding
// the account, so the create must not record the assertion and the broker must
// refuse.
func TestFederation_ACreateBodyCannotForgeTheProof(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID) // emailVerified: true, alice@example.com
	seedOIDCProvider(t, db, "webapp", m)

	// The request an org admin sends: POST /v1/iam/users, in its own org, naming
	// somebody else's address, stating the proof, choosing the password.
	if _, err := users.New(db).Create(tctx(), &users.CreateInput{
		User: schema.User{
			Owner: "hanzo", Name: "trap", Email: m.email,
			EmailVerified: true,
		},
		Password: "the sender's own passphrase",
	}); err != nil {
		t.Fatalf("create the trap row: %v", err)
	}
	trap := userRow(t, db, "trap")
	if trap.EmailVerified {
		t.Fatal("the create recorded a proof the request asserted")
	}
	if trap.PasswordHash == "" {
		t.Fatal("premise: the row must carry the sender's digest")
	}

	// The innermost decision, by identity: the address names an account nobody
	// proved, so the link is refused rather than resolved either way.
	app2, _ := store.GetApplicationByClientId(tctx(), db, "webapp")
	prov, _ := store.GetProvider(tctx(), db, "admin", fedProvGoogle)
	_, err := linkOrProvision(tctx(), db, app2, prov, federatedIdentity{
		subject: "google-sub-real-owner", email: m.email, emailVerified: true,
	})
	if !errors.Is(err, errAddressHeld) {
		t.Fatalf("linkOrProvision err = %v, want errAddressHeld", err)
	}

	// And the same refusal over the wire: no code is minted, nothing is linked,
	// the digest is untouched, and no second row appears on the one address.
	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()
	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-forged", cookie), testRedirect)
	qs := mustQuery(t, loc)
	if qs.Get("code") != "" {
		t.Fatalf("ACCOUNT TAKEOVER: a stated proof bought a code: %q", loc)
	}
	if qs.Get("error") != "access_denied" {
		t.Fatalf("error = %q, want access_denied: %q", qs.Get("error"), loc)
	}
	after := userRow(t, db, "trap")
	if after.Google != "" {
		t.Fatalf("the provider subject was linked onto the row: %q", after.Google)
	}
	if after.EmailVerified {
		t.Fatal("the address was marked proven by a party that did not prove it")
	}
	if after.PasswordHash != trap.PasswordHash {
		t.Fatal("the digest was rewritten; this refuses, it does not evict")
	}
	if countUsers(t, db) != before {
		t.Fatal("a second row was provisioned on an address one row already holds")
	}
}

// The positive control, and the half that would die silently. Refusing the body
// must not disarm the broker: a genuine federated provision still records the
// proof its provider gave, and that recorded proof is what lets the same person
// sign in later through a second identity on the same address instead of being
// refused. Without this, "never record it" would pass the test above.
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

	// The proof is load-bearing: a second identity on the same proven address
	// links onto the account rather than being refused or duplicated.
	before := countUsers(t, db)
	app2, _ := store.GetApplicationByClientId(tctx(), db, "webapp")
	prov, _ := store.GetProvider(tctx(), db, "admin", fedProvGoogle)
	linked, err := linkOrProvision(tctx(), db, app2, prov, federatedIdentity{
		subject: "google-sub-second-identity", email: m.email, emailVerified: true,
	})
	if err != nil {
		t.Fatalf("a proven address refused a second identity: %v", err)
	}
	if linked.Name != provisioned.Name {
		t.Fatalf("linked onto %q, want the existing account %q", linked.Name, provisioned.Name)
	}
	if countUsers(t, db) != before {
		t.Fatal("a second row was created on an address one account already proved")
	}
}
