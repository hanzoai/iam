// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/store"
)

// What a federated sign-in may CREATE.

// An application with registration switched off does not get new accounts created
// by a social provider either. The switch is the tenant's, and it used to mean one
// thing at the password and wallet doors and nothing at all at this one.
func TestFederation_ProvisioningHonoursTheSignupSwitch(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}}) // signup OFF
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	loc := requireRedirect(t, callback(t, app, q.Get("state"), "idp-code-1", cookie), testRedirect)
	cb := mustQuery(t, loc)
	if cb.Get("code") != "" {
		t.Fatalf("registration is off, yet federation minted a code: %q", loc)
	}
	if cb.Get("error") != "access_denied" {
		t.Fatalf("want access_denied, got %q (%q)", cb.Get("error"), cb.Get("error_description"))
	}
	if countUsers(t, db) != before {
		t.Fatal("a social sign-in created an account on an application that is closed to registration")
	}
}

// An existing account still signs in through that same closed application: the
// switch governs REGISTRATION, not sign-in, so turning it off must not lock out the
// people who already have accounts.
func TestFederation_SignupSwitchDoesNotBlockAnExistingAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", redirectURIs: []string{testRedirect}}) // signup OFF
	m := newMockOIDC(t, fedGoogleCID)
	seedUser(t, db, "alice", m.email, "pw")
	// The link law needs proof on BOTH sides of the address (linkOrProvision): a row
	// with a password and an UNPROVEN address is refused, whatever this switch says.
	// So prove the local side, which leaves the registration switch as the only
	// thing under test.
	verifyEmail(t, db, "alice")
	seedOIDCProvider(t, db, "webapp", m)

	runOIDCLogin(t, app, db, m, "webapp", nil)
	u, err := store.GetUserByConnector(tctx(), db, "hanzo", "google", m.sub)
	if err != nil || u == nil || u.Name != "alice" {
		t.Fatalf("the existing account must still sign in and be linked: %v %v", u, err)
	}
}

// A provider that hands over no address at all is REFUSED, not turned into an
// account. This is the live GitHub App shape: the App ignores the requested scope,
// /user/emails answers 403, and what used to happen was a second account named
// after the PROVIDER ("github") with an empty email — unreachable, unrecoverable,
// and never matched to the person's real account.
func TestFederation_NoAddressIsRefusedRatherThanNamedAfterTheProvider(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockGitHub(t)
	m.emailsForbidden = true // the App has no "Email addresses" permission
	m.profileEmail = ""      // and the profile hides it
	seedGitHubProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGitHub)
	loc := requireRedirect(t, callback(t, app, q.Get("state"), "gh-code-1", cookie), testRedirect)
	cb := mustQuery(t, loc)
	if cb.Get("code") != "" {
		t.Fatalf("a sign-in with no address minted a code: %q", loc)
	}
	if cb.Get("error") != "access_denied" || !strings.Contains(cb.Get("error_description"), "email") {
		t.Fatalf("the refusal must say what is missing, got %q / %q", cb.Get("error"), cb.Get("error_description"))
	}
	if countUsers(t, db) != before {
		t.Fatalf("an email-less account was provisioned anyway (%d -> %d)", before, countUsers(t, db))
	}
	for _, name := range []string{"github", "github2", "user"} {
		if u, _ := store.GetUserByName(tctx(), db, "hanzo", name); u != nil {
			t.Fatalf("an account named %q was created from the provider type", name)
		}
	}
}

// verifyEmail marks the account's own address as proven, the state a password
// signup never reaches on its own.
func verifyEmail(t *testing.T, db orm.DB, name string) {
	t.Helper()
	u := userRow(t, db, name)
	u.EmailVerified = true
	if err := u.UpdateCtx(tctx()); err != nil {
		t.Fatalf("verify email: %v", err)
	}
}
