// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"strings"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// What a federated sign-in may CREATE.

// An application with registration switched off does not get new accounts created
// by a social provider either. The switch is the tenant's, and it used to mean one
// thing at the password and wallet endpoints and nothing at all at this one.
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

// An IdP address that is present but NOT verified must not create an account.
// GitHub's profile email (returned when /user/emails has no verified entry) is
// the live shape of this refusal.
func TestFederation_UnverifiedEmailIsNotProvisioned(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "webapp", signup: true, redirectURIs: []string{testRedirect}})
	m := newMockGitHub(t)
	m.emails = []map[string]any{
		{"email": "octo-unverified@example.com", "primary": true, "verified": false},
	}
	m.profileEmail = "octo-profile@example.com"
	seedGitHubProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGitHub)
	loc := requireRedirect(t, callback(t, app, q.Get("state"), "gh-code-1", cookie), testRedirect)
	cb := mustQuery(t, loc)
	if cb.Get("code") != "" {
		t.Fatalf("unverified email must not mint a code: %q", loc)
	}
	if cb.Get("error") != "access_denied" {
		t.Fatalf("want access_denied, got %q / %q", cb.Get("error"), cb.Get("error_description"))
	}
	desc := cb.Get("error_description")
	if !strings.Contains(desc, "email") {
		t.Fatalf("refusal should mention email, got %q", desc)
	}
	if countUsers(t, db) != before {
		t.Fatalf("an unverified federated account was provisioned (%d -> %d)", before, countUsers(t, db))
	}
}

// linkOrProvision itself refuses !emailVerified before calling Create.
func TestLinkOrProvision_RefusesUnverifiedEmail(t *testing.T) {
	ctx := tctx()
	db, app, prov, _ := federatedApp(t)
	_, _, err := linkOrProvision(ctx, db, app, prov, federatedIdentity{
		subject: "idp-unverified", email: "newbie@example.com", emailVerified: false,
	})
	if err != errUnverifiedFederatedEmail {
		t.Fatalf("got %v, want errUnverifiedFederatedEmail", err)
	}
	if u, _ := store.GetUserByEmail(ctx, db, app.Organization, "newbie@example.com"); u != nil {
		t.Fatal("an unverified provision left a user row")
	}
}
