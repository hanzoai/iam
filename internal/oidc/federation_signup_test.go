// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// An application that does not allow sign-up must not mint accounts through the
// SOCIAL door either.
//
// This is the asymmetry the check closes. Password sign-up and the wallet front door
// both refuse when EnableSignUp is false, so turning the flag off is the documented
// way to close registration — but federation never read it, and "Continue with
// Google" kept creating accounts on the very same application. An operator who
// closed the estate had closed two of three doors and been told it was shut.
func TestFederation_SignupDisabledRefusesNewAccount(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{signup: false, clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	cb, _ := url.Parse(loc)
	if code := cb.Query().Get("code"); code != "" {
		t.Fatalf("federation minted an authorization code on a signup-disabled app: %q", loc)
	}
	if got := countUsers(t, db); got != before {
		t.Fatalf("a new account was provisioned despite enableSignUp=false: users %d -> %d", before, got)
	}
	if u, _ := store.GetUserByConnector(context.Background(), db, "hanzo", "google", m.sub); u != nil {
		t.Fatal("a federated account was created on an application that forbids sign-up")
	}
}

// Closing sign-up must NOT lock out people who already have accounts. The gate
// belongs on the branch that CREATES an account, not on the federation entry point —
// otherwise "no new registrations" silently becomes "nobody can log in", which is an
// outage rather than a policy.
func TestFederation_SignupDisabledStillSignsInExistingUser(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{signup: false, clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	// A returning user: already linked to this provider subject.
	seedUser(t, db, "returning", "returning@example.com", "pw")
	if _, err := updateUser(context.Background(), db, "hanzo", "returning", func(fresh *schema.User) error {
		fresh.Google = m.sub
		return nil
	}); err != nil {
		t.Fatalf("link the returning user: %v", err)
	}

	before := countUsers(t, db)
	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	cb, _ := url.Parse(loc)
	if cb.Query().Get("code") == "" {
		t.Fatalf("an EXISTING user must still sign in when signup is closed; got %q", loc)
	}
	if got := countUsers(t, db); got != before {
		t.Fatalf("sign-in must not create a user: %d -> %d", before, got)
	}
}
