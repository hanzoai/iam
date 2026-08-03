// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/iam/pkg/store"
)

// A SOCIAL signup lands where a password signup lands: in an org of its own.
//
// This is the door that matters most. Federation creates the account in the APP's
// org, which for the live consumer apps is the shared signup org — so "Continue with
// Google" was the widest path into a co-tenancy with Hanzo's own org. Closing the
// exposure on the password door alone would leave the busiest one standing.
func TestFederation_PersonalOrgIsProvisioned(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{signup: true, orgChoice: orgChoicePersonal,
		clientID: "webapp", redirectURIs: []string{testRedirect}})
	m := newMockOIDC(t, fedGoogleCID)
	seedOIDCProvider(t, db, "webapp", m)

	q, cookie := beginAuthorize(t, app, "webapp", fedProvGoogle)
	m.mu.Lock()
	m.nonce = q.Get("nonce")
	m.mu.Unlock()

	resp := callback(t, app, q.Get("state"), "idp-code-1", cookie)
	loc := requireRedirect(t, resp, testRedirect)
	cb, _ := url.Parse(loc)
	if cb.Query().Get("code") == "" {
		t.Fatalf("social signup must still mint a code; got %q", loc)
	}

	ctx := context.Background()
	// The account must NOT be sitting in the app's shared org.
	u, err := store.GetUserByConnector(ctx, db, "hanzo", "google", m.sub)
	if err != nil {
		t.Fatal(err)
	}
	if u != nil {
		t.Fatal("social signup was left in the shared signup org 'hanzo'")
	}
	// It must be in an org of its own, founded by them, with the IdP's verified
	// address carried through — the bit cloud's funding gate reads.
	org, err := store.GetOrganizationByName(ctx, db, "alice")
	if err != nil || org == nil {
		t.Fatalf("personal org 'alice' not provisioned: %v", err)
	}
	moved, err := store.GetUserByName(ctx, db, "alice", "alice")
	if err != nil || moved == nil {
		t.Fatalf("federated user not found in their own org: %v", err)
	}
	if !moved.EmailVerified {
		t.Error("a verifying IdP's email_verified must carry through to the account")
	}
	if !moved.IsAdmin {
		t.Error("the founder must admin their own org")
	}
}
