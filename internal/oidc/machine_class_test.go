// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

// A machine credential must STATE that it is a machine, in the token, the way it
// already states which ledger it spends from.
//
// Until it did, the only credentials account.IsMachine ever recognised were the
// API keys, whose class comes off a user row. A token carried no class at all, so
// every first-party service that authenticates by client_credentials read as a
// PERSON — and a spend row named the application in its user column, which reads
// as attributed spend and is not. The query for spend nobody owns returned
// nothing, because every row was "owned" by hanzo-cloud.
//
// These drive the REAL mint paths (POST /oauth/token) and run the REAL predicate
// (account.IsMachine) over the decoded claims, so what is pinned is mint → claim →
// predicate, not a helper in isolation.

import (
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hanzoai/account"

	"github.com/hanzoai/iam/pkg/schema"
)

// classOf mints a token by the named grant and returns its decoded claims.
// Shared is the case the audience heuristic below cannot see.
func classOf(t *testing.T, org string, shared bool) Claims {
	t.Helper()
	app, db := newServer(t)
	seedAppFull(t, db, fullApp{clientID: "svc-" + org, secret: "svc-secret", org: org, shared: shared})

	resp, tok := postToken(t, app, url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {"svc-" + org},
		"client_secret": {"svc-secret"},
	})
	raw, _ := tok["access_token"].(string)
	if resp.StatusCode != 200 || raw == "" {
		t.Fatalf("client_credentials did not mint: status=%d body=%v", resp.StatusCode, tok)
	}
	var got Claims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &got); err != nil {
		t.Fatalf("parse access token: %v", err)
	}
	return got
}

// THE FIX. Every shape of machine token says so, and the one predicate money and
// attribution both read agrees.
func TestMachineToken_statesItsClass(t *testing.T) {
	for _, c := range []struct {
		name   string
		org    string
		shared bool
	}{
		{name: "a first-party service in the signup org", org: account.SignupOrg},
		{name: "a tenant's own service", org: "acme"},
		{name: "a SHARED app, which the audience heuristic cannot see", org: "acme", shared: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := classOf(t, c.org, c.shared)

			if got.Type != schema.Program {
				t.Errorf("type = %q, want %q", got.Type, schema.Program)
			}
			if !account.IsMachine(got.Type) {
				t.Fatal("the predicate still reads a program as a person; the claim never reached it")
			}
		})
	}
}

// WHY THE CLAIM AND NOT THE INFERENCE. A consumer with no class claim can only
// guess, and the guess available to it is that the token's audience equals its
// name — true of a single-tenant app by construction (clientId == name), and
// FALSE of a shared one, whose audience IAM qualifies with the org it was minted
// for. So the inference reports every shared app's machine as a person, silently.
//
// This test states that gap as the reason the claim exists. If audienceFor ever
// stops qualifying a shared audience, this fails and the claim is merely
// redundant rather than load-bearing — which is worth being told.
func TestMachineToken_audienceCannotStandInForTheClass(t *testing.T) {
	shared := classOf(t, "acme", true)
	if len(shared.Audience) == 0 {
		t.Fatal("no audience to compare")
	}
	if shared.Audience[0] == shared.Name {
		t.Fatalf("a shared app's audience %q equals its name; the inference would have covered this case",
			shared.Audience[0])
	}
	if !account.IsMachine(shared.Type) {
		t.Error("a shared app's machine reads as a person — exactly what the inference gets wrong")
	}

	// …and for the single-tenant app the two agree, so stating the class moves no
	// principal that was already being read correctly.
	solo := classOf(t, "acme", false)
	if solo.Audience[0] != solo.Name {
		t.Errorf("single-tenant audience %q != name %q; the inference's own case has moved",
			solo.Audience[0], solo.Name)
	}
}

// THE REVERSE, and the one that matters most: a PERSON must never be typed a
// machine. A class claim that over-fires would hand a human's spend to an agent
// column and pool their wallet with the org's.
func TestPersonToken_carriesNoClass(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-console"},
		"client_secret": {"top-secret"},
		"username":      {"alice@hanzo.ai"}, "password": {"correct horse"},
	})
	raw, _ := tok["access_token"].(string)
	if resp.StatusCode != 200 || raw == "" {
		t.Fatalf("password grant did not mint: status=%d body=%v", resp.StatusCode, tok)
	}
	var got Claims
	if _, _, err := jwt.NewParser().ParseUnverified(raw, &got); err != nil {
		t.Fatalf("parse access token: %v", err)
	}

	if got.Type != "" {
		t.Errorf("a person's token carries type %q; only a machine has a class to state", got.Type)
	}
	if account.IsMachine(got.Type) {
		t.Fatal("a person reads as a machine — their spend would land in an agent column")
	}
}
