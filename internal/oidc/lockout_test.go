// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"net/url"
	"testing"
)

// F-D1: public ROPC without lockout is an online brute-force oracle. A run of wrong
// passwords must lock the account (refused even with the correct password inside the
// window); a correct password before the limit resets the counter. State is the
// per-row SigninWrongTimes/LastSigninWrongTime casdoor already used.

func TestPasswordGrant_lockoutAfterRepeatedWrong(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console"}) // public
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	wrong := url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-console"},
		"username": {"alice@hanzo.ai"}, "password": {"WRONG"},
	}
	// Exactly signinWrongLimit wrong attempts, each a plain bad-credential refusal.
	for i := 0; i < signinWrongLimit; i++ {
		resp, tok := postToken(t, app, wrong)
		requireError(t, resp, tok, 400, "invalid_grant")
	}
	// Now the CORRECT password is refused — the account is locked.
	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-console"},
		"username": {"alice@hanzo.ai"}, "password": {"correct horse"},
	})
	if resp.StatusCode != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("locked account status=%d err=%v, want 400 invalid_grant", resp.StatusCode, tok["error"])
	}
	desc, _ := tok["error_description"].(string)
	if desc == "the username or password is incorrect" || desc == "" {
		t.Errorf("lockout must use a DISTINCT message, got %q", desc)
	}
}

// F-D1 PROOF on the REAL create path. The seeded-user tests above hand-set
// SetId("owner/name"), so their storage key happens to equal owner/name and the
// counter persists regardless of the bug. A user minted through the canonical
// users.Create path (signup / SCIM / federation / CRUD) instead gets an
// auto-allocated int64 storage key, so a counter save keyed by "owner/name" writes
// NOTHING — the account never locks. This drives the ACTUAL signup endpoint (no
// SetId anywhere), then proves the account locks: it FAILS against the owner/name
// save (6th correct password accepted) and PASSES once the counter targets the
// loaded row's real key.
func TestPasswordGrant_lockout_signupCreatedUser(t *testing.T) {
	app, db := newServer(t)
	// One PUBLIC app that both allows signup AND drives ROPC — the real console shape.
	seedApp(t, db, appOpts{clientID: "hanzo-console", signup: true})
	seedOrg(t, db, "hanzo")

	// Create the account through the ONE canonical create path — NO SetId. Its storage
	// key is an auto-int64 and its sub a UUID: exactly the post-cutover account shape.
	const pw = "correct horse battery staple"
	status, env := signupReq(t, app, map[string]string{
		"clientId": "hanzo-console", "organization": "hanzo",
		"username": "mallory", "password": pw, "email": "mallory@hanzo.ai",
	})
	if status != 200 || env["status"] != "ok" {
		t.Fatalf("signup: status=%d env=%v, want 200 ok", status, env)
	}

	wrong := url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-console"},
		"username": {"mallory@hanzo.ai"}, "password": {"WRONG"},
	}
	for i := 0; i < signinWrongLimit; i++ {
		resp, tok := postToken(t, app, wrong)
		requireError(t, resp, tok, 400, "invalid_grant")
	}
	// The CORRECT password on the 6th attempt must now be REFUSED — locked.
	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-console"},
		"username": {"mallory@hanzo.ai"}, "password": {pw},
	})
	if resp.StatusCode != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("a signup-created account did NOT lock after %d wrong passwords: status=%d err=%v — the counter never persisted (F-D1)",
			signinWrongLimit, resp.StatusCode, tok["error"])
	}
	desc, _ := tok["error_description"].(string)
	if desc != "too many failed attempts; the account is temporarily locked" {
		t.Errorf("lockout must use the DISTINCT lock message, got %q", desc)
	}
}

// A correct password before the limit resets the counter, so the lock never trips.
func TestPasswordGrant_correctPasswordResetsLockout(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console"}) // public
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	wrong := url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-console"},
		"username": {"alice@hanzo.ai"}, "password": {"WRONG"},
	}
	right := url.Values{
		"grant_type": {"password"}, "client_id": {"hanzo-console"},
		"username": {"alice@hanzo.ai"}, "password": {"correct horse"},
	}
	// Two rounds of (limit-1 wrong, then a success). If the success did not reset the
	// counter, the accumulated wrongs (2*(limit-1)) would exceed the limit and the
	// final success would be locked out.
	for round := 0; round < 2; round++ {
		for i := 0; i < signinWrongLimit-1; i++ {
			resp, tok := postToken(t, app, wrong)
			requireError(t, resp, tok, 400, "invalid_grant")
		}
		resp, tok := postToken(t, app, right)
		if resp.StatusCode != 200 {
			t.Fatalf("round %d: correct password status = %d, want 200 (counter must reset); body=%v", round, resp.StatusCode, tok)
		}
	}
}
