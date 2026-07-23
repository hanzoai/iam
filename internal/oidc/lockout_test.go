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
