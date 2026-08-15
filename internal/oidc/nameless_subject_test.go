// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"errors"
	"testing"
)

// A grant whose subject stopped resolving must not renew.
//
// THE CHAIN THIS CLOSES. A refresh token freezes its subject's (owner, name) key
// at establishment and every rotation copies that key forward. userClaims used to
// answer a key that resolved to no row with a NAMELESS Identity — the passed-in id
// as `sub` and nothing else — which reads downstream not as "profile unknown" but
// as a set of answers: no name, no orgs, no billing account. account.Payer takes a
// missing name in the signup org to mean "not a person" and bills the account
// beside it, which is the platform's own balance. So a token that had failed to
// name anybody spent the pool, and because each rotation copied the dead key
// forward, it renewed itself indefinitely.
//
// Re-keying is the ordinary way to reach that state, not a corruption: founding a
// personal org moves the row from (hanzo, alice) to (alice-co, alice) while a
// refresh token minted before the move still names hanzo/alice.
func TestRefresh_ReKeyedSubjectCannotRenew(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	refresh1, _ := tok["refresh_token"].(string)
	if refresh1 == "" {
		t.Fatal("setup: no refresh token issued")
	}

	// The row moves out from under the key the token pinned.
	alice := userRow(t, db, "alice")
	alice.Owner = "alice-co"
	if err := alice.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("re-key alice: %v", err)
	}

	status, out := refresh(t, app, "pub", refresh1, nil)
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("re-keyed subject renewed: status=%d body=%v, want 400 invalid_grant", status, out)
	}
	// The assertion that matters is not the status but the ABSENCE of a credential:
	// a nameless access token is the thing that reaches the billing gate.
	if out["access_token"] != nil || out["refresh_token"] != nil {
		t.Fatalf("minted a token for a subject that names nobody: %v", out)
	}
}

// Deleting a user must not upgrade their billing. Soft-delete leaves the row in
// place, so the lookup SUCCEEDS and only the flag says the user is gone — which is
// exactly the case a `u == nil` check alone would miss.
func TestRefresh_DeletedSubjectCannotRenew(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	refresh1, _ := tok["refresh_token"].(string)

	alice := userRow(t, db, "alice")
	alice.IsDeleted = true
	if err := alice.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("delete alice: %v", err)
	}

	status, out := refresh(t, app, "pub", refresh1, nil)
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("deleted subject renewed: status=%d body=%v, want 400 invalid_grant", status, out)
	}
	if out["access_token"] != nil {
		t.Fatalf("minted a token for a deleted user: %v", out)
	}
}

// A ban must take effect on the path that RENEWS access, not only on the one that
// establishes it. The password grant already refused a forbidden user; refresh did
// not, so banning someone left their live session rotating indefinitely.
func TestRefresh_BannedSubjectCannotRenew(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	refresh1, _ := tok["refresh_token"].(string)

	alice := userRow(t, db, "alice")
	alice.IsForbidden = true
	if err := alice.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("ban alice: %v", err)
	}

	status, out := refresh(t, app, "pub", refresh1, nil)
	if status != 400 || out["error"] != "invalid_grant" {
		t.Fatalf("banned subject renewed: status=%d body=%v, want 400 invalid_grant", status, out)
	}
}

// The positive control. Refusing a dead subject must not cost a live one its
// session — without this, "fail the mint" could be satisfied by failing always.
func TestRefresh_LiveSubjectStillRotates(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub", redirectURIs: []string{testRedirect}, refreshHours: 24})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	tok := grantViaPKCE(t, app, "pub", "openid offline_access")
	refresh1, _ := tok["refresh_token"].(string)

	status, out := refresh(t, app, "pub", refresh1, nil)
	if status != 200 {
		t.Fatalf("live subject failed to rotate: status=%d body=%v", status, out)
	}
	if out["access_token"] == nil || out["refresh_token"] == nil {
		t.Fatalf("rotation dropped a token: %v", out)
	}
}

// A FAULT IS NOT A DEAD CREDENTIAL. Both used to return the same nameless
// Identity, so a database blip promoted whoever hit it to the pool. They are now
// distinct, and the distinction is load-bearing in two directions: a fault must
// not revoke a live user's session (it is answered 500, retryable), and an absent
// row must not be retried forever (it is answered invalid_grant, terminal).
//
// Flattening the two — `if err != nil || u == nil` — passes every other test in
// this file, so this is the one that holds the difference.
func TestUserClaims_FaultAndAbsenceAreDifferentAnswers(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()

	// Absent: the store answers cleanly that there is no such user.
	if _, err := userClaims(ctx, db, "hanzo/nobody"); !errors.Is(err, ErrNoSubject) {
		t.Fatalf("absent subject: err = %v, want ErrNoSubject", err)
	}
	// Malformed subjects name nobody either.
	for _, sub := range []string{"", "hanzo", "/alice", "hanzo/"} {
		if _, err := userClaims(ctx, db, sub); !errors.Is(err, ErrNoSubject) {
			t.Fatalf("subject %q: err = %v, want ErrNoSubject", sub, err)
		}
	}

	// Fault: the store cannot answer at all. A closed database is the cheapest
	// honest fault — the row may well exist, so this must NOT be ErrNoSubject.
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
	_, err := userClaims(ctx, db, "hanzo/alice")
	if err == nil {
		t.Fatal("a store fault resolved an identity; want an error")
	}
	if errors.Is(err, ErrNoSubject) {
		t.Fatalf("a store fault was reported as a dead credential: %v", err)
	}
}
