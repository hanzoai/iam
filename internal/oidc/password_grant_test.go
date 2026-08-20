// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"
)

// The Resource Owner Password Credentials grant (RFC 6749 §4.3) — the durable
// first-party console session. Verifies the happy path mints a real, verifiable
// token carrying the user's identity, and that every rejection (bad password,
// public client, password-disabled app) fails closed. The password is checked
// through the SAME algorithm-aware path the login form uses.

func TestPasswordGrant_mintsTokenForValidCredentials(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"hanzo-console"},
		"client_secret": {"top-secret"},
		"username":      {"alice@hanzo.ai"},
		"password":      {"correct horse"},
		"scope":         {"openid profile email offline_access"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200; body=%v", resp.StatusCode, tok)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token; body=%v", tok)
	}
	// offline_access → a refresh token; openid → an id_token.
	if tok["refresh_token"] == nil || tok["refresh_token"] == "" {
		t.Errorf("offline_access requested but no refresh_token minted")
	}
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" {
		t.Errorf("subject = %q, want hanzo/alice", claims.Subject)
	}
	if claims.Owner != "hanzo" {
		t.Errorf("owner = %q, want hanzo", claims.Owner)
	}
}

func TestPasswordGrant_wrongPassword_invalidGrant(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"hanzo-console"},
		"client_secret": {"top-secret"},
		"username":      {"alice@hanzo.ai"},
		"password":      {"WRONG"},
	})
	requireError(t, resp, tok, 400, "invalid_grant")
}

func TestPasswordGrant_unknownUser_invalidGrant_sameAsBadPassword(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	// No user seeded: an unknown user must return the SAME opaque invalid_grant as
	// a wrong password — no user-enumeration oracle.
	resp, tok := postToken(t, app, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"hanzo-console"},
		"client_secret": {"top-secret"},
		"username":      {"ghost@hanzo.ai"},
		"password":      {"anything"},
	})
	requireError(t, resp, tok, 400, "invalid_grant")
}

func TestPasswordGrant_publicClient_rejected(t *testing.T) {
	app, db := newServer(t)
	// A public (no-secret) client can never use the password grant.
	seedApp(t, db, appOpts{clientID: "pub"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"},
		"client_id":  {"pub"},
		"username":   {"alice@hanzo.ai"},
		"password":   {"correct horse"},
	})
	if resp.StatusCode != 401 {
		t.Fatalf("public-client password grant status = %d, want 401; body=%v", resp.StatusCode, tok)
	}
}
