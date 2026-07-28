// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"net/url"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// forbidUser flips an already-seeded user to revoked (IsForbidden), keeping its
// password intact — so a denial in the password grant is provably the
// forbidden-user gate, not a credential mismatch.
func forbidUser(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	u, err := orm.Get[schema.User](db, owner+"/"+name)
	if err != nil {
		t.Fatalf("load %s/%s: %v", owner, name, err)
	}
	u.IsForbidden = true
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("forbid %s/%s: %v", owner, name, err)
	}
}

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

// CASDOOR PARITY: a PUBLIC client (no secret, no PKCE) may complete the password
// grant — the console/chat apps casdoor allowed. See passwordGrant's doc comment.
func TestPasswordGrant_publicClient_legacyParity_succeeds(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console"}) // no secret → public client
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"},
		"client_id":  {"hanzo-console"},
		"username":   {"alice@hanzo.ai"},
		"password":   {"correct horse"},
		"scope":      {"openid"},
	})
	if resp.StatusCode != 200 {
		t.Fatalf("public-client password grant status = %d, want 200 (casdoor parity); body=%v", resp.StatusCode, tok)
	}
	access, _ := tok["access_token"].(string)
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" || claims.Owner != "hanzo" {
		t.Errorf("subject/owner = %q/%q, want hanzo/alice / hanzo", claims.Subject, claims.Owner)
	}
}

// The relaxation is BOUNDED: a public client still cannot pass a WRONG password —
// the credential check is untouched.
func TestPasswordGrant_publicClient_wrongPassword_denied(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console"}) // public
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"},
		"client_id":  {"hanzo-console"},
		"username":   {"alice@hanzo.ai"},
		"password":   {"WRONG"},
	})
	requireError(t, resp, tok, 400, "invalid_grant")
}

// A forbidden (revoked) user is denied even to a public client.
func TestPasswordGrant_publicClient_forbiddenUser_denied(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console"}) // public
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	forbidUser(t, db, "hanzo", "alice")

	resp, tok := postToken(t, app, url.Values{
		"grant_type": {"password"},
		"client_id":  {"hanzo-console"},
		"username":   {"alice@hanzo.ai"},
		"password":   {"correct horse"},
	})
	requireError(t, resp, tok, 400, "invalid_grant")
}

// F-D2: a public console must NOT be able to mint a token for a reserved system org
// (admin/built-in/app) by passing organization=<reserved> — that path resolved
// admin/<super> and minted a real SuperAdmin token on the correct password.
func TestPasswordGrant_reservedTargetOrg_refused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "zoo-console"}) // public, Organization=hanzo per seedApp
	// A SuperAdmin lives in the admin org with a known, CORRECT password — so the
	// refusal is provably the org gate, not a bad credential.
	seedUserInOrg(t, db, "admin", "z", "z@hanzo.ai", "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type":   {"password"},
		"client_id":    {"zoo-console"},
		"organization": {"admin"},
		"username":     {"z"},
		"password":     {"correct horse"},
	})
	requireError(t, resp, tok, 400, "invalid_grant")
	// And no token leaked.
	if tok["access_token"] != nil {
		t.Fatal("F-D2: a reserved-org password grant minted a token")
	}
}

// A foreign tenant org (not the client's own, non-shared) is refused too.
func TestPasswordGrant_foreignTenantOrg_refused(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console"}) // Organization=hanzo, not shared
	seedUserInOrg(t, db, "lux", "eve", "eve@lux.ai", "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type":   {"password"},
		"client_id":    {"hanzo-console"},
		"organization": {"lux"},
		"username":     {"eve"},
		"password":     {"correct horse"},
	})
	requireError(t, resp, tok, 400, "invalid_grant")
}

// A confidential client (registered secret) is UNCHANGED: a wrong/absent secret is
// still a 401 client-authentication failure — the relaxation is public-only.
func TestPasswordGrant_confidentialClient_wrongSecret_stillRejected(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "conf-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	resp, tok := postToken(t, app, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"conf-console"},
		"client_secret": {"WRONG"},
		"username":      {"alice@hanzo.ai"},
		"password":      {"correct horse"},
	})
	if resp.StatusCode != 401 {
		t.Fatalf("confidential wrong-secret status = %d, want 401; body=%v", resp.StatusCode, tok)
	}
}
