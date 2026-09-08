// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// RFC 8693 Token Exchange — the standard on-behalf-of flow (replaces the retired
// issue-user-token verb). An allow-listed confidential client presents a valid
// subject_token and receives a token bound to that subject, re-scoped to a
// downstream resource. These tests pin the happy path AND every red-hardened
// control: the allow-list is clientId-only (the closed CRITICAL), a reserved-org
// subject needs the separate admin capability, public clients are refused, and an
// invalid subject_token yields invalid_grant.

// exchange posts a token-exchange grant as the confidential client (basic auth).
func exchange(t *testing.T, app *zip.App, clientID, secret string, extra url.Values) (int, map[string]any) {
	t.Helper()
	form := url.Values{
		"grant_type":    {grantTypeTokenExchange},
		"client_id":     {clientID},
		"client_secret": {secret},
	}
	for k, v := range extra {
		form[k] = v
	}
	resp, body := do(t, app, formReq("POST", PathToken, form))
	return resp.StatusCode, decode(t, body)
}

// subjectTokenFor mints a real access token for (org, name) via the password
// grant through `viaClient` — a valid subject_token an exchange can present.
func subjectTokenFor(t *testing.T, app *zip.App, viaClient, secret, org, username, password string) string {
	t.Helper()
	_, tok := postToken(t, app, url.Values{
		"grant_type":    {"password"},
		"client_id":     {viaClient},
		"client_secret": {secret},
		"organization":  {org},
		"username":      {username},
		"password":      {password},
		"scope":         {"openid profile"},
	})
	st, _ := tok["access_token"].(string)
	if st == "" {
		t.Fatalf("could not mint a subject_token; body=%v", tok)
	}
	return st
}

// directSubjectToken signs a verifiable access token for the (owner,name) user
// directly under the trusted signing cert — the legitimate way to obtain a
// subject_token for a RESERVED-org subject now that public ROPC into a reserved org
// is forbidden (F-D2). verifyToken checks only the trusted kid + signature + time,
// so a cert-signed token carrying the user's `sub` is accepted; the exchange then
// resolves that subject and applies its OWN reserved-org gate (the thing under test).
func directSubjectToken(t *testing.T, db orm.DB, certName, owner, name string) string {
	t.Helper()
	ctx := context.Background()
	cert, err := store.GetSigningCert(ctx, db, certName)
	if err != nil || cert == nil {
		t.Fatalf("signing cert %q: %v", certName, err)
	}
	signer, err := NewSignerFromCert(cert, nil, "https://hanzo.id")
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	u, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil || u == nil {
		t.Fatalf("user %s/%s not seeded: %v", owner, name, err)
	}
	app := &schema.Application{Organization: u.Owner, ClientId: "direct"}
	tok, err := signer.Sign(app, Identity{Id: subjectOf(u), Email: u.Email, Name: u.Name}, "openid profile", "", time.Hour, nowFunc())
	if err != nil {
		t.Fatalf("sign subject token: %v", err)
	}
	return tok
}

func TestTokenExchange_mintsForSubject(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	subject := subjectTokenFor(t, app, "hanzo-console", "top-secret", "hanzo", "alice@hanzo.ai", "correct horse")

	status, tok := exchange(t, app, "hanzo-console", "top-secret", url.Values{
		"subject_token":      {subject},
		"subject_token_type": {subjectTokenTypeAccess},
		"resource":           {"hanzo-cloud"},
	})
	if status != 200 {
		t.Fatalf("status = %d; body=%v", status, tok)
	}
	if tok["issued_token_type"] != tokenTypeAccessToken {
		t.Errorf("issued_token_type = %v, want %s", tok["issued_token_type"], tokenTypeAccessToken)
	}
	access, _ := tok["access_token"].(string)
	if access == "" {
		t.Fatalf("no access_token; body=%v", tok)
	}
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("exchanged token does not verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" || claims.Owner != "hanzo" {
		t.Errorf("subject/owner = %q/%q, want hanzo/alice / hanzo", claims.Subject, claims.Owner)
	}
	if claims.Azp != "hanzo-console" {
		t.Errorf("azp = %q, want hanzo-console (the acting client)", claims.Azp)
	}
	// The RFC 8707 resource became the aud.
	audOK := false
	for _, a := range claims.Audience {
		if a == "hanzo-cloud" {
			audOK = true
		}
	}
	if !audOK {
		t.Errorf("aud = %v, want it to contain the requested resource hanzo-cloud", claims.Audience)
	}
}

func TestTokenExchange_notAllowlisted_403(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "some-other-app")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	subject := subjectTokenFor(t, app, "hanzo-console", "top-secret", "hanzo", "alice@hanzo.ai", "correct horse")

	// hanzo-console holds a valid subject_token but is off the exchange allow-list.
	status, _ := exchange(t, app, "hanzo-console", "top-secret", url.Values{"subject_token": {subject}})
	if status != 403 {
		t.Fatalf("off-allow-list exchange status = %d, want 403", status)
	}
}

// TestTokenExchange_nameCollisionAttacker_403 is the regression guard for the
// closed CRITICAL: an attacker app named like the console but with the attacker's
// OWN clientId is refused at the allow-list (matched by clientId only), even though
// it holds a valid subject_token for its own tenant user.
func TestTokenExchange_nameCollisionAttacker_403(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	// Attacker: a DIFFERENT clientId, but NAME collides with the allow-listed one.
	seedAttackerApp(t, db, "evil", "hanzo-console", "evil-pwn", "attacker-knows-this", "cert-hanzo-console")
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	subject := subjectTokenFor(t, app, "hanzo-console", "top-secret", "hanzo", "alice@hanzo.ai", "correct horse")

	status, body := exchange(t, app, "evil-pwn", "attacker-knows-this", url.Values{
		"subject_token": {subject},
		"resource":      {"hanzo-cloud"},
	})
	if status != 403 {
		t.Fatalf("PRIV-ESC REOPENED: name-collision client admitted (status=%d) — allow-list must key on clientId only; body=%v", status, body)
	}
}

func TestTokenExchange_reservedOrgSubject_requiresAdminCapability(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console") // general only
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	// An admin-org user with a password, so we can mint their subject_token.
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "admin pw")
	subject := directSubjectToken(t, db, "cert-hanzo-console", "admin", "root")

	status, _ := exchange(t, app, "hanzo-console", "top-secret", url.Values{
		"subject_token": {subject},
		"resource":      {"hanzo-cloud"},
	})
	if status != 403 {
		t.Fatalf("reserved-org exchange without admin capability status = %d, want 403", status)
	}
}

func TestTokenExchange_reservedOrgSubject_admitsWithAdminCapability(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	t.Setenv("IAM_ADMIN_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUserInOrg(t, db, "admin", "root", "root@hanzo.ai", "admin pw")
	subject := directSubjectToken(t, db, "cert-hanzo-console", "admin", "root")

	status, tok := exchange(t, app, "hanzo-console", "top-secret", url.Values{
		"subject_token": {subject},
		"resource":      {"hanzo-cloud"},
	})
	if status != 200 {
		t.Fatalf("legit admin exchange status = %d; body=%v", status, tok)
	}
	if access, _ := tok["access_token"].(string); access == "" {
		t.Fatalf("no admin token minted; body=%v", tok)
	}
}

func TestTokenExchange_invalidSubjectToken_invalidGrant(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	status, tok := exchange(t, app, "hanzo-console", "top-secret", url.Values{"subject_token": {"garbage.not.a.jwt"}})
	if status != 400 || tok["error"] != "invalid_grant" {
		t.Fatalf("invalid subject_token → status=%d error=%v, want 400 invalid_grant", status, tok["error"])
	}
}

func TestTokenExchange_publicClient_rejected(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "pub")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "pub"}) // no secret → public
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")

	status, _ := exchange(t, app, "pub", "", url.Values{"subject_token": {"x"}})
	if status != 401 {
		t.Fatalf("public-client exchange status = %d, want 401", status)
	}
}

func TestTokenExchange_emitsAudit(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	subject := subjectTokenFor(t, app, "hanzo-console", "top-secret", "hanzo", "alice@hanzo.ai", "correct horse")

	exchange(t, app, "hanzo-console", "top-secret", url.Values{"subject_token": {subject}, "resource": {"hanzo-cloud"}})

	logs, err := orm.TypedQuery[schema.AuditLog](db).Filter("Action=", "token-exchange").GetAll(context.Background())
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(logs) != 1 || logs[0].User != "hanzo/alice" || logs[0].Object != "hanzo-console" {
		t.Fatalf("token-exchange audit = %+v, want one row {user:hanzo/alice, minter:hanzo-console}", logs)
	}
}

// A client that knows how long it needs the token may ask for less than the
// application grants, and the token really is shorter — this is what lets a
// credential handed to a leased process die with the lease.
func TestTokenExchange_lifetimeShortensTheToken(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	subject := subjectTokenFor(t, app, "hanzo-console", "top-secret", "hanzo", "alice@hanzo.ai", "correct horse")

	status, tok := exchange(t, app, "hanzo-console", "top-secret", url.Values{
		"subject_token": {subject},
		"lifetime":      {"900"},
	})
	if status != 200 {
		t.Fatalf("status = %d; body=%v", status, tok)
	}
	if got, _ := tok["expires_in"].(float64); int(got) != 900 {
		t.Errorf("expires_in = %v, want 900", tok["expires_in"])
	}
	access, _ := tok["access_token"].(string)
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("exchanged token does not verify: %v", err)
	}
	if life := claims.ExpiresAt.Sub(nowFunc()); life > 15*time.Minute {
		t.Errorf("token lives %v, want no more than the 900s asked for", life)
	}
}

// The clamp runs ONE WAY. A request for more life than the application declares
// leaves the application's own lifetime standing, so no caller can lengthen a
// credential by asking.
func TestTokenExchange_lifetimeCannotOutrunTheApplication(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	subject := subjectTokenFor(t, app, "hanzo-console", "top-secret", "hanzo", "alice@hanzo.ai", "correct horse")

	for _, asked := range []string{"86400", "0", "-1", "forever", ""} {
		status, tok := exchange(t, app, "hanzo-console", "top-secret", url.Values{
			"subject_token": {subject},
			"lifetime":      {asked},
		})
		if status != 200 {
			t.Fatalf("lifetime=%q: status = %d; body=%v", asked, status, tok)
		}
		want := int(appTTL(&schema.Application{}).Seconds())
		if got, _ := tok["expires_in"].(float64); int(got) != want {
			t.Errorf("lifetime=%q: expires_in = %v, want the application's own %d", asked, tok["expires_in"], want)
		}
	}
}
