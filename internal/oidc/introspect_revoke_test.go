// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"encoding/base64"
	"net/http"
	"net/url"
	"testing"

	"github.com/zap-proto/zip"
)

// RFC 7662 introspection + RFC 7009 revocation, end to end: mint a real token via
// the password grant, introspect it (active + claims), revoke it, and confirm it
// then reads inactive AND its bearer no longer resolves at userinfo.

// postForm posts a form to path as the confidential client (client_secret_basic).
func postForm(t *testing.T, app *zip.App, path, clientID, secret string, form url.Values) (*http.Response, map[string]any) {
	t.Helper()
	req := formReq("POST", path, form)
	if clientID != "" {
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	}
	resp, body := do(t, app, req)
	return resp, decode(t, body)
}

// mintPasswordToken issues an access+refresh token for the seeded user.
func mintPasswordToken(t *testing.T, app *zip.App) (access, refresh string) {
	t.Helper()
	_, tok := postToken(t, app, url.Values{
		"grant_type":    {"password"},
		"client_id":     {"hanzo-console"},
		"client_secret": {"top-secret"},
		"username":      {"alice@hanzo.ai"},
		"password":      {"correct horse"},
		"scope":         {"openid profile email offline_access"},
	})
	access, _ = tok["access_token"].(string)
	refresh, _ = tok["refresh_token"].(string)
	if access == "" {
		t.Fatalf("no access_token minted; body=%v", tok)
	}
	return access, refresh
}

func TestIntrospect_activeToken_returnsClaims(t *testing.T) {
	app, db := newServer(t)
	_ = db
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	access, _ := mintPasswordToken(t, app)

	_, ir := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if ir["active"] != true {
		t.Fatalf("active = %v, want true; body=%v", ir["active"], ir)
	}
	if ir["sub"] != "hanzo/alice" {
		t.Errorf("sub = %v, want hanzo/alice", ir["sub"])
	}
	if ir["owner"] != "hanzo" {
		t.Errorf("owner = %v, want hanzo", ir["owner"])
	}
	if ir["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", ir["token_type"])
	}
}

func TestIntrospect_requiresConfidentialClientAuth(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	access, _ := mintPasswordToken(t, app)

	// No client auth → 401 (introspection is privileged).
	resp, _ := postForm(t, app, PathIntrospect, "", "", url.Values{"token": {access}})
	if resp.StatusCode != 401 {
		t.Fatalf("unauthenticated introspect status = %d, want 401", resp.StatusCode)
	}
	// Wrong secret → 401.
	resp2, _ := postForm(t, app, PathIntrospect, "hanzo-console", "WRONG", url.Values{"token": {access}})
	if resp2.StatusCode != 401 {
		t.Fatalf("bad-secret introspect status = %d, want 401", resp2.StatusCode)
	}
}

func TestIntrospect_garbageToken_inactive(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	_, ir := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {"not-a-real-token"}})
	if ir["active"] != false {
		t.Fatalf("garbage token active = %v, want false", ir["active"])
	}
}

func TestRevoke_accessToken_thenInactive(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "correct horse")
	access, _ := mintPasswordToken(t, app)

	// Active before revoke.
	_, before := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if before["active"] != true {
		t.Fatalf("token not active before revoke; body=%v", before)
	}

	// Revoke → 200.
	resp, _ := postForm(t, app, PathRevoke, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if resp.StatusCode != 200 {
		t.Fatalf("revoke status = %d, want 200", resp.StatusCode)
	}

	// Inactive after revoke — introspection reflects the deleted grant row.
	_, after := postForm(t, app, PathIntrospect, "hanzo-console", "top-secret", url.Values{"token": {access}})
	if after["active"] != false {
		t.Fatalf("token still active after revoke; body=%v", after)
	}

	// And the bearer no longer resolves at userinfo (revocation is real).
	req := formReqNoBody("GET", PathUserInfo)
	req.Header.Set("Authorization", "Bearer "+access)
	if resp, _ := do(t, app, req); resp.StatusCode == 200 {
		t.Fatalf("userinfo still 200 for a revoked bearer")
	}
}

func TestRevoke_unknownToken_is200_noOracle(t *testing.T) {
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	// RFC 7009 §2.2: an unknown token is a silent 200, not an error.
	resp, _ := postForm(t, app, PathRevoke, "hanzo-console", "top-secret", url.Values{"token": {"unknown"}})
	if resp.StatusCode != 200 {
		t.Fatalf("unknown-token revoke status = %d, want 200", resp.StatusCode)
	}
}
