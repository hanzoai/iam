// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
)

// issue-user-token is a security primitive: an allow-listed confidential client
// mints a bearer carrying a TARGET user's full authority. These tests pin both
// halves — that a legitimate call mints a token whose claims ARE the target
// user's (so a resource server scopes to the user's tenant, and the token
// verifies under the same JWKS), and that EVERY rejection path (bad secret,
// off-allow-list, no auth, unknown/forbidden user) fails closed.

// issueReq builds a POST issue-user-token request authenticating `clientID`/
// `secret` via HTTP Basic — the confidential-client credential the console sends.
func issueReq(clientID, secret, query string) *http.Request {
	req := httptest.NewRequest("POST", PathIssueUserToken+query, nil)
	req.Host = "hanzo.id"
	if clientID != "" {
		req.Header.Set("Authorization", "Basic "+
			base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)))
	}
	return req
}

// dataMap pulls the `data` object out of the v1 envelope.
func dataMap(t *testing.T, body []byte) map[string]any {
	t.Helper()
	m := decode(t, body)
	d, _ := m["data"].(map[string]any)
	return d
}

func TestIssueUserToken_mintsTargetUserAuthority(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, body := do(t, app, issueReq("hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200; body=%s", resp.StatusCode, body)
	}
	m := decode(t, body)
	if m["status"] != "ok" {
		t.Fatalf("status field = %v; body=%s", m["status"], body)
	}
	data := dataMap(t, body)
	access, _ := data["accessToken"].(string)
	if access == "" {
		t.Fatalf("no accessToken in data; body=%s", body)
	}
	if exp, _ := data["expiresIn"].(float64); exp <= 0 {
		t.Fatalf("expiresIn = %v, want > 0", data["expiresIn"])
	}

	// The minted token must verify under the SAME JWKS and carry the TARGET user's
	// identity — subject = hanzo/alice, owner claim = the user's org (so a resource
	// server that scopes on `owner` scopes to alice's tenant, not the client's).
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" {
		t.Errorf("subject = %q, want hanzo/alice", claims.Subject)
	}
	if claims.Owner != "hanzo" {
		t.Errorf("owner claim = %q, want hanzo (the target user's tenant)", claims.Owner)
	}
	if claims.Azp != "hanzo-console" {
		t.Errorf("azp = %q, want hanzo-console (the minting client)", claims.Azp)
	}
}

func TestIssueUserToken_audienceOverride(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	// The admin path pins ?aud=<brand>-cloud so cloud's audience allow-list accepts
	// a reserved-admin operator's token.
	_, body := do(t, app, issueReq("hanzo-console", "top-secret", "?id=hanzo/alice&aud=hanzo-cloud"))
	access, _ := dataMap(t, body)["accessToken"].(string)
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	found := false
	for _, a := range claims.Audience {
		if a == "hanzo-cloud" {
			found = true
		}
	}
	if !found {
		t.Fatalf("aud = %v, want it to contain the ?aud= override hanzo-cloud", claims.Audience)
	}
}

func TestIssueUserToken_defaultAudienceIsClientWhenUserHasNoApp(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw") // no SignupApplication

	_, body := do(t, app, issueReq("hanzo-console", "top-secret", "?id=hanzo/alice"))
	access, _ := dataMap(t, body)["accessToken"].(string)
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "hanzo-console" {
		t.Fatalf("default aud = %v, want [hanzo-console] (the minting client fallback)", claims.Audience)
	}
}

func TestIssueUserToken_wrongSecret_401(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, body := do(t, app, issueReq("hanzo-console", "WRONG", "?id=hanzo/alice"))
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401; body=%s", resp.StatusCode, body)
	}
	if decode(t, body)["status"] != "error" {
		t.Fatalf("want status:error; body=%s", body)
	}
}

func TestIssueUserToken_notAllowlisted_403(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "some-other-app") // hanzo-console NOT listed
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, body := do(t, app, issueReq("hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 403 {
		t.Fatalf("status = %d, want 403 (client authenticated but not allow-listed); body=%s", resp.StatusCode, body)
	}
}

func TestIssueUserToken_emptyAllowlist_failsClosed(t *testing.T) {
	// No IAM_KEY_MINT_ALLOWED_APPS set → NOBODY may mint (a missing config must
	// never mean "anyone can hand out a user's authority").
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, _ := do(t, app, issueReq("hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 403 {
		t.Fatalf("empty allow-list status = %d, want 403 (fail closed)", resp.StatusCode)
	}
}

func TestIssueUserToken_noClientAuth_401(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	resp, _ := do(t, app, issueReq("", "", "?id=hanzo/alice"))
	if resp.StatusCode != 401 {
		t.Fatalf("no-auth status = %d, want 401", resp.StatusCode)
	}
}

func TestIssueUserToken_unknownUser_error(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	_, body := do(t, app, issueReq("hanzo-console", "top-secret", "?id=hanzo/ghost"))
	if decode(t, body)["status"] != "error" {
		t.Fatalf("unknown user must be status:error; body=%s", body)
	}
}

func TestIssueUserToken_forbiddenUser_403(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	// A forbidden/deleted user is a revoked principal — no token may be minted for it.
	u := orm.New[schema.User](db)
	u.Owner, u.Name = "hanzo", "banned"
	u.IsForbidden = true
	u.SetId("hanzo/banned")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed forbidden user: %v", err)
	}

	resp, _ := do(t, app, issueReq("hanzo-console", "top-secret", "?id=hanzo/banned"))
	if resp.StatusCode != 403 {
		t.Fatalf("forbidden-user status = %d, want 403", resp.StatusCode)
	}
}
