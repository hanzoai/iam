// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam2/internal/schema"
	"github.com/hanzoai/iam2/internal/store"
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

func TestMintUserKeys_generatesReadableHkKey(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	req := issueReq("hanzo-console", "top-secret", "?id=hanzo/alice")
	req.URL.Path = PathMintUserKeys
	resp, body := do(t, app, req)
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}
	key, _ := dataMap(t, body)["accessKey"].(string)
	if !strings.HasPrefix(key, "hk-") || len(key) < 8 {
		t.Fatalf("accessKey = %q, want an hk- key", key)
	}
	// The minted key is persisted on the user row (get-user / getUserKey read it).
	u, err := store.GetUserByName(context.Background(), db, "hanzo", "alice")
	if err != nil || u == nil {
		t.Fatalf("reload user: %v", err)
	}
	if u.AccessKey != key {
		t.Fatalf("persisted AccessKey = %q, want the minted %q", u.AccessKey, key)
	}
}

func TestRevokeUserKeys_clearsTheKey(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	// mint, then revoke.
	mint := issueReq("hanzo-console", "top-secret", "?id=hanzo/alice")
	mint.URL.Path = PathMintUserKeys
	do(t, app, mint)

	rev := issueReq("hanzo-console", "top-secret", "?id=hanzo/alice")
	rev.URL.Path = PathRevokeUserKeys
	resp, body := do(t, app, rev)
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("revoke status = %d; body=%s", resp.StatusCode, body)
	}
	u, _ := store.GetUserByName(context.Background(), db, "hanzo", "alice")
	if u.AccessKey != "" {
		t.Fatalf("AccessKey after revoke = %q, want empty", u.AccessKey)
	}
}

func TestIssueUserToken_emitsAuditRecord(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, _ := do(t, app, issueReq("hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	// The mint is accountable: an audit row names the action, target, and minter.
	logs, err := orm.TypedQuery[schema.AuditLog](db).Filter("Action=", "issue-user-token").GetAll(context.Background())
	if err != nil {
		t.Fatalf("query audit: %v", err)
	}
	if len(logs) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(logs))
	}
	if logs[0].User != "hanzo/alice" || logs[0].Object != "hanzo-console" {
		t.Fatalf("audit row = {user:%q, minter:%q}, want {hanzo/alice, hanzo-console}", logs[0].User, logs[0].Object)
	}
}

func TestMintUserKeys_notAllowlisted_403(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "other")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	req := issueReq("hanzo-console", "top-secret", "?id=hanzo/alice")
	req.URL.Path = PathMintUserKeys
	resp, _ := do(t, app, req)
	if resp.StatusCode != 403 {
		t.Fatalf("off-allow-list mint status = %d, want 403", resp.StatusCode)
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
