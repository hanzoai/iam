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

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
)

// The `hk-` Cloud API-key primitives (mint/revoke). A confidential, allow-listed
// client (client_secret_basic) acts on a ?id=<owner>/<name> target user. These are
// a product credential, not an RFC token flow — the on-behalf-of TOKEN minting is
// RFC 8693 Token Exchange (token_exchange_test.go).

// seedForbiddenUser seeds a revoked (forbidden) user — no credential may be minted
// or rotated for it.
func seedForbiddenUser(t *testing.T, db orm.DB, owner, name string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.IsForbidden = true
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed forbidden user %s/%s: %v", owner, name, err)
	}
}

// keyReq builds a POST to a key primitive authenticating clientID/secret via Basic.
func keyReq(path, clientID, secret, query string) *http.Request {
	req := httptest.NewRequest("POST", path+query, nil)
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

// issue-user-token is the compat shim the console's adminBearer depends on: an
// allow-listed confidential client mints a token bound to the ?id= target user.
func TestIssueUserToken_mintsTargetUserToken(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, body := do(t, app, keyReq(PathIssueUserToken, "hanzo-console", "top-secret", "?id=hanzo/alice&aud=hanzo-cloud"))
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}
	access, _ := dataMap(t, body)["accessToken"].(string)
	if access == "" {
		t.Fatalf("no accessToken; body=%s", body)
	}
	// The minted token verifies under the JWKS and carries the TARGET user's identity.
	claims, err := verifyToken(context.Background(), db, access)
	if err != nil {
		t.Fatalf("minted token does not verify: %v", err)
	}
	if claims.Subject != "hanzo/alice" || claims.Owner != "hanzo" {
		t.Fatalf("subject/owner = %q/%q, want hanzo/alice / hanzo", claims.Subject, claims.Owner)
	}
	if exp, _ := dataMap(t, body)["expiresIn"].(float64); exp <= 0 {
		t.Fatalf("expiresIn = %v, want > 0", dataMap(t, body)["expiresIn"])
	}
}

func TestIssueUserToken_notAllowlisted_403(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "other-app")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")
	resp, _ := do(t, app, keyReq(PathIssueUserToken, "hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 403 {
		t.Fatalf("off-allow-list issue-user-token = %d, want 403", resp.StatusCode)
	}
}

func TestMintUserKeys_generatesReadableHkKey(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, body := do(t, app, keyReq(PathMintUserKeys, "hanzo-console", "top-secret", "?id=hanzo/alice"))
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

	do(t, app, keyReq(PathMintUserKeys, "hanzo-console", "top-secret", "?id=hanzo/alice"))

	resp, body := do(t, app, keyReq(PathRevokeUserKeys, "hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 200 || decode(t, body)["status"] != "ok" {
		t.Fatalf("revoke status = %d; body=%s", resp.StatusCode, body)
	}
	u, _ := store.GetUserByName(context.Background(), db, "hanzo", "alice")
	if u.AccessKey != "" {
		t.Fatalf("AccessKey after revoke = %q, want empty", u.AccessKey)
	}
}

func TestMintUserKeys_notAllowlisted_403(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "other")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, _ := do(t, app, keyReq(PathMintUserKeys, "hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 403 {
		t.Fatalf("off-allow-list mint status = %d, want 403", resp.StatusCode)
	}
}

func TestMintUserKeys_forbiddenUser_403(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedForbiddenUser(t, db, "hanzo", "banned")

	resp, _ := do(t, app, keyReq(PathMintUserKeys, "hanzo-console", "top-secret", "?id=hanzo/banned"))
	if resp.StatusCode != 403 {
		t.Fatalf("forbidden-user mint status = %d, want 403", resp.StatusCode)
	}
}

// ITEM 1 [functional break]: every mint/revoke test above seeds its user with
// SetId("owner/name"), so the row's storage key HAPPENS to equal "owner/name" and the
// pre-fix owner/name-keyed read resolves it. A user minted through the ONE canonical
// users.Create path (signup / SCIM / federation / CRUD) gets a store-ASSIGNED surrogate
// key (a GenerateID decimal string) and a UUID sub — the exact post-cutover account
// shape — for which an "owner/name" lookup MISSES. The pre-fix saveUser then errored
// (orm.ErrNotFound → 500) and no hk- key was ever minted or revoked for a new signup.
// This drives mint AND revoke against a create-path user; it FAILS before the fix (mint
// 500) and PASSES after (the write targets the row's real storage key, both shapes).
func TestMintRevokeUserKeys_createPathUser_persists(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})

	// Canonical create — surrogate storage key, UUID sub, NO SetId anywhere.
	if _, err := users.New(db).Create(tctx(), &users.CreateInput{
		User:     schema.User{Owner: "hanzo", Name: "mallory", Email: "mallory@hanzo.ai"},
		Password: "pw",
	}); err != nil {
		t.Fatalf("create via canonical path: %v", err)
	}

	// MINT must persist the hk- key on the real (surrogate-keyed) row.
	resp, body := do(t, app, keyReq(PathMintUserKeys, "hanzo-console", "top-secret", "?id=hanzo/mallory"))
	if resp.StatusCode != 200 {
		t.Fatalf("mint status=%d body=%s — saveUser missed the surrogate-key row (ITEM 1)", resp.StatusCode, body)
	}
	key, _ := dataMap(t, body)["accessKey"].(string)
	if !strings.HasPrefix(key, "hk-") {
		t.Fatalf("accessKey=%q, want an hk- key", key)
	}
	u, err := store.GetUserByName(tctx(), db, "hanzo", "mallory")
	if err != nil || u == nil {
		t.Fatalf("reload after mint: %v", err)
	}
	if u.AccessKey != key {
		t.Fatalf("persisted AccessKey=%q, want the minted %q — the write missed the real row", u.AccessKey, key)
	}

	// REVOKE must clear it on the same real row.
	resp, body = do(t, app, keyReq(PathRevokeUserKeys, "hanzo-console", "top-secret", "?id=hanzo/mallory"))
	if resp.StatusCode != 200 {
		t.Fatalf("revoke status=%d body=%s", resp.StatusCode, body)
	}
	if u, _ := store.GetUserByName(tctx(), db, "hanzo", "mallory"); u.AccessKey != "" {
		t.Fatalf("AccessKey after revoke=%q, want empty", u.AccessKey)
	}
}
