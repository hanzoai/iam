// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
	"github.com/hanzoai/iam/internal/users"
)

// The `sk-` Cloud API-key primitives (mint/revoke). A confidential, allow-listed
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

	resp, body := do(t, app, keyReq(PathTokensIssue, "hanzo-console", "top-secret", "?id=hanzo/alice&aud=hanzo-cloud"))
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
	resp, _ := do(t, app, keyReq(PathTokensIssue, "hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 403 {
		t.Fatalf("off-allow-list issue-user-token = %d, want 403", resp.StatusCode)
	}
}

func TestMintUserKeys_generatesReadableSkKey(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, body := do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}
	key, _ := dataMap(t, body)["accessKey"].(string)
	if !strings.HasPrefix(key, "sk-") || len(key) < 8 {
		t.Fatalf("accessKey = %q, want an sk- key", key)
	}
	// Assert the ROUND TRIP, not where the bytes landed. This test used to require
	// the key on schema.User.AccessKey — which nothing resolves — so it passed while
	// every minted credential authenticated nobody. What matters is that the key
	// resolves back to its user.
	got, err := store.UserByAccessKey(context.Background(), db, key)
	if err != nil || got == nil {
		t.Fatalf("minted key does not resolve to a user: %v", err)
	}
	if got.Owner != "hanzo" || got.Name != "alice" {
		t.Fatalf("key resolved to %s/%s, want hanzo/alice", got.Owner, got.Name)
	}
}

func TestRevokeUserKeys_clearsTheKey(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/alice"))

	resp, body := do(t, app, keyReq(PathKeysRevoke, "hanzo-console", "top-secret", "?id=hanzo/alice"))
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

	resp, _ := do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/alice"))
	if resp.StatusCode != 403 {
		t.Fatalf("off-allow-list mint status = %d, want 403", resp.StatusCode)
	}
}

func TestMintUserKeys_forbiddenUser_403(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedForbiddenUser(t, db, "hanzo", "banned")

	resp, _ := do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/banned"))
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
// (orm.ErrNotFound → 500) and no sk- key was ever minted or revoked for a new signup.
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

	// MINT must persist the sk- key on the real (surrogate-keyed) row.
	resp, body := do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/mallory"))
	if resp.StatusCode != 200 {
		t.Fatalf("mint status=%d body=%s — saveUser missed the surrogate-key row (ITEM 1)", resp.StatusCode, body)
	}
	key, _ := dataMap(t, body)["accessKey"].(string)
	if !strings.HasPrefix(key, "sk-") {
		t.Fatalf("accessKey=%q, want an sk- key", key)
	}
	got, err := store.UserByAccessKey(tctx(), db, key)
	if err != nil || got == nil {
		t.Fatalf("minted key does not resolve to its user — the write missed the row the resolver reads: %v", err)
	}
	if got.Owner != "hanzo" || got.Name != "mallory" {
		t.Fatalf("key resolved to %s/%s, want hanzo/mallory", got.Owner, got.Name)
	}

	// REVOKE must clear it on the same real row.
	resp, body = do(t, app, keyReq(PathKeysRevoke, "hanzo-console", "top-secret", "?id=hanzo/mallory"))
	if resp.StatusCode != 200 {
		t.Fatalf("revoke status=%d body=%s", resp.StatusCode, body)
	}
	if u, _ := store.GetUserByName(tctx(), db, "hanzo", "mallory"); u.AccessKey != "" {
		t.Fatalf("AccessKey after revoke=%q, want empty", u.AccessKey)
	}
}

// The pk- fix, end to end on the ONE mint: `?type=publishable` yields a PUBLISHABLE
// key. Before this there was no endpoint anywhere that minted one — IAM owned the
// model, the resolver and the ingest door, and nothing produced the credential they
// were written for, so every surface configured its own thing and error reporting
// stayed a separate DSN.
//
// The type is a FIELD on the one mint, never a second endpoint: the two classes of key
// differ in what they may do, not in what you call to get one.
func TestMintUserKeys_publishableType_mintsAPkAndNeverAPrincipal(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	resp, body := do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/alice&type=publishable"))
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d; body=%s", resp.StatusCode, body)
	}
	key, _ := dataMap(t, body)["accessKey"].(string)
	if !strings.HasPrefix(key, "pk-") {
		t.Fatalf("accessKey = %q, want a pk- publishable key", key)
	}

	// It resolves to an ORG at the ingest door…
	k, err := store.PublishableKeyByAccessKey(context.Background(), db, key, time.Now())
	if err != nil || k == nil {
		t.Fatalf("the minted publishable key does not resolve at the ingest door: %v", err)
	}
	if k.Owner != "hanzo" {
		t.Fatalf("publishable key resolved to org %q, want hanzo", k.Owner)
	}
	// …and to NOBODY as a principal. This is the property that makes it safe to ship
	// in a browser bundle, and it must hold for a key we minted ourselves.
	if u, err := store.UserByAccessKey(context.Background(), db, key); err == nil && u != nil {
		t.Fatalf("a publishable key resolved to principal %s/%s — it must never authenticate", u.Owner, u.Name)
	}
}

// A publishable mint must not disturb the SECRET credential, and vice versa: they are
// two keys with opposite exposure, and rotating the browser key cannot be allowed to
// sign the holder out of their own API.
func TestMintUserKeys_publishableAndSecretCoexist(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	_, secretBody := do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/alice"))
	secret, _ := dataMap(t, secretBody)["accessKey"].(string)
	_, pubBody := do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/alice&type=publishable"))
	pub, _ := dataMap(t, pubBody)["accessKey"].(string)
	if !strings.HasPrefix(secret, "sk-") || !strings.HasPrefix(pub, "pk-") {
		t.Fatalf("halves = %q / %q, want sk- and pk-", secret, pub)
	}
	if u, err := store.UserByAccessKey(context.Background(), db, secret); err != nil || u == nil {
		t.Fatalf("minting the publishable key broke the secret key: %v", err)
	}

	// Revoking the PUBLISHABLE key is scoped: the secret key still authenticates.
	resp, body := do(t, app, keyReq(PathKeysRevoke, "hanzo-console", "top-secret", "?id=hanzo/alice&type=publishable"))
	if resp.StatusCode != 200 {
		t.Fatalf("scoped revoke status = %d; body=%s", resp.StatusCode, body)
	}
	if _, err := store.PublishableKeyByAccessKey(context.Background(), db, pub, time.Now()); err == nil {
		t.Fatal("the publishable key survived its own revoke")
	}
	if u, err := store.UserByAccessKey(context.Background(), db, secret); err != nil || u == nil {
		t.Fatalf("revoking the publishable key revoked the secret key: %v", err)
	}
}

// An unknown type is REFUSED, not silently defaulted. Defaulting would hand a caller
// that asked for a browser-safe key a session-equivalent secret instead — the failure
// mode is a credential in the wrong place, so it must be loud.
func TestMintUserKeys_unknownType_400(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-console")
	app, db := newServer(t)
	seedApp(t, db, appOpts{clientID: "hanzo-console", secret: "top-secret"})
	seedUser(t, db, "alice", "alice@hanzo.ai", "pw")

	for _, typ := range []string{"public", "publishible", "sk", "SECRET"} {
		resp, body := do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/alice&type="+typ))
		if resp.StatusCode != 400 {
			t.Fatalf("type=%q status = %d, want 400; body=%s", typ, resp.StatusCode, body)
		}
	}
	// And the two spellings that ARE the contract still work.
	for _, typ := range []string{"", "secret", "publishable"} {
		resp, body := do(t, app, keyReq(PathKeysMint, "hanzo-console", "top-secret", "?id=hanzo/alice&type="+typ))
		if resp.StatusCode != 200 {
			t.Fatalf("type=%q status = %d, want 200; body=%s", typ, resp.StatusCode, body)
		}
	}
}
