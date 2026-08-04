// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package compat_test

// GAP B — get-user?accessKey: cloud's identity boundary resolves an opaque SECRET API
// key (sk-) to {owner,name,email,isAdmin} to authenticate a keyed request. It is
// SECURITY-CRITICAL: the caller presents a secret key and learns who it belongs to,
// so it is gated behind the CapKeyResolve service capability, fails closed on an
// unknown key, and NEVER leaks a secret field — in particular never the resolved
// user's OTHER credential (the value on its User row) on an sk- resolution. A PUBLIC
// pk- is write-only and is REFUSED here (its org-only dual is /v1/iam/resolve-key).

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"

	"github.com/hanzoai/iam/internal/testhttp"
)

const (
	resolverApp = "hanzo-cloud"     // admin-owned service app that holds CapKeyResolve
	otherApp    = "hanzo-noresolve" // admin-owned app WITHOUT the capability
	svcSecret   = "resolver-secret"

	// A value stamped on schema.User.AccessKey. NOTHING resolves that field, so this
	// authenticates nobody — it is a sentinel proving both that a user-row value is
	// never a credential and that its retired prefix is not a key shape.
	userRowKey        = "hk-live-KEYUSERHK"
	keyUserSecretHash = "SENTINEL_ACCESS_SECRET_HASH"
	projPK            = "pk-live-KEYUSERPK"       // publishable half of a schema.Key
	projSK            = "sk-live-KEYUSERPKSECRET" // confidential half of the same Key
)

// keyEnv decodes the single-object get-user envelope.
type keyEnv struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Code   string `json:"code"`
	Data   struct {
		Owner   string `json:"owner"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		IsAdmin bool   `json:"isAdmin"`
	} `json:"data"`
}

// getBasic drives a get through the real router authenticating as a confidential
// client (client_secret_basic) — how cloud's key resolver authenticates to IAM.
func (h *harness) getBasic(t *testing.T, path, clientID, secret string) (int, string) {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	req.Host = "hanzo.id"
	req.SetBasicAuth(clientID, secret)
	resp, err := testhttp.Do(h.app, req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, string(b)
}

// keyFixtures seeds the two service apps, the target user (with secret sentinels and a
// non-resolving value on its User row), and a schema.Key (pk-/sk-) belonging to that
// user; then arms the CapKeyResolve allowlist with resolverApp only.
func keyFixtures(t *testing.T, h *harness) {
	t.Helper()
	seedClientApp(t, h.db, resolverApp, svcSecret)
	seedClientApp(t, h.db, otherApp, svcSecret)

	u := orm.New[schema.User](h.db)
	u.Owner, u.Name, u.Email = "hanzo", "keyuser", "keyuser@hanzo.ai"
	u.IsAdmin = true
	u.AccessKey = userRowKey
	u.AccessSecret = projSK // a secret half on the user row too — must never surface
	u.AccessSecretHash = keyUserSecretHash
	u.PasswordHash = secretUserHash
	u.SetId("hanzo/keyuser")
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed key user: %v", err)
	}

	k := orm.New[schema.Key](h.db)
	k.Owner, k.Name, k.User = "hanzo", "keyuser-key", "hanzo/keyuser"
	k.AccessKey, k.AccessSecret = projPK, projSK
	k.SetId("hanzo/keyuser-key")
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed key: %v", err)
	}

	t.Setenv("IAM_KEY_RESOLVE_APPS", resolverApp)
}

func seedClientApp(t *testing.T, db orm.DB, name, secret string) {
	t.Helper()
	a := orm.New[schema.Application](db)
	a.Owner, a.Name = "admin", name // admin-owned → the CapKeyResolve owner-pin holds
	a.Organization = "hanzo"
	a.ClientId = name
	a.ClientSecret = secret
	a.SetId("admin/" + name)
	if err := a.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed client app: %v", err)
	}
}

// A cap-holding service caller resolves the SECRET key shape to the right user, with
// the exact {owner,name,email,isAdmin} cloud consumes — and NO secret ever appears —
// while the PUBLIC publishable pk- is REFUSED, so a public key can never become a read
// principal at cloud's identity boundary.
func TestGetUserByAccessKey_ResolvesSecretsRefusesPublishable(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	for _, tc := range []struct{ name, key string }{
		{"sk confidential half", projSK},
	} {
		status, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+tc.key, resolverApp, svcSecret)
		if status != 200 {
			t.Fatalf("%s: status=%d body=%s", tc.name, status, body)
		}
		var e keyEnv
		if err := json.Unmarshal([]byte(body), &e); err != nil {
			t.Fatalf("%s: envelope: %v body=%s", tc.name, err, body)
		}
		if e.Status != "ok" {
			t.Fatalf("%s: status=%q body=%s", tc.name, e.Status, body)
		}
		if e.Data.Owner != "hanzo" || e.Data.Name != "keyuser" ||
			e.Data.Email != "keyuser@hanzo.ai" || !e.Data.IsAdmin {
			t.Fatalf("%s: data=%+v, want hanzo/keyuser keyuser@hanzo.ai isAdmin=true", tc.name, e.Data)
		}
		// No secret material, and — critically — not the user's OTHER credential
		// (the value on its User row) when an sk- key was the one presented.
		for _, secret := range []string{secretUserHash, keyUserSecretHash, userRowKey} {
			if tc.key != secret && strings.Contains(body, secret) {
				t.Fatalf("%s: SECRET LEAK %q in body:\n%s", tc.name, secret, body)
			}
		}
	}

	// The PUBLIC pk- publishable half is WRITE-ONLY: get-user?accessKey REFUSES it, even
	// to the cap-holding service caller, so a public key never becomes a read principal.
	status, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+projPK, resolverApp, svcSecret)
	var e keyEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Msg != "the entity does not exist" {
		t.Fatalf("publishable pk- via get-user?accessKey: status=%d env=%+v — a pk- must never resolve to a principal", status, e)
	}
	if strings.Contains(body, "keyuser") {
		t.Fatalf("publishable pk- leaked the principal identity: %s", body)
	}
}

// There are exactly TWO key shapes. A value carrying a retired prefix is not a key —
// not a deprecated one, not an accepted-for-now one — and it authenticates NOBODY even
// when that exact value is stamped on a real, live user's row.
//
// This is the sharp end of the one-way property: keyFixtures puts userRowKey on
// hanzo/keyuser, so a resurrected prefix branch (or any new read of
// schema.User.AccessKey as a credential) would resolve it to an ADMIN principal and
// fail here loudly. The refusal must also carry key_unknown, which is what renders the
// actionable "mint a new one at cloud.hanzo.ai/keys" for the holder — never
// key_wrong_door, whose advice ("use your secret key") would be a lie to someone whose
// credential no longer exists.
func TestGetUserByAccessKey_RetiredPrefixIsNotAKey(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	_, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+userRowKey, resolverApp, svcSecret)
	var e keyEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" {
		t.Fatalf("a retired prefix resolved: env=%+v body=%s", e, body)
	}
	if e.Code != "key_unknown" {
		t.Errorf("code = %q, want key_unknown (the actionable 'mint a new one' path)", e.Code)
	}
	if strings.Contains(body, "keyuser") {
		t.Fatalf("a retired prefix leaked the principal identity: %s", body)
	}
}

// F1 REGRESSION — end to end: a forged Key (planted in the attacker's own org but
// pointing User at the reserved admin org = SuperAdmin) must yield NO identity
// through the real get-user?accessKey path, even to the cap-holding service caller.
func TestGetUserByAccessKey_CrossTenantForgeryDenied(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	// admin/root already exists in the harness (a SuperAdmin). Plant a Key in
	// "attackerOrg" whose User names it, with a KNOWN secret. Seeded directly (the
	// write-side gate would also reject it via the API).
	k := orm.New[schema.Key](h.db)
	k.Owner, k.Name, k.User = "attackerOrg", "forge", "admin/root"
	k.AccessKey, k.AccessSecret = "pk-live-FORGE", "sk-live-FORGE"
	k.SetId("attackerOrg/forge")
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed forged key: %v", err)
	}

	for _, key := range []string{"pk-live-FORGE", "sk-live-FORGE"} {
		_, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+key, resolverApp, svcSecret)
		var e keyEnv
		_ = json.Unmarshal([]byte(body), &e)
		if e.Status != "error" || e.Msg != "the entity does not exist" {
			t.Fatalf("FORGERY resolved via %q: env=%+v body=%s", key, e, body)
		}
		if strings.Contains(body, "\"admin\"") || strings.Contains(body, "\"root\"") {
			t.Fatalf("FORGERY leaked the SuperAdmin identity via %q: %s", key, body)
		}
	}
}

// A caller WITHOUT the capability is refused with v1's verbatim message, whether it
// is an app not on the allowlist or (implicitly) a human — never a resolved user.
func TestGetUserByAccessKey_NonCapDenied(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	status, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+projSK, otherApp, svcSecret)
	var e keyEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Msg != "auth:Unauthorized operation" {
		t.Fatalf("non-cap resolve status=%d env=%+v, want error auth:Unauthorized operation", status, e)
	}
	if strings.Contains(body, "keyuser") {
		t.Fatalf("non-cap caller learned the principal: %s", body)
	}
}

// An unknown key resolves to the not-exist envelope — fail closed, no principal.
func TestGetUserByAccessKey_UnknownKeyNotFound(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	_, body := h.getBasic(t, "/v1/iam/get-user?accessKey=hk-live-NOSUCHKEY", resolverApp, svcSecret)
	var e keyEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Msg != "the entity does not exist" {
		t.Fatalf("unknown key env=%+v, want error 'the entity does not exist'", e)
	}
}

// An EMPTY accessKey does not trigger key resolution — it falls through to the
// ordinary owner/name read, which a SuperAdmin serves as before.
func TestGetUserByAccessKey_EmptyFallsThrough(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	// Empty accessKey + an id: the handler must take the owner/name path, not the key
	// path (which would demand CapKeyResolve the human super does not hold as an app).
	status, body := h.get(t, "/v1/iam/get-user?accessKey=&id=hanzo/alice", h.token(t, "admin/root"))
	if status != 200 || !strings.Contains(body, "alice") {
		t.Fatalf("empty accessKey did not fall through to owner/name read: status=%d body=%s", status, body)
	}
}

// The refusal REASON reaches the wire while the human sentence stays uniform.
//
// "the entity does not exist" is IAM's generic answer, and cloud rendered it verbatim
// to users: a holder whose key had been revoked was told their entity was gone and
// went looking for a deleted organization instead of minting a new key. The prose is
// deliberately unchanged — nothing that reads `msg` can tell the causes apart — and
// the machine-readable `code` carries the reason to the confidential app that already
// passed CapKeyResolve to get here.
func TestGetUserByAccessKey_RefusalCarriesItsReason(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	for _, tc := range []struct{ name, key, wantCode string }{
		{"revoked / never minted", "sk-live-NOSUCHKEY2", "key_unknown"},
		{"unknown secret half", "sk-live-NOSUCHKEY", "key_unknown"},
		{"a publishable key at the SECRET door", projPK, "key_wrong_door"},
		{"an unrecognized shape", "fw_deadbeef", "key_unknown"},
		{"a retired prefix", "hk-live-NOSUCHKEY", "key_unknown"},
	} {
		_, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+tc.key, resolverApp, svcSecret)
		var e keyEnv
		_ = json.Unmarshal([]byte(body), &e)
		if e.Status != "error" || e.Msg != "the entity does not exist" {
			t.Fatalf("%s: env=%+v — the human sentence must stay uniform", tc.name, e)
		}
		if e.Code != tc.wantCode {
			t.Errorf("%s: code = %q, want %q", tc.name, e.Code, tc.wantCode)
		}
		// The credential must never be echoed back, in any field.
		if strings.Contains(body, tc.key) {
			t.Errorf("%s: the refusal echoed the presented key: %s", tc.name, body)
		}
	}
}

// The AUTH refusal is not a key reason. A caller that fails the CapKeyResolve gate
// gets the unauthorized envelope and NO code at all — so a non-cap caller can never
// use `code` as an existence oracle for keys it may not resolve.
func TestGetUserByAccessKey_NonCapCallerLearnsNoReason(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	_, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+projSK, otherApp, svcSecret)
	var e keyEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Code != "" {
		t.Fatalf("non-cap caller env=%+v, want an error with NO code", e)
	}
}
