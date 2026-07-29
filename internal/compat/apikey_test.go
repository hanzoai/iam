// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package compat_test

// GAP B — get-user?accessKey: cloud's identity boundary resolves an opaque SECRET API
// key (hk-/sk-) to {owner,name,email,isAdmin} to authenticate a keyed request. It is
// SECURITY-CRITICAL: the caller presents a secret key and learns who it belongs to,
// so it is gated behind the CapKeyResolve service capability, fails closed on an
// unknown key, and NEVER leaks a secret field — in particular never the resolved
// user's OTHER credential (its hk- AccessKey) on an sk- resolution. A PUBLIC pk- is
// write-only and is REFUSED here (its org-only dual is /v1/iam/resolve-key).

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"

	"github.com/hanzoai/iam/internal/testhttp"
)

const (
	resolverApp = "hanzo-cloud"     // admin-owned service app that holds CapKeyResolve
	otherApp    = "hanzo-noresolve" // admin-owned app WITHOUT the capability
	svcSecret   = "resolver-secret"

	keyUserHK         = "hk-live-KEYUSERHK" // the user's own durable Cloud API key
	keyUserSecretHash = "SENTINEL_ACCESS_SECRET_HASH"
	projPK            = "pk-live-KEYUSERPK"       // publishable half of a schema.Key
	projSK            = "sk-live-KEYUSERPKSECRET" // confidential half of the same Key
)

// keyEnv decodes the single-object get-user envelope.
type keyEnv struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
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

// keyFixtures seeds the two service apps, the target user (with an hk- key + secret
// sentinels), and a schema.Key (pk-/sk-) belonging to that user; then arms the
// CapKeyResolve allowlist with resolverApp only.
func keyFixtures(t *testing.T, h *harness) {
	t.Helper()
	seedClientApp(t, h.db, resolverApp, svcSecret)
	seedClientApp(t, h.db, otherApp, svcSecret)

	u := orm.New[schema.User](h.db)
	u.Owner, u.Name, u.Email = "hanzo", "keyuser", "keyuser@hanzo.ai"
	u.IsAdmin = true
	u.AccessKey = keyUserHK
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

// A cap-holding service caller resolves each SECRET key shape to the right user, with
// the exact {owner,name,email,isAdmin} cloud consumes — and NO secret ever appears —
// while the PUBLIC publishable pk- is REFUSED, so a public key can never become a read
// principal at cloud's identity boundary.
func TestGetUserByAccessKey_ResolvesSecretsRefusesPublishable(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	for _, tc := range []struct{ name, key string }{
		{"hk on user row", keyUserHK},
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
		// (its hk- key) when an sk- key was the one presented.
		for _, secret := range []string{secretUserHash, keyUserSecretHash, keyUserHK} {
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

	status, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+keyUserHK, otherApp, svcSecret)
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
