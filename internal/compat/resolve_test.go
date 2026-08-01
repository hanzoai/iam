// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package compat_test

// resolve-key: the WRITE-ONLY ingest door and dual of get-user?accessKey. These tests
// drive the REAL mounted router (routes.Route: the authz Guard authenticates the
// confidential client, resolve-key is handler-authorized and cap-gated) and prove the
// load-bearing property — a PUBLIC publishable pk- resolves to just an ORG, never a
// principal, on EVERY door:
//   - resolve-key turns it into {org, scope} and nothing else (the org-only projection);
//   - a SECRET key's pk- half, an sk-, an expired/unknown key, a non-cap app, and a
//     human are all refused;
//   - and the same pk- presented to get-user?accessKey (even by a CapKeyResolve holder)
//     or as a bearer to a gated route yields NO principal.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

const (
	pubResolverApp = "hanzo-cloud-ingest"   // admin-owned app holding CapPublishableResolve
	pubOtherApp    = "hanzo-cloud-noingest" // admin-owned app WITHOUT the capability
	pubSecret      = "ingest-resolver-secret"

	sitePK      = "pk-live-SITEKEY"    // a WRITE-ONLY publishable key (Scope=publish)
	secretKeyPK = "pk-live-SERVERHALF" // the pk- half of a SECRET (default) key
	secretKeySK = "sk-live-SERVERHALF" // the sk- half of that same secret key
)

// resolveEnv decodes the resolve-key envelope. Org/Scope are the org-only projection;
// Owner/Name/Email/IsAdmin are SENTINELS — if resolve-key ever discloses a principal,
// they surface.
type resolveEnv struct {
	Status string `json:"status"`
	Msg    string `json:"msg"`
	Data   struct {
		Org     string `json:"org"`
		Scope   string `json:"scope"`
		Owner   string `json:"owner"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		IsAdmin bool   `json:"isAdmin"`
	} `json:"data"`
}

// pubKeyFixtures seeds the two ingest-resolver apps, a WRITE-ONLY publishable key and a
// SECRET key (both owned by hanzo), and arms IAM_PUBLISHABLE_RESOLVE_APPS with the
// resolver app only.
func pubKeyFixtures(t *testing.T, h *harness) {
	t.Helper()
	seedClientApp(t, h.db, pubResolverApp, pubSecret)
	seedClientApp(t, h.db, pubOtherApp, pubSecret)

	// A publishable (write-only) key: Scope=publish, pk- only, no user, owned by hanzo.
	pk := orm.New[schema.Key](h.db)
	pk.Owner, pk.Name = "hanzo", "site"
	pk.Scope = schema.KeyScopePublish
	pk.AccessKey = sitePK
	pk.SetId("hanzo/site")
	if err := pk.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed publish key: %v", err)
	}

	// A SECRET (default, Scope="") key: pk- + sk-, referencing hanzo/boss (a real user
	// the harness seeds). Its pk- half must NEVER resolve via resolve-key.
	sk := orm.New[schema.Key](h.db)
	sk.Owner, sk.Name, sk.User = "hanzo", "server", "hanzo/boss"
	sk.AccessKey, sk.AccessSecret = secretKeyPK, secretKeySK
	sk.SetId("hanzo/server")
	if err := sk.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed secret key: %v", err)
	}

	t.Setenv("IAM_PUBLISHABLE_RESOLVE_APPS", pubResolverApp)
}

// A publishable pk- resolves to just the ORG that holds it — org and scope, and NO
// principal field of any kind.
func TestResolveKey_ResolvesOrgOnly(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)

	status, body := h.getBasic(t, "/v1/iam/resolve-key?accessKey="+sitePK, pubResolverApp, pubSecret)
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var e resolveEnv
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("envelope: %v body=%s", err, body)
	}
	if e.Status != "ok" || e.Data.Org != "hanzo" || e.Data.Scope != schema.KeyScopePublish {
		t.Fatalf("resolve = %+v, want ok org=hanzo scope=publish; body=%s", e, body)
	}
	// ORG-ONLY: no principal field is populated, and no principal-only key appears in
	// the raw body — resolve-key discloses WHICH org, never WHO.
	if e.Data.Owner != "" || e.Data.Name != "" || e.Data.Email != "" || e.Data.IsAdmin {
		t.Fatalf("resolve-key disclosed a principal: %+v", e.Data)
	}
	for _, principalKey := range []string{`"email"`, `"isAdmin"`, `"name"`, `"owner"`} {
		if strings.Contains(body, principalKey) {
			t.Fatalf("resolve-key body carries a principal field %s: %s", principalKey, body)
		}
	}
}

// A SECRET key's pk- half (Scope != publish) and its sk- half are BOTH refused: the
// door serves only keys explicitly minted as browser keys, and an sk- never matches the
// pk- prefix.
func TestResolveKey_RefusesNonPublishable(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)

	for _, tc := range []struct{ name, key string }{
		{"secret key's pk- half", secretKeyPK},
		{"an sk- confidential half", secretKeySK},
		{"an hk-", "hk-live-anything"},
		{"unknown pk-", "pk-live-NOSUCH"},
		{"empty", ""},
	} {
		status, body := h.getBasic(t, "/v1/iam/resolve-key?accessKey="+tc.key, pubResolverApp, pubSecret)
		var e resolveEnv
		_ = json.Unmarshal([]byte(body), &e)
		if e.Status != "error" || e.Msg != "the entity does not exist" {
			t.Fatalf("%s: status=%d env=%+v, want error 'the entity does not exist'", tc.name, status, e)
		}
		if e.Data.Org != "" {
			t.Fatalf("%s: leaked org %q on a refusal", tc.name, e.Data.Org)
		}
	}
}

// An expired publishable key is refused — resolve-key honors only a live key.
func TestResolveKey_RefusesExpired(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)

	k := orm.New[schema.Key](h.db)
	k.Owner, k.Name = "hanzo", "expired"
	k.Scope = schema.KeyScopePublish
	k.AccessKey = "pk-live-EXPIRED"
	k.ExpireTime = "2020-01-01T00:00:00Z"
	k.SetId("hanzo/expired")
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed expired key: %v", err)
	}

	_, body := h.getBasic(t, "/v1/iam/resolve-key?accessKey=pk-live-EXPIRED", pubResolverApp, pubSecret)
	var e resolveEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Data.Org != "" {
		t.Fatalf("expired key resolved: env=%+v body=%s", e, body)
	}
}

// A confidential app WITHOUT CapPublishableResolve is refused — no org disclosed. This
// is the least-privilege gate: holding some capability does not grant this one.
func TestResolveKey_NonCapAppDenied(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)

	status, body := h.getBasic(t, "/v1/iam/resolve-key?accessKey="+sitePK, pubOtherApp, pubSecret)
	var e resolveEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Msg != "auth:Unauthorized operation" {
		t.Fatalf("non-cap resolve status=%d env=%+v, want error auth:Unauthorized operation", status, e)
	}
	if e.Data.Org != "" {
		t.Fatalf("non-cap caller learned the org: %s", body)
	}
}

// A HUMAN — even a SuperAdmin bearer — is refused: key resolution is a machine-identity
// boundary (a capability is vacuous for a non-app), so resolve-key is app-only.
func TestResolveKey_HumanDenied(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)

	status, body := h.get(t, "/v1/iam/resolve-key?accessKey="+sitePK, h.token(t, "admin/root"))
	var e resolveEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Msg != "auth:Unauthorized operation" {
		t.Fatalf("human (SuperAdmin) resolve status=%d env=%+v, want error auth:Unauthorized operation", status, e)
	}
	if e.Data.Org != "" {
		t.Fatalf("human caller learned the org: %s", body)
	}
}

// THE INVARIANT, end to end: the SAME publishable pk- that resolve-key turns into an
// org can NEVER become a principal — not via get-user?accessKey (even for a caller that
// holds CapKeyResolve and CAN resolve secret keys), and not as a bearer to a gated
// route. A public key authenticates no read, anywhere.
func TestResolveKey_PublishableNeverBecomesPrincipal(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)
	// Grant the resolver app BOTH capabilities: it CAN resolve secret keys to principals
	// (CapKeyResolve), yet the publishable pk- is still refused there.
	t.Setenv("IAM_KEY_RESOLVE_APPS", pubResolverApp)

	// Control: resolve-key DOES turn the publishable pk- into an org.
	if _, body := h.getBasic(t, "/v1/iam/resolve-key?accessKey="+sitePK, pubResolverApp, pubSecret); !strings.Contains(body, `"org":"hanzo"`) {
		t.Fatalf("control: resolve-key should resolve the publishable pk- to an org: %s", body)
	}
	// Control: get-user?accessKey DOES resolve a SECRET sk- to its principal.
	if _, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+secretKeySK, pubResolverApp, pubSecret); !strings.Contains(body, "boss") {
		t.Fatalf("control: get-user?accessKey should resolve the secret sk- to its user: %s", body)
	}

	// The publishable pk- via get-user?accessKey → NO principal (write-only), even for a
	// CapKeyResolve holder.
	_, body := h.getBasic(t, "/v1/iam/get-user?accessKey="+sitePK, pubResolverApp, pubSecret)
	var ke keyEnv
	_ = json.Unmarshal([]byte(body), &ke)
	if ke.Status != "error" || ke.Msg != "the entity does not exist" {
		t.Fatalf("publishable pk- via get-user?accessKey resolved a principal: env=%+v body=%s", ke, body)
	}
	if strings.Contains(body, "hanzo/") || strings.Contains(body, `"isAdmin"`) {
		t.Fatalf("publishable pk- leaked identity via get-user: %s", body)
	}

	// The publishable pk- presented as a BEARER to a gated route → 401 (never a
	// principal — it is not a token, and it can never become one).
	status, _ := h.get(t, "/v1/iam/keys?owner=hanzo", sitePK)
	if status != 401 {
		t.Fatalf("publishable pk- as bearer to a gated route: status=%d, want 401", status)
	}
}
