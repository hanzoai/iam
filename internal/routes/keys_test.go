// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package routes_test

// The two key doors, driven through the mounted router.
//
// /v1/iam/keys/principal is cloud's identity boundary: a caller presents an
// opaque SECRET key and learns who holds it. That makes it security-critical in
// both directions — it is gated behind the CapKeyResolve service capability, it
// fails closed on an unknown key, and it never returns a secret field, in
// particular never the resolved user's OTHER credential.
//
// /v1/iam/keys/org is its dual and cloud's ingest boundary: a PUBLISHABLE pk- is
// write-only, so it resolves to the ORG that holds it and to no principal at all.
// A pk- presented at the principal door is refused, which is the property that
// lets a pk- ship in browser JavaScript.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

const (
	principalDoor = "/v1/iam/keys/principal?accessKey="
	orgDoor       = "/v1/iam/keys/org?accessKey="
)

const (
	resolverApp = "hanzo-cloud"     // admin-owned service app holding CapKeyResolve
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

const (
	pubResolverApp = "hanzo-cloud-ingest"   // admin-owned app holding CapPublishableResolve
	pubOtherApp    = "hanzo-cloud-noingest" // admin-owned app WITHOUT the capability
	pubSecret      = "ingest-resolver-secret"

	sitePK      = "pk-live-SITEKEY"    // a WRITE-ONLY publishable key (Scope=publish)
	secretKeyPK = "pk-live-SERVERHALF" // the pk- half of a SECRET (default) key
	secretKeySK = "sk-live-SERVERHALF" // the sk- half of that same secret key
)

// keyEnv decodes the principal door's envelope.
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

// resolveEnv decodes the org door's envelope. Org/Scope are the org-only
// projection; Owner/Name/Email/IsAdmin are SENTINELS — if the door ever discloses
// a principal, they surface.
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
	// the harness seeds). Its pk- half must NEVER resolve at the org door.
	sk := orm.New[schema.Key](h.db)
	sk.Owner, sk.Name, sk.User = "hanzo", "server", "hanzo/boss"
	sk.AccessKey, sk.AccessSecret = secretKeyPK, secretKeySK
	sk.SetId("hanzo/server")
	if err := sk.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed secret key: %v", err)
	}

	t.Setenv("IAM_PUBLISHABLE_RESOLVE_APPS", pubResolverApp)
}

// ---- the principal door ----------------------------------------------------

// A cap-holding service caller resolves the SECRET key shape to the right user, with
// the exact {owner,name,email,isAdmin} cloud consumes — and NO secret ever appears —
// while the PUBLIC publishable pk- is REFUSED, so a public key can never become a read
// principal at cloud's identity boundary.
func TestPrincipalDoor_ResolvesSecretsRefusesPublishable(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	status, body := h.getBasic(t, principalDoor+projSK, resolverApp, svcSecret)
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var e keyEnv
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("envelope: %v body=%s", err, body)
	}
	if e.Status != "ok" {
		t.Fatalf("status=%q body=%s", e.Status, body)
	}
	if e.Data.Owner != "hanzo" || e.Data.Name != "keyuser" ||
		e.Data.Email != "keyuser@hanzo.ai" || !e.Data.IsAdmin {
		t.Fatalf("data=%+v, want hanzo/keyuser keyuser@hanzo.ai isAdmin=true", e.Data)
	}
	// No secret material, and — critically — not the user's OTHER credential
	// (the value on its User row) when an sk- key was the one presented.
	for _, secret := range []string{secretUserHash, keyUserSecretHash, userRowKey} {
		if strings.Contains(body, secret) {
			t.Fatalf("SECRET LEAK %q in body:\n%s", secret, body)
		}
	}

	// The PUBLIC pk- publishable half is WRITE-ONLY: the principal door REFUSES it,
	// even to the cap-holding service caller, so a public key never becomes a read
	// principal.
	status, body = h.getBasic(t, principalDoor+projPK, resolverApp, svcSecret)
	var pub keyEnv
	_ = json.Unmarshal([]byte(body), &pub)
	if pub.Status != "error" || pub.Msg != "the entity does not exist" {
		t.Fatalf("publishable pk- at the principal door: status=%d env=%+v — a pk- must never resolve to a principal", status, pub)
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
func TestPrincipalDoor_RetiredPrefixIsNotAKey(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	_, body := h.getBasic(t, principalDoor+userRowKey, resolverApp, svcSecret)
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

// A forged Key — planted in the attacker's own org but pointing User at the
// reserved admin org, so it would resolve to a SuperAdmin — yields NO identity,
// even to the cap-holding service caller.
func TestPrincipalDoor_CrossTenantForgeryDenied(t *testing.T) {
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
		_, body := h.getBasic(t, principalDoor+key, resolverApp, svcSecret)
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
func TestPrincipalDoor_NonCapDenied(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	status, body := h.getBasic(t, principalDoor+projSK, otherApp, svcSecret)
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
func TestPrincipalDoor_UnknownKeyNotFound(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	_, body := h.getBasic(t, principalDoor+"hk-live-NOSUCHKEY", resolverApp, svcSecret)
	var e keyEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Msg != "the entity does not exist" {
		t.Fatalf("unknown key env=%+v, want error 'the entity does not exist'", e)
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
func TestPrincipalDoor_RefusalCarriesItsReason(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	for _, tc := range []struct{ name, key, wantCode string }{
		{"revoked / never minted", "sk-live-NOSUCHKEY2", "key_unknown"},
		{"unknown secret half", "sk-live-NOSUCHKEY", "key_unknown"},
		{"a publishable key at the SECRET door", projPK, "key_wrong_door"},
		{"an unrecognized shape", "fw_deadbeef", "key_unknown"},
		{"a retired prefix", "hk-live-NOSUCHKEY", "key_unknown"},
	} {
		_, body := h.getBasic(t, principalDoor+tc.key, resolverApp, svcSecret)
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
func TestPrincipalDoor_NonCapCallerLearnsNoReason(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	_, body := h.getBasic(t, principalDoor+projSK, otherApp, svcSecret)
	var e keyEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Code != "" {
		t.Fatalf("non-cap caller env=%+v, want an error with NO code", e)
	}
}

// A MACHINE key resolves to the ORG POOL, and the wire says so.
//
// This is the money defect on the key door. account.Payer falls back to a shape
// rule when nothing names a payer, and that rule hands anyone in the signup org a
// PERSONAL wallet. A service account has no person, so "hanzo/<name>" is a wallet
// no funding path can name — an admin grant credits the pool, a deposit names a
// real member — and it reads $0 forever. The projection omitted the payer
// entirely, so every first-party service key 402'd ("Insufficient balance")
// against an org pool holding millions, and minting a fresh key never helped:
// every new key resolved exactly the same way.
//
// The assertion is on the RAW BODY because the field is a WIRE CONTRACT with the
// gateway's resolver (it decodes into iam.User's `billing_account`); a struct that
// agrees with itself would prove nothing about the name on the wire.
func TestPrincipalDoor_MachineNamesTheOrgPool(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	// Make the resolved principal a machine — what a service account IS.
	u, err := store.GetUserByName(context.Background(), h.db, "hanzo", "keyuser")
	if err != nil || u == nil {
		t.Fatalf("load key user: %v", err)
	}
	u.Type = schema.ServiceAccount
	if err := u.UpdateCtx(context.Background()); err != nil {
		t.Fatalf("mark service account: %v", err)
	}

	status, body := h.getBasic(t, principalDoor+projSK, resolverApp, svcSecret)
	if status != 200 {
		t.Fatalf("resolve: status=%d body=%s", status, body)
	}
	if !strings.Contains(body, `"billing_account":"org:hanzo"`) {
		t.Fatalf("key resolution named no ledger — the gateway will fall back to a ghost personal wallet and 402: %s", body)
	}
}

// The principal door resolves a KEY and nothing else. A ?id= would make it a
// second address for the user read, which is the thing being retired; without
// this the door would look migrated and quietly widen what it answers.
func TestPrincipalDoor_ReadsKeysOnly(t *testing.T) {
	h := newHarness(t)
	keyFixtures(t, h)

	status, body := h.getBasic(t, "/v1/iam/keys/principal?id=hanzo/keyuser", resolverApp, svcSecret)
	if status == 200 && len(body) > 0 && body[0] == '{' {
		var e keyEnv
		if err := json.Unmarshal([]byte(body), &e); err == nil && e.Status == "ok" && e.Data.Owner != "" {
			t.Errorf("?id= resolved a user at the key door: %s", body)
		}
	}
}

// ---- the org door ----------------------------------------------------------

// A publishable pk- resolves to just the ORG that holds it — org and scope, and NO
// principal field of any kind.
func TestOrgDoor_ResolvesOrgOnly(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)

	status, body := h.getBasic(t, orgDoor+sitePK, pubResolverApp, pubSecret)
	if status != 200 {
		t.Fatalf("status=%d body=%s", status, body)
	}
	var e resolveEnv
	if err := json.Unmarshal([]byte(body), &e); err != nil {
		t.Fatalf("envelope: %v body=%s", err, body)
	}
	if e.Status != "ok" || e.Data.Org != "hanzo" || e.Data.Scope != schema.KeyScopePublish {
		t.Fatalf("env=%+v, want ok org=hanzo scope=%s", e, schema.KeyScopePublish)
	}
	// NOT A PRINCIPAL. The projection carries no user field at all, so no pk- can
	// ever become a way to learn who anyone is.
	if e.Data.Owner != "" || e.Data.Name != "" || e.Data.Email != "" || e.Data.IsAdmin {
		t.Fatalf("the org door disclosed a principal: %+v", e.Data)
	}
	for _, principalKey := range []string{`"email"`, `"isAdmin"`, `"name"`, `"owner"`} {
		if strings.Contains(body, principalKey) {
			t.Fatalf("the org door body carries a principal field %s: %s", principalKey, body)
		}
	}
}

// A SECRET key's pk- half (Scope != publish) and its sk- half are BOTH refused: the
// door serves only keys explicitly minted as browser keys, and an sk- never matches the
// pk- prefix.
func TestOrgDoor_RefusesNonPublishable(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)

	for _, tc := range []struct{ name, key string }{
		{"secret key's pk- half", secretKeyPK},
		{"an sk- confidential half", secretKeySK},
		{"a retired prefix", "hk-live-anything"},
		{"unknown pk-", "pk-live-NOSUCH"},
		{"empty", ""},
	} {
		status, body := h.getBasic(t, orgDoor+tc.key, pubResolverApp, pubSecret)
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

// An expired publishable key does not resolve, and the refusal says so — which is
// what lets the holder be told to re-mint instead of hunting a configuration
// error.
func TestOrgDoor_RefusesExpired(t *testing.T) {
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

	_, body := h.getBasic(t, orgDoor+"pk-live-EXPIRED", pubResolverApp, pubSecret)
	var e resolveEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Data.Org != "" {
		t.Fatalf("an expired key resolved: env=%+v body=%s", e, body)
	}
}

// A confidential app WITHOUT CapPublishableResolve learns nothing — not the org,
// not whether the key exists.
func TestOrgDoor_NonCapAppDenied(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)

	_, body := h.getBasic(t, orgDoor+sitePK, pubOtherApp, pubSecret)
	var e resolveEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Msg != "auth:Unauthorized operation" {
		t.Fatalf("non-cap app env=%+v, want error auth:Unauthorized operation", e)
	}
	if e.Data.Org != "" {
		t.Fatalf("non-cap app learned the org: %s", body)
	}
}

// A HUMAN is refused, even a SuperAdmin. A capability is held vacuously by a
// non-app, so key resolution is a machine boundary and never an interactive admin
// action.
func TestOrgDoor_HumanDenied(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)

	_, body := h.get(t, orgDoor+sitePK, h.token(t, "admin/root"))
	var e resolveEnv
	_ = json.Unmarshal([]byte(body), &e)
	if e.Status != "error" || e.Msg != "auth:Unauthorized operation" {
		t.Fatalf("a SuperAdmin human resolved a key: env=%+v body=%s", e, body)
	}
}

// THE INVARIANT, end to end: the SAME publishable pk- the org door turns into an
// org can NEVER become a principal — not at the principal door (even for a caller
// that holds CapKeyResolve and CAN resolve secret keys), and not as a bearer to a
// gated route. A public key authenticates no read, anywhere.
func TestPublishableNeverBecomesPrincipal(t *testing.T) {
	h := newHarness(t)
	pubKeyFixtures(t, h)
	// Grant the resolver app BOTH capabilities: it CAN resolve secret keys to principals
	// (CapKeyResolve), yet the publishable pk- is still refused there.
	t.Setenv("IAM_KEY_RESOLVE_APPS", pubResolverApp)

	// Control: the org door DOES turn the publishable pk- into an org.
	if _, body := h.getBasic(t, orgDoor+sitePK, pubResolverApp, pubSecret); !strings.Contains(body, `"org":"hanzo"`) {
		t.Fatalf("control: the org door should resolve the publishable pk- to an org: %s", body)
	}
	// Control: the principal door DOES resolve a SECRET sk- to its principal.
	if _, body := h.getBasic(t, principalDoor+secretKeySK, pubResolverApp, pubSecret); !strings.Contains(body, "boss") {
		t.Fatalf("control: the principal door should resolve the secret sk- to its user: %s", body)
	}

	// The publishable pk- at the principal door → NO principal (write-only), even for
	// a CapKeyResolve holder.
	_, body := h.getBasic(t, principalDoor+sitePK, pubResolverApp, pubSecret)
	var ke keyEnv
	_ = json.Unmarshal([]byte(body), &ke)
	if ke.Status != "error" || ke.Msg != "the entity does not exist" {
		t.Fatalf("publishable pk- at the principal door resolved a principal: env=%+v body=%s", ke, body)
	}
	if strings.Contains(body, "hanzo/") || strings.Contains(body, `"isAdmin"`) {
		t.Fatalf("publishable pk- leaked identity at the principal door: %s", body)
	}

	// The publishable pk- presented as a BEARER to a gated route → 401 (never a
	// principal — it is not a token, and it can never become one).
	status, _ := h.get(t, "/v1/iam/keys?owner=hanzo", sitePK)
	if status != 401 {
		t.Fatalf("publishable pk- as bearer to a gated route: status=%d, want 401", status)
	}
}
