// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// seedKeyUser creates the user a resolved key belongs to.
func seedKeyUser(t *testing.T, db orm.DB, owner, name, email, hk string) *schema.User {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email, u.AccessKey = owner, name, email, hk
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	return u
}

// seedKey creates a schema.Key credential (pk-/sk- halves) owned by a tenant and
// referencing user — in the shape the minter WRITES: the digest of the secret and
// no plaintext. A fixture that keeps the plaintext tests a row this estate stopped
// minting, and every resolver bug that only the digest path has would pass under it.
// The one legacy row left is the drain test's, which is what that test is about.
func seedKey(t *testing.T, db orm.DB, owner, name, user, pk, sk string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.User = owner, name, user
	k.AccessKey, k.AccessSecretDigest = pk, schema.DigestSecret(sk)
	k.State = "Active"
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed key: %v", err)
	}
}

// UserByAccessKey resolves the SECRET shape (sk-) to the correct user and FAILS
// CLOSED on a public pk- — the WRITE-ONLY invariant a wrong resolution would
// violate. A pk- ships in client JS, so turning it into a read identity is the
// browser-key catastrophe; it must authenticate no read here.
func TestUserByAccessKey_ResolvesSecretsRefusesPublishable(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	u := seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "")
	// A schema.Key credential (pk- publishable half + sk- secret half) belonging to
	// hanzo/alice.
	seedKey(t, db, "hanzo", "alice-key", "hanzo/alice", "pk-live-PROJ", "sk-live-SECRET")

	// The SECRET shape resolves to the owning user.
	got, err := UserByAccessKey(ctx, db, "sk-live-SECRET")
	if err != nil {
		t.Fatalf("sk confidential half: %v", err)
	}
	if got == nil || got.Owner != u.Owner || got.Name != u.Name {
		t.Fatalf("sk confidential half resolved %+v, want hanzo/alice", got)
	}

	// The PUBLIC pk- publishable half — even though its Key names a real owning user
	// in the key's own tenant — resolves to NOBODY. It is write-only, never a principal.
	if got, err := UserByAccessKey(ctx, db, "pk-live-PROJ"); !errors.Is(err, orm.ErrNotFound) || got != nil {
		t.Fatalf("publishable pk- resolved %+v (err=%v), want (nil, ErrNotFound) — a pk- must never authenticate a read", got, err)
	}
}

// schema.User.AccessKey IS NOT A CREDENTIAL. There are two key shapes, both living on
// schema.Key; a value on the User row authenticates nobody no matter how it is spelled.
//
// The fixture is deliberately a live user carrying a retired-prefix value in that exact
// field, because that is the only arrangement a resurrected prefix branch would resolve.
// Asserting on a value no row bears would pass with the branch back in place and guard
// nothing.
func TestUserByAccessKey_UserRowValueIsNotACredential(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedKeyUser(t, db, "hanzo", "carol", "carol@hanzo.ai", "hk-live-CAROLROW")

	got, err := UserByAccessKey(ctx, db, "hk-live-CAROLROW")
	if !errors.Is(err, orm.ErrNotFound) || got != nil {
		t.Fatalf("a user-row value authenticated %+v (err=%v) — schema.User.AccessKey must never be a credential", got, err)
	}
	if r := Reason(err); r != KeyUnknown {
		t.Errorf("reason = %q, want %q (the actionable 'mint a new one' path)", r, KeyUnknown)
	}
}

// A key whose row references a user by bare username (no owner/name) resolves within
// the key's own tenant — never across tenants. The SECRET (sk-) half resolves; the
// public pk- half never does.
func TestUserByAccessKey_BareUserRefWithinTenant(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedKeyUser(t, db, "hanzo", "bob", "bob@hanzo.ai", "")
	seedKey(t, db, "hanzo", "bob-key", "bob", "pk-live-BOB", "sk-live-BOB")

	got, err := UserByAccessKey(ctx, db, "sk-live-BOB")
	if err != nil || got == nil || got.Owner != "hanzo" || got.Name != "bob" {
		t.Fatalf("bare-user sk resolved %+v err=%v, want hanzo/bob", got, err)
	}
	// The pk- half of the same key resolves to nobody (write-only).
	if got, err := UserByAccessKey(ctx, db, "pk-live-BOB"); !errors.Is(err, orm.ErrNotFound) || got != nil {
		t.Fatalf("bare-user pk- resolved %+v err=%v, want (nil, ErrNotFound)", got, err)
	}
}

// F1 REGRESSION — credential forgery: a Key in tenant A whose User names a foreign
// owner (a victim tenant, or the reserved admin org = SuperAdmin) must resolve to
// NOBODY, even though those users exist. The resolved owner is pinned to the KEY
// ROW's own tenant; a "/"-qualified foreign reference fails closed.
func TestUserByAccessKey_RejectsCrossTenantUserRef(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	// Real high-value victims in OTHER orgs.
	admZ := seedKeyUser(t, db, "admin", "z", "z@hanzo.ai", "")
	admZ.IsAdmin = true
	if err := admZ.UpdateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	seedKeyUser(t, db, "victimorg", "ceo", "ceo@victim.example", "")

	// Attacker plants keys in its OWN org (attackerOrg — a write it IS authorized
	// for) pointing User at a foreign identity, with a KNOWN secret it supplied.
	seedKey(t, db, "attackerOrg", "forge-super", "admin/z", "pk-live-FORGESUPER", "sk-live-FORGESUPER")
	seedKey(t, db, "attackerOrg", "forge-victim", "victimorg/ceo", "pk-live-FORGEVICTIM", "sk-live-FORGEVICTIM")

	for _, key := range []string{
		"pk-live-FORGESUPER", "sk-live-FORGESUPER",
		"pk-live-FORGEVICTIM", "sk-live-FORGEVICTIM",
	} {
		got, err := UserByAccessKey(ctx, db, key)
		if !errors.Is(err, orm.ErrNotFound) || got != nil {
			t.Fatalf("FORGERY: key %q resolved to %+v (err=%v), want (nil, ErrNotFound)", key, got, err)
		}
	}
}

// Fail-closed: empty, unknown, wrong-shape, and user-less keys all resolve to
// orm.ErrNotFound — never a fallback or wrong user.
func TestUserByAccessKey_FailsClosed(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "")
	// An org-scoped key with NO user reference — cannot be attributed to a principal.
	seedKey(t, db, "hanzo", "org-key", "", "pk-live-ORGONLY", "sk-live-ORGONLY")

	for _, tc := range []struct{ name, key string }{
		{"empty", ""},
		{"whitespace", "   "},
		// A retired prefix is not a key. Kept as a fixture so that re-adding a branch
		// for it breaks a test rather than passing silently.
		{"retired prefix", "hk-live-NOSUCH"},
		{"unknown pk", "pk-live-NOSUCH"},
		{"unknown sk", "sk-live-NOSUCH"},
		{"unrecognized prefix", "fw_deadbeef"},
		{"bare garbage", "not-a-key"},
		{"user-less pk resolves nobody", "pk-live-ORGONLY"},
		{"user-less sk resolves nobody", "sk-live-ORGONLY"},
	} {
		got, err := UserByAccessKey(ctx, db, tc.key)
		if !errors.Is(err, orm.ErrNotFound) || got != nil {
			t.Fatalf("%s: got (%+v, %v), want (nil, ErrNotFound)", tc.name, got, err)
		}
	}
}

// seedPublishKey creates a WRITE-ONLY publishable key: pk- only, Scope=publish, no
// secret, owned by a tenant. expire is an RFC3339 stamp or "" for never.
func seedPublishKey(t *testing.T, db orm.DB, owner, name, pk, expire string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name = owner, name
	k.Scope = schema.KeyScopePublish
	k.AccessKey = pk
	k.ExpireTime = expire
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed publish key: %v", err)
	}
}

// PublishableKeyByAccessKey resolves ONLY a live, publish-scoped pk- to its Key — never
// a user — and fails closed on everything else: a non-pk- value, an unknown key, a
// SECRET key's own pk- half (Scope != publish), or an expired key. This is the
// org-only door's fail-closed contract, the write-only invariant's other half (the
// principal path is closed by TestUserByAccessKey_ResolvesSecretsRefusesPublishable).
func TestPublishableKeyByAccessKey(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	seedPublishKey(t, db, "hanzo", "site", "pk-live-PUBLISH", "")                           // never expires
	seedPublishKey(t, db, "hanzo", "site-exp", "pk-live-EXPIRED", "2020-01-01T00:00:00Z")   // long expired
	seedPublishKey(t, db, "hanzo", "site-future", "pk-live-FUTURE", "2099-01-01T00:00:00Z") // still valid
	// A SECRET (default, Scope="") key that HAS a pk- half — must NOT resolve here.
	seedKey(t, db, "hanzo", "secret", "hanzo/alice", "pk-live-SECRETHALF", "sk-live-x")

	// A live publishable key resolves to its ORG (Owner), scope publish.
	for _, key := range []string{"pk-live-PUBLISH", "pk-live-FUTURE"} {
		k, err := PublishableKeyByAccessKey(ctx, db, key, now)
		if err != nil || k == nil || k.Owner != "hanzo" || k.Scope != schema.KeyScopePublish {
			t.Fatalf("%s resolved %+v err=%v, want a hanzo publish key", key, k, err)
		}
	}

	for _, tc := range []struct{ name, key string }{
		{"secret key's pk- half (Scope != publish)", "pk-live-SECRETHALF"},
		{"an sk- confidential half (wrong prefix)", "sk-live-x"},
		{"a retired prefix", "hk-live-x"},
		{"expired publish key", "pk-live-EXPIRED"},
		{"unknown pk-", "pk-live-NOSUCH"},
		{"empty", ""},
		{"whitespace", "   "},
	} {
		if k, err := PublishableKeyByAccessKey(ctx, db, tc.key, now); !errors.Is(err, orm.ErrNotFound) || k != nil {
			t.Fatalf("%s: resolved %+v (err=%v), want (nil, ErrNotFound)", tc.name, k, err)
		}
	}
}

// ── the reason, not just the refusal ─────────────────────────────────────────

// Every refusal still fails closed AND now says which refusal it was. "the entity
// does not exist" was one sentence for causes that call for opposite actions: a
// revoked key needs re-minting, a pk- at the secret door needs the other door, and a
// cross-tenant key row is an ATTACK — none of which the holder or an operator could
// tell apart. The reason is additive: errors.Is(err, orm.ErrNotFound) still holds for
// every case, so no existing caller changes behavior.
func TestUserByAccessKey_ReasonsAreDistinguishable(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "")
	seedKey(t, db, "hanzo", "org-key", "", "pk-live-ORGONLY", "sk-live-ORGONLY")
	// An attacker's own-org key naming a foreign identity — the same-tenant pin.
	seedKey(t, db, "attackerOrg", "forge", "victimorg/ceo", "pk-live-FORGE", "sk-live-FORGE")
	// A key naming a same-tenant user that does not exist — a dangling row.
	seedKey(t, db, "hanzo", "dangling", "hanzo/ghost", "pk-live-GHOST", "sk-live-GHOST")

	for _, tc := range []struct {
		name string
		key  string
		want KeyFailure
	}{
		{"unknown sk", "sk-live-NOSUCH", KeyUnknown},
		{"a pk- at the SECRET door", "pk-live-ORGONLY", KeyWrongDoor},
		// Not a shape this estate issues → KeyUnknown, never KeyWrongDoor. WrongDoor
		// advises "use your secret key", which is a lie to someone holding no key at
		// all; KeyUnknown is what renders the actionable "mint a new one" in cloud.
		{"a retired prefix", "hk-live-NOSUCH", KeyUnknown},
		{"an unrecognized shape", "fw_deadbeef", KeyUnknown},
		{"empty", "", KeyUnknown},
		{"cross-tenant key row is a SECURITY event", "sk-live-FORGE", KeyForeignUser},
		{"user-less key row cannot name a principal", "sk-live-ORGONLY", KeyForeignUser},
		{"key naming a nonexistent same-tenant user", "sk-live-GHOST", KeyDanglingUser},
	} {
		got, err := UserByAccessKey(ctx, db, tc.key)
		if got != nil {
			t.Fatalf("%s: resolved %+v, want nil — every case must still fail closed", tc.name, got)
		}
		if !errors.Is(err, orm.ErrNotFound) {
			t.Fatalf("%s: err=%v, want it to still satisfy errors.Is(_, orm.ErrNotFound)", tc.name, err)
		}
		if r := Reason(err); r != tc.want {
			t.Errorf("%s: reason = %q, want %q", tc.name, r, tc.want)
		}
	}
}

// The publishable door tells its three refusals apart. This is the trio the cloud
// fork's own test annotated as "unknown / not publishable / expired" while having no
// way to distinguish them — the annotation is now executable.
func TestPublishableKeyByAccessKey_ReasonsAreDistinguishable(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	seedPublishKey(t, db, "hanzo", "site-exp", "pk-live-EXPIRED", "2020-01-01T00:00:00Z")
	seedKey(t, db, "hanzo", "secret", "hanzo/alice", "pk-live-SECRETHALF", "sk-live-x")

	for _, tc := range []struct {
		name string
		key  string
		want KeyFailure
	}{
		{"unknown", "pk-live-NOSUCH", KeyUnknown},
		{"not publishable", "pk-live-SECRETHALF", KeyNotPublishable},
		{"expired", "pk-live-EXPIRED", KeyExpired},
		{"not a pk- at all", "sk-live-x", KeyWrongDoor},
	} {
		k, err := PublishableKeyByAccessKey(ctx, db, tc.key, now)
		if k != nil {
			t.Fatalf("%s: resolved %+v, want nil", tc.name, k)
		}
		if !errors.Is(err, orm.ErrNotFound) {
			t.Fatalf("%s: err=%v, want errors.Is(_, orm.ErrNotFound)", tc.name, err)
		}
		if r := Reason(err); r != tc.want {
			t.Errorf("%s: reason = %q, want %q", tc.name, r, tc.want)
		}
	}
}

// A real store fault is NOT a bad credential. Reason yields "" for anything that is
// not a not-found, so a caller can never render infrastructure trouble to a user as
// "your key is invalid".
func TestReason_StoreFaultIsNotAKeyFailure(t *testing.T) {
	if r := Reason(errors.New("dial tcp: connection refused")); r != "" {
		t.Fatalf("Reason(store fault) = %q, want \"\"", r)
	}
	if r := Reason(nil); r != "" {
		t.Fatalf("Reason(nil) = %q, want \"\"", r)
	}
	// A bare orm.ErrNotFound from a path predating KeyError still reads as unknown.
	if r := Reason(orm.ErrNotFound); r != KeyUnknown {
		t.Fatalf("Reason(orm.ErrNotFound) = %q, want %q", r, KeyUnknown)
	}
}

// A KEY'S OWN LIMIT REACHES THE RESOLVER.
//
// The resolver reads the Key row to find the user and used to discard everything
// else on it. So a resource server could learn WHO a key speaks for and never how
// much of that authority the key carries — which made a per-key limit
// unenforceable no matter what was stored, and is why the Scope column had one
// value in the whole estate.
//
// One lookup answers both, because it is one row: a second call would be a second
// read and a second chance for the two halves to disagree about the same key.
func TestUserAndScopeByAccessKey_CarriesTheKeysOwnLimit(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "")
	seedScopedKey(t, db, "hanzo", "limited", "hanzo/alice", "pk-live-L", "sk-live-L", "model:zen5,project:acme")
	seedKey(t, db, "hanzo", "unlimited", "hanzo/alice", "pk-live-U", "sk-live-U")

	u, scope, err := UserAndScopeByAccessKey(ctx, db, "sk-live-L")
	if err != nil {
		t.Fatalf("limited key: %v", err)
	}
	if u == nil || u.Name != "alice" {
		t.Fatalf("limited key resolved %+v, want hanzo/alice", u)
	}
	if scope != "model:zen5,project:acme" {
		t.Fatalf("scope = %q, want the key row's own limit", scope)
	}

	// A key with no limit answers "" — unrestricted, which is every key minted
	// before limits existed. Empty must never read as "denied everything".
	if _, scope, err = UserAndScopeByAccessKey(ctx, db, "sk-live-U"); err != nil {
		t.Fatalf("unlimited key: %v", err)
	}
	if scope != "" {
		t.Fatalf("an unlimited key must answer an empty scope, got %q", scope)
	}

	// Two keys of ONE user carry different limits, which is the whole point: the
	// limit is a property of the credential, not of the person.
	if _, s1, _ := UserAndScopeByAccessKey(ctx, db, "sk-live-L"); s1 == "" {
		t.Fatal("one user's two keys must be able to differ")
	}

	// The refusals still refuse, and still say nothing about a scope.
	if _, scope, err := UserAndScopeByAccessKey(ctx, db, "pk-live-L"); err == nil || scope != "" {
		t.Fatal("a publishable key must resolve to no principal and no scope")
	}
	if _, scope, err := UserAndScopeByAccessKey(ctx, db, "sk-live-NOPE"); err == nil || scope != "" {
		t.Fatal("an unknown key must fail closed with no scope")
	}

	// UserByAccessKey is the same lookup with the scope dropped, so the two can
	// never disagree about who a key speaks for.
	plain, err := UserByAccessKey(ctx, db, "sk-live-L")
	if err != nil || plain == nil || plain.Name != u.Name {
		t.Fatalf("the narrow door must answer the same user: %+v %v", plain, err)
	}
}

func seedScopedKey(t *testing.T, db orm.DB, owner, name, user, pk, sk, scope string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.User, k.Scope = owner, name, user, scope
	k.AccessKey, k.AccessSecretDigest = pk, schema.DigestSecret(sk)
	k.State = "Active"
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed scoped key: %v", err)
	}
}

// A key minted before the digest existed still authenticates, and stops being
// plaintext the first time it does.
//
// This is the whole migration. The estate cannot re-mint every deployed
// credential at once, so the resolver falls back to the legacy column — and a hit
// there DRAINS the row rather than leaving it to be found the same way forever.
// Without the drain the fallback is not a migration, it is a second permanent
// lookup path, and the plaintext never goes away.
func TestUserByAccessKey_LegacyPlaintextResolvesAndIsDrained(t *testing.T) {
	ctx, db := context.Background(), memDB(t)
	const secret = "sk-live-legacyplaintextsecret000"

	u := orm.New[schema.User](db)
	u.Owner, u.Name = "acme", "ada"
	u.SetId("acme/ada")
	if err := u.CreateCtx(ctx); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	// A row exactly as the old minter left it: the secret verbatim, no digest.
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.Type, k.User = "acme", "cloud-api", "User", "ada"
	k.AccessKey, k.AccessSecret = "pk-live-legacy", secret
	k.SetId("acme/cloud-api")
	if err := k.CreateCtx(ctx); err != nil {
		t.Fatalf("seed legacy key: %v", err)
	}

	got, err := UserByAccessKey(ctx, db, secret)
	if err != nil {
		t.Fatalf("a legacy key must still authenticate: %v", err)
	}
	if got.Owner != "acme" || got.Name != "ada" {
		t.Fatalf("resolved %s/%s, want acme/ada", got.Owner, got.Name)
	}

	after, err := orm.Get[schema.Key](db, "acme/cloud-api")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if after.AccessSecret != "" {
		t.Fatalf("the plaintext survived the drain: %q", after.AccessSecret)
	}
	if after.AccessSecretDigest != schema.DigestSecret(secret) {
		t.Fatal("the drain did not write the digest, so this row would take the legacy path forever")
	}
	// And it still resolves — now through the digest, with nothing plaintext left.
	if _, err := UserByAccessKey(ctx, db, secret); err != nil {
		t.Fatalf("the drained key stopped authenticating: %v", err)
	}
}

// seedOrgKey seeds a server key owned by an org and carrying no user — the shape
// behind the act grant — with an explicit lifecycle flag and expiry.
func seedOrgKey(t *testing.T, db orm.DB, owner, name, sk, state, expire string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.Type = owner, name, "Organization"
	k.AccessSecretDigest = schema.DigestSecret(sk)
	k.State, k.ExpireTime = state, expire
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org key: %v", err)
	}
}

// THE SECRET DOOR ANSWERS FOR LIVE KEYS AND ONLY LIVE KEYS.
//
// Three facts one table holds together, because they are the same fact seen from
// three angles: a key in the shape the minter WRITES (a digest, no plaintext) is
// found; a key whose lifetime ran out is not; a key someone switched off is not.
// The first is what a private plaintext query here got wrong — every key minted
// since digests existed was invisible to it, so the grant behind acting for a user
// authenticated nothing but pre-digest rows. The other two are what a lookup with
// no liveness question got wrong: a real secret went on working after the row
// stopped being honored.
func TestKeyBySecret_AnswersOnlyForALiveKey(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	const (
		live     = "sk-live-ORGLIVE00000000000000000"
		expired  = "sk-live-ORGEXPIRED0000000000000"
		disabled = "sk-live-ORGDISABLED000000000000"
		legacy   = "sk-live-ORGLEGACY00000000000000"
		undated  = "sk-live-ORGUNDATED0000000000000"
	)
	seedOrgKey(t, db, "hanzo", "live", live, "Active", "2099-01-01T00:00:00Z")
	seedOrgKey(t, db, "hanzo", "expired", expired, "Active", "2020-01-01T00:00:00Z")
	seedOrgKey(t, db, "hanzo", "disabled", disabled, "Disabled", "")
	// A row minted before either flag existed: no State, no expiry, plaintext secret.
	// It must keep working, or the fix strands every credential already deployed.
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.Type = "hanzo", "legacy", "Organization"
	k.AccessSecret = legacy
	k.SetId("hanzo/legacy")
	if err := k.CreateCtx(ctx); err != nil {
		t.Fatalf("seed legacy org key: %v", err)
	}
	seedOrgKey(t, db, "hanzo", "undated", undated, "Active", "")

	for _, tc := range []struct {
		name   string
		secret string
		want   string // key name that must answer, "" for nobody
	}{
		{"the shape the minter writes: a digest and no plaintext", live, "live"},
		{"no expiry means never expires", undated, "undated"},
		{"a pre-digest row still answers, and is drained", legacy, "legacy"},
		{"a key whose lifetime ran out answers for nobody", expired, ""},
		{"a key that was switched off answers for nobody", disabled, ""},
		{"an unknown secret", "sk-live-NOSUCH", ""},
		{"a publishable half is not a secret", "pk-live-ORGLIVE", ""},
		{"empty", "", ""},
	} {
		got, err := KeyBySecret(ctx, db, tc.secret)
		if err != nil {
			t.Fatalf("%s: err = %v, want none — this door reports no key, not which refusal", tc.name, err)
		}
		switch {
		case tc.want == "":
			if got != nil {
				t.Errorf("%s: resolved %s/%s, want nobody", tc.name, got.Owner, got.Name)
			}
		case got == nil:
			t.Errorf("%s: resolved nobody, want hanzo/%s", tc.name, tc.want)
		case got.Name != tc.want:
			t.Errorf("%s: resolved %s, want %s", tc.name, got.Name, tc.want)
		}
	}

	// The legacy row was drained on the way through, exactly as the get-user door
	// drains it: one resolver, one migration, not two.
	after, err := orm.Get[schema.Key](db, "hanzo/legacy")
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if after.AccessSecret != "" || after.AccessSecretDigest != schema.DigestSecret(legacy) {
		t.Fatalf("the drain did not run on this door: secret=%q digest=%q", after.AccessSecret, after.AccessSecretDigest)
	}
}

// BOTH DOORS REFUSE THE SAME ROWS, AND SAY WHY. The get-user door reads a key
// through the same resolver, so a key that stopped being honored authenticates
// nobody there either — and the holder is told which of the two terminations it
// was, because re-minting and switching a key back on are different acts.
func TestUserByAccessKey_ExpiredAndDisabledResolveToNobody(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "")
	for _, s := range []struct{ name, secret, state, expire string }{
		{"live", "sk-live-USERLIVE000000000000000", "Active", ""},
		{"expired", "sk-live-USEREXPIRED0000000000", "Active", "2020-01-01T00:00:00Z"},
		{"disabled", "sk-live-USERDISABLED000000000", "Disabled", ""},
	} {
		k := orm.New[schema.Key](db)
		k.Owner, k.Name, k.User = "hanzo", s.name, "hanzo/alice"
		k.AccessSecretDigest = schema.DigestSecret(s.secret)
		k.State, k.ExpireTime = s.state, s.expire
		k.SetId("hanzo/" + s.name)
		if err := k.CreateCtx(ctx); err != nil {
			t.Fatalf("seed %s: %v", s.name, err)
		}
	}

	u, err := UserByAccessKey(ctx, db, "sk-live-USERLIVE000000000000000")
	if err != nil || u == nil || u.Name != "alice" {
		t.Fatalf("a live key resolved %+v err=%v, want hanzo/alice", u, err)
	}

	for _, tc := range []struct {
		name   string
		secret string
		want   KeyFailure
	}{
		{"ran out", "sk-live-USEREXPIRED0000000000", KeyExpired},
		{"switched off", "sk-live-USERDISABLED000000000", KeyDisabled},
	} {
		got, err := UserByAccessKey(ctx, db, tc.secret)
		if got != nil {
			t.Fatalf("%s: authenticated %s/%s — a key that is not honored must resolve to nobody", tc.name, got.Owner, got.Name)
		}
		if !errors.Is(err, orm.ErrNotFound) {
			t.Fatalf("%s: err = %v, want errors.Is(_, orm.ErrNotFound)", tc.name, err)
		}
		if r := Reason(err); r != tc.want {
			t.Errorf("%s: reason = %q, want %q", tc.name, r, tc.want)
		}
	}
}
