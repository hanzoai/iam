// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
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
// referencing user.
func seedKey(t *testing.T, db orm.DB, owner, name, user, pk, sk string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.User = owner, name, user
	k.AccessKey, k.AccessSecret = pk, sk
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed key: %v", err)
	}
}

// UserByAccessKey resolves each SECRET key shape (hk-, sk-) to the correct user and
// FAILS CLOSED on a public pk- — the WRITE-ONLY invariant a wrong resolution would
// violate. A pk- ships in client JS, so turning it into a read identity is the
// browser-key catastrophe; it must authenticate no read here.
func TestUserByAccessKey_ResolvesSecretsRefusesPublishable(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	u := seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "hk-live-ALICEKEY")
	// A schema.Key credential (pk- publishable half + sk- secret half) belonging to
	// hanzo/alice.
	seedKey(t, db, "hanzo", "alice-key", "hanzo/alice", "pk-live-PROJ", "sk-live-SECRET")

	// The SECRET shapes resolve to the owning user.
	for _, tc := range []struct{ name, key string }{
		{"hk on the user row", "hk-live-ALICEKEY"},
		{"sk confidential half", "sk-live-SECRET"},
	} {
		got, err := UserByAccessKey(ctx, db, tc.key)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got == nil || got.Owner != u.Owner || got.Name != u.Name {
			t.Fatalf("%s resolved %+v, want hanzo/alice", tc.name, got)
		}
	}

	// The PUBLIC pk- publishable half — even though its Key names a real owning user
	// in the key's own tenant — resolves to NOBODY. It is write-only, never a principal.
	if got, err := UserByAccessKey(ctx, db, "pk-live-PROJ"); !errors.Is(err, orm.ErrNotFound) || got != nil {
		t.Fatalf("publishable pk- resolved %+v (err=%v), want (nil, ErrNotFound) — a pk- must never authenticate a read", got, err)
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
	seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "hk-live-ALICEKEY")
	// An org-scoped key with NO user reference — cannot be attributed to a principal.
	seedKey(t, db, "hanzo", "org-key", "", "pk-live-ORGONLY", "sk-live-ORGONLY")

	for _, tc := range []struct{ name, key string }{
		{"empty", ""},
		{"whitespace", "   "},
		{"unknown hk", "hk-live-NOSUCH"},
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
		{"an hk- (wrong prefix)", "hk-live-x"},
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

	seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "hk-live-ALICEKEY")
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
		{"revoked or never-minted hk", "hk-live-NOSUCH", KeyUnknown},
		{"unknown sk", "sk-live-NOSUCH", KeyUnknown},
		{"a pk- at the SECRET door", "pk-live-ORGONLY", KeyWrongDoor},
		{"an unrecognized shape", "fw_deadbeef", KeyWrongDoor},
		{"empty", "", KeyWrongDoor},
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
