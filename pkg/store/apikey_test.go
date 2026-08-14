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

// now is the instant every test in this file resolves a key at. Both key doors take
// the instant as a parameter, so a lifetime test moves the EXPIRY rather than the
// clock and the suite has no wall-clock dependence at all.
var now = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

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
	got, err := UserByAccessKey(ctx, db, "sk-live-SECRET", now)
	if err != nil {
		t.Fatalf("sk confidential half: %v", err)
	}
	if got == nil || got.Owner != u.Owner || got.Name != u.Name {
		t.Fatalf("sk confidential half resolved %+v, want hanzo/alice", got)
	}

	// The PUBLIC pk- publishable half — even though its Key names a real owning user
	// in the key's own tenant — resolves to NOBODY. It is write-only, never a principal.
	if got, err := UserByAccessKey(ctx, db, "pk-live-PROJ", now); !errors.Is(err, orm.ErrNotFound) || got != nil {
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

	got, err := UserByAccessKey(ctx, db, "hk-live-CAROLROW", now)
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

	got, err := UserByAccessKey(ctx, db, "sk-live-BOB", now)
	if err != nil || got == nil || got.Owner != "hanzo" || got.Name != "bob" {
		t.Fatalf("bare-user sk resolved %+v err=%v, want hanzo/bob", got, err)
	}
	// The pk- half of the same key resolves to nobody (write-only).
	if got, err := UserByAccessKey(ctx, db, "pk-live-BOB", now); !errors.Is(err, orm.ErrNotFound) || got != nil {
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
		got, err := UserByAccessKey(ctx, db, key, now)
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
		got, err := UserByAccessKey(ctx, db, tc.key, now)
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
		got, err := UserByAccessKey(ctx, db, tc.key, now)
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

	u, scope, err := UserAndScopeByAccessKey(ctx, db, "sk-live-L", now)
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
	if _, scope, err = UserAndScopeByAccessKey(ctx, db, "sk-live-U", now); err != nil {
		t.Fatalf("unlimited key: %v", err)
	}
	if scope != "" {
		t.Fatalf("an unlimited key must answer an empty scope, got %q", scope)
	}

	// Two keys of ONE user carry different limits, which is the whole point: the
	// limit is a property of the credential, not of the person.
	if _, s1, _ := UserAndScopeByAccessKey(ctx, db, "sk-live-L", now); s1 == "" {
		t.Fatal("one user's two keys must be able to differ")
	}

	// The refusals still refuse, and still say nothing about a scope.
	if _, scope, err := UserAndScopeByAccessKey(ctx, db, "pk-live-L", now); err == nil || scope != "" {
		t.Fatal("a publishable key must resolve to no principal and no scope")
	}
	if _, scope, err := UserAndScopeByAccessKey(ctx, db, "sk-live-NOPE", now); err == nil || scope != "" {
		t.Fatal("an unknown key must fail closed with no scope")
	}

	// UserByAccessKey is the same lookup with the scope dropped, so the two can
	// never disagree about who a key speaks for.
	plain, err := UserByAccessKey(ctx, db, "sk-live-L", now)
	if err != nil || plain == nil || plain.Name != u.Name {
		t.Fatalf("the narrow door must answer the same user: %+v %v", plain, err)
	}
}

func seedScopedKey(t *testing.T, db orm.DB, owner, name, user, pk, sk, scope string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.User = owner, name, user
	k.AccessKey, k.AccessSecret, k.Scope = pk, sk, scope
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed scoped key: %v", err)
	}
}

// ref names a resolved user as owner/name — the whole of what a refusal test needs
// to say. A user record carries credential material, so an auth test states WHO it
// resolved and never prints the row.
func ref(u *schema.User) string {
	if u == nil {
		return "nobody"
	}
	return u.Owner + "/" + u.Name
}

// seedSecretKeyExpiring creates an sk- credential with an explicit RFC3339 expiry
// ("" for never), so a lifetime test states the expiry rather than waiting for one.
func seedSecretKeyExpiring(t *testing.T, db orm.DB, owner, name, user, sk, expire string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.User = owner, name, user
	k.AccessSecret = sk
	k.ExpireTime = expire
	k.SetId(owner + "/" + name)
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed secret key: %v", err)
	}
}

// FORBIDDING A USER ENDS THEIR SECRET KEY. A principal's standing is one fact, so a
// user the JWT door refuses (internal/authz reads IsForbidden/IsDeleted off the
// loaded record) is refused at the key door too. Both terminations are covered.
//
// Each case carries its own KNOWN-POSITIVE: the identical key resolves while the
// user is in good standing and stops the moment the bit is set. Without that control
// a refusal proves nothing — a fixture that never resolved at all would look exactly
// like a working gate.
func TestUserByAccessKey_ForbiddenUserCannotAuthenticate(t *testing.T) {
	for _, tc := range []struct {
		name string
		set  func(u *schema.User)
	}{
		{"forbidden", func(u *schema.User) { u.IsForbidden = true }},
		{"deleted", func(u *schema.User) { u.IsDeleted = true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := memDB(t)
			ctx := context.Background()
			u := seedKeyUser(t, db, "hanzo", "dave", "dave@hanzo.ai", "")
			seedKey(t, db, "hanzo", "dave-key", "hanzo/dave", "pk-live-DAVE", "sk-live-DAVE")

			got, err := UserByAccessKey(ctx, db, "sk-live-DAVE", now)
			if err != nil || got == nil || got.Name != "dave" {
				t.Fatalf("control: live key resolved (%s, %v), want hanzo/dave — the fixture "+
					"must work before its refusal means anything", ref(got), err)
			}

			tc.set(u)
			if err := u.UpdateCtx(ctx); err != nil {
				t.Fatal(err)
			}

			got, err = UserByAccessKey(ctx, db, "sk-live-DAVE", now)
			if !errors.Is(err, orm.ErrNotFound) || got != nil {
				t.Fatalf("a %s user authenticated as %s (err=%v) — the key must stop with the principal",
					tc.name, ref(got), err)
			}
			if r := Reason(err); r != KeyForbiddenUser {
				t.Errorf("reason = %q, want %q — the credential is intact, the principal is not", r, KeyForbiddenUser)
			}
		})
	}
}

// AN EXPIRY THAT IS SET IS AN EXPIRY THAT IS HONORED, on the secret door exactly as
// on the publishable one — one keyLive, one meaning.
//
// The two cases are the control pair: the same shape, the same instant, an expiry on
// either side of it. A gate that refused both would fail the first, so this cannot
// pass by refusing everything.
func TestUserByAccessKey_ExpiredSecretKeyIsRefused(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedKeyUser(t, db, "hanzo", "erin", "erin@hanzo.ai", "")
	seedSecretKeyExpiring(t, db, "hanzo", "erin-live", "hanzo/erin", "sk-live-ERINLIVE",
		now.Add(time.Hour).Format(time.RFC3339))
	seedSecretKeyExpiring(t, db, "hanzo", "erin-past", "hanzo/erin", "sk-live-ERINPAST",
		now.Add(-time.Hour).Format(time.RFC3339))

	got, err := UserByAccessKey(ctx, db, "sk-live-ERINLIVE", now)
	if err != nil || got == nil || got.Name != "erin" {
		t.Fatalf("control: unexpired key resolved (%s, %v), want hanzo/erin", ref(got), err)
	}

	got, err = UserByAccessKey(ctx, db, "sk-live-ERINPAST", now)
	if !errors.Is(err, orm.ErrNotFound) || got != nil {
		t.Fatalf("an expired secret key authenticated as %s (err=%v)", ref(got), err)
	}
	if r := Reason(err); r != KeyExpired {
		t.Errorf("reason = %q, want %q — the holder must be told to re-mint", r, KeyExpired)
	}
}
