// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
)

// API-key → principal resolution: the ONE way an opaque Hanzo API key is turned
// into the user it authenticates, for the get-user?accessKey path cloud's identity
// boundary calls. Every shape FAILS CLOSED — an unknown, empty, or unrecognized-shape
// key resolves to orm.ErrNotFound, never a fallback or wrong user, so a bad key can
// never inherit another principal's identity.
//
// There are exactly TWO key shapes, and only the SECRET one authenticates a reader:
//
//   - sk-  the confidential half of a schema.Key credential (Key.AccessSecret) —
//          resolve the key row, then its owning user (same-tenant pinned). This is
//          the ONE durable full-access bearer credential; keys.Mint issues it.
//   - pk-  the PUBLISHABLE half (Key.AccessKey). Refused here, always.
//
// A pk- is deliberately NOT a resolving case: it is WRITE-ONLY and MUST NEVER become
// a principal. A pk- is public — it ships in client JS — so turning it into a read
// identity is the browser-key catastrophe. It is refused on EVERY caller of this
// function (get-user?accessKey AND the registry token path), so a public key
// authenticates no read anywhere. Its ONLY resolution is org-only, at the ingest door
// (keys.resolve → /v1/iam/resolve-key), and only for a publishable key.
//
// Any other string is not a key. It carries no shape this estate mints, so it cannot
// be told apart from a value that was never issued at all, and it resolves to nobody.

// ── why a key did not resolve ────────────────────────────────────────────────
//
// FAILING CLOSED AND FAILING SILENTLY ARE DIFFERENT THINGS, and this file used to do
// both. Every non-resolution collapsed into a bare orm.ErrNotFound, which the key-door
// handler rendered as "the entity does not exist" — one sentence for causes that call
// for opposite actions from the holder. A user whose key was REVOKED went looking for
// a deleted organization instead of minting a new key, and a tenant admin's forgery
// attempt (the same-tenant pin below) was indistinguishable from a typo.
//
// The reason is therefore a VALUE, carried beside the error rather than baked into
// its text. It changes no decision here — every branch still refuses — so refusing
// and explaining stay orthogonal.
type KeyFailure string

const (
	// KeyWrongDoor: a REAL credential presented at the door that does not answer for
	// it — a pk- at the SECRET door, or a non-pk- at the publishable one. The holder
	// has a working key; they used the wrong half. Reserved for exactly that, so the
	// advice it carries ("use your secret sk- key") is always true when it is given.
	KeyWrongDoor KeyFailure = "key_wrong_door"
	// KeyUnknown: no live credential answers to this value. Never minted, already
	// revoked, or carrying a prefix this estate does not issue — the holder cannot
	// tell those apart and does not need to, because the cure is the same one: mint a
	// new key. Nothing about their org is wrong. This is the honest answer for any
	// string that is not a live sk-, which is why the default case lands here.
	KeyUnknown KeyFailure = "key_unknown"
	// KeyForeignUser: an sk- row resolved, but it names a user in ANOTHER tenant.
	// The same-tenant pin (userOwningKey) refused it. This is a SECURITY EVENT, not
	// a user error, and it must never again look like one.
	KeyForeignUser KeyFailure = "key_foreign_user"
	// KeyDanglingUser: an sk- row resolved and named a same-tenant user that does
	// not exist. A data-integrity fault in the key table, not the holder's doing.
	KeyDanglingUser KeyFailure = "key_dangling_user"
	// KeyNotPublishable: a real key addressed by its pk- half whose scope is not
	// publish. The browser door refuses it precisely because it is a secret.
	KeyNotPublishable KeyFailure = "key_not_publishable"
	// KeyExpired: the row exists and is the right scope, but its lifetime has run
	// out. Both doors report it, because both ask the same question (see dead).
	KeyExpired KeyFailure = "key_expired"
	// KeyDisabled: the row exists and has not run out, but its lifecycle flag says
	// it is turned off. Told apart from KeyExpired because the cures differ — an
	// expired key is re-minted, a disabled one is switched back on — and told apart
	// from KeyUnknown because the credential is real and its holder is not guessing.
	KeyDisabled KeyFailure = "key_disabled"
)

// KeyError is an orm.ErrNotFound that ALSO says why. It Unwraps to orm.ErrNotFound
// so every existing `errors.Is(err, orm.ErrNotFound)` caller keeps working untouched
// and unaware: the reason is strictly additive, and a caller that does not care
// about it is not made to.
type KeyError struct{ Reason KeyFailure }

func (e *KeyError) Error() string { return "key not resolved: " + string(e.Reason) }
func (e *KeyError) Unwrap() error { return orm.ErrNotFound }

// Reason extracts the failure reason from a key-resolution error. A plain
// orm.ErrNotFound (from a path that predates this type) reads as KeyUnknown, and
// anything else — a real store fault — reads as "" so a caller never reports an
// infrastructure failure as a bad credential.
func Reason(err error) KeyFailure {
	var ke *KeyError
	if errors.As(err, &ke) {
		return ke.Reason
	}
	if errors.Is(err, orm.ErrNotFound) {
		return KeyUnknown
	}
	return ""
}

func notFound(r KeyFailure) error { return &KeyError{Reason: r} }

// UserByAccessKey resolves an opaque API key to the user it authenticates, or a
// KeyError (an orm.ErrNotFound naming its cause) for anything else. It never returns
// a wrong user: only a live sk- resolves, through an exact-match lookup pinned to the
// key row's own tenant; an sk- whose row names no resolvable user fails closed rather
// than guessing one; and a public pk- resolves to nobody at all.
//
// The two shapes are refused for DIFFERENT reasons, and the difference is the whole
// value of the answer. A pk- is a real credential at the wrong door (KeyWrongDoor —
// "use your secret key"). Anything else answers to no live credential at all
// (KeyUnknown — "mint a new one"), whether it was revoked, never issued, or carries
// some prefix this estate does not mint. There is no third case, because there is no
// third shape: a value that is not a pk- and not a live sk- is simply not a key, and
// special-casing any particular non-key spelling would invent the third family back.
//
// Revocation is deletion, so a gone key reads as KeyUnknown. Termination is not the
// only way a real row stops answering, though: an sk- that has run out (KeyExpired) or
// been switched off (KeyDisabled) resolves to nobody just the same, because the one
// place a secret becomes a key asks that question for every door (see keyBySecret).
func UserByAccessKey(ctx context.Context, db orm.DB, key string) (*schema.User, error) {
	u, _, err := UserAndScopeByAccessKey(ctx, db, key)
	return u, err
}

// UserAndScopeByAccessKey is UserByAccessKey plus the key row's own Scope — what
// that CREDENTIAL may reach, as distinct from what its holder may.
//
// One lookup, because it is one row: the resolver already reads the Key to find
// the user, and dropping the scope on the way out is what made a per-key limit
// unenforceable — a resource server could learn WHO a key speaks for and never
// how much of that authority the key carries. A second call would be a second
// read of the same row and a second chance for the two answers to disagree.
//
// Scope is "" for a key that names no limit, which is every key minted before
// limits existed and means unrestricted.
func UserAndScopeByAccessKey(ctx context.Context, db orm.DB, key string) (*schema.User, string, error) {
	key = strings.TrimSpace(key)
	switch {
	case strings.HasPrefix(key, "sk-"):
		return userAndScopeOwningKey(ctx, db, key)
	case strings.HasPrefix(key, "pk-"):
		// WRITE-ONLY and never a principal (see the package note above). Fail closed,
		// and say so as the wrong door: this holder has a working key, just not here.
		return nil, "", notFound(KeyWrongDoor)
	default:
		// Not a shape this estate issues, so no live credential can answer to it.
		// Fail closed, and tell the holder the one thing that helps: mint a new key.
		return nil, "", notFound(KeyUnknown)
	}
}

// userOwningKey resolves the schema.Key whose `field` equals val (the sk- path:
// field == "AccessSecret"), then the user that key belongs to — CONSTRAINED to the
// key row's OWN tenant. A key that resolves no user (a key with no User reference — an
// org/app-scoped credential) fails closed with orm.ErrNotFound: this path attributes
// a key to a USER principal in the key's own org, or to none. Only the confidential
// sk- half reaches here; a public pk- is write-only and never resolves to a principal
// (UserByAccessKey refuses it before this point).
//
// The same-tenant pin is the F1 forgery gate. Key.User and AccessSecret are
// attacker-controlled at write time and keys CRUD authorizes only (Key.Owner,
// Key.Name) — never the User field — so a tenant admin could plant a Key in its OWN
// org whose User names "admin/z" (a SuperAdmin) or a victim tenant's user and,
// presenting the known secret, have get-user?accessKey resolve it to that foreign
// identity. Refusing any resolved owner != k.Owner makes that impossible: a key can
// only ever speak for a user in the org that owns the key, and a non-super can never
// own a key under a reserved org (authorize gates keys writes), so no sk- key can
// resolve to a SuperAdmin or cross-tenant identity.
func userAndScopeOwningKey(ctx context.Context, db orm.DB, secret string) (*schema.User, string, error) {
	k, err := keyBySecret(ctx, db, secret)
	if err != nil {
		return nil, "", err
	}
	owner, name := keyUserRef(k)
	// Same-tenant pin: the resolved user MUST live in the key row's own org. A
	// "/"-qualified User naming a foreign owner is a forgery attempt — fail closed,
	// and say WHICH refusal this was: a cross-tenant reference is an attack signal
	// and must not read to an operator as a mistyped key.
	if owner == "" || name == "" || owner != k.Owner {
		return nil, "", notFound(KeyForeignUser)
	}
	u, err := GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, "", err
	}
	if u == nil {
		return nil, "", notFound(KeyDanglingUser)
	}
	return u, k.Scope, nil
}

// keyBySecret finds the key a presented secret belongs to WITHOUT the row ever
// having to hold that secret: the digest of what was presented is the lookup
// value, and one indexed read answers it.
//
// The fallback is a migration, not a second way of doing this. Rows minted
// before the digest existed carry the secret in plaintext, and the estate cannot
// re-mint every deployed credential at once — so a digest miss tries the legacy
// column, and a hit there DRAINS it: the digest is written, the plaintext is
// cleared, and that row never takes this path again. The fallback therefore
// shrinks to nothing on its own and can be deleted when the plaintext count
// reaches zero, which is a query anyone can run.
//
// A drain that fails is not an authentication failure. The caller presented a
// real credential; the write is housekeeping, and refusing them because
// housekeeping failed would turn a storage problem into an outage.
//
// FOUND IS NOT HONORED. A row that has run out or been switched off still answers
// to its secret, and it must still resolve to nobody — so the liveness question is
// asked HERE, at the one place a presented secret becomes a key, and no door can
// forget to ask it.
func keyBySecret(ctx context.Context, db orm.DB, secret string) (*schema.Key, error) {
	digest := schema.DigestSecret(secret)
	if digest == "" {
		return nil, notFound(KeyUnknown)
	}
	k, err := only(ctx, db, "AccessSecretDigest=", digest)
	if err != nil {
		return nil, err
	}
	if k == nil {
		if k, err = only(ctx, db, "AccessSecret=", secret); err != nil {
			return nil, err
		}
		if k == nil {
			return nil, notFound(KeyUnknown)
		}
		k.AccessSecretDigest = digest
		k.AccessSecret = ""
		_ = k.UpdateCtx(ctx)
	}
	if r := dead(k, time.Now().UTC()); r != "" {
		return nil, notFound(r)
	}
	return k, nil
}

// only reads the ONE key whose field equals val: nil when none does, and an error
// rather than an arbitrary pick when more than one does. A secret two rows answer
// to names no single credential, and guessing which one would let a planted
// duplicate speak for the row it was copied from.
func only(ctx context.Context, db orm.DB, field, val string) (*schema.Key, error) {
	ks, err := orm.TypedQuery[schema.Key](db).Filter(field, val).GetAll(ctx)
	if err != nil {
		return nil, err
	}
	switch len(ks) {
	case 0:
		return nil, nil
	case 1:
		return ks[0], nil
	default:
		return nil, fmt.Errorf("store: %d keys share one secret — ambiguous credential", len(ks))
	}
}

// keyUserRef extracts the (owner, name) of the user a schema.Key belongs to. The
// User field is the "owner/name" identity used everywhere a user is referenced
// (Token.User, Membership.User); a bare username without a "/" is taken within the
// key's own tenant (Key.Owner). An empty User yields ("",""). The owner it returns
// is NOT trusted: userOwningKey rejects any owner that is not the key row's own
// (Key.Owner), so a "/"-qualified reference to a foreign owner resolves to nobody.
func keyUserRef(k *schema.Key) (owner, name string) {
	if o, n, ok := strings.Cut(k.User, "/"); ok && o != "" && n != "" {
		return o, n
	}
	if k.User != "" {
		return k.Owner, k.User
	}
	return "", ""
}

// KeyBySecret resolves a server key by its confidential sk- secret — the ONE way
// the durable 'act' grant behind as() is authenticated. It returns the KEY ROW
// (its Owner and its grants), never a user: the org key acts FOR members of its
// tenant, it is not itself one, so this is not the get-user resolver and does not
// pin to a User field.
//
// It carries NO lookup of its own: keyBySecret is how a presented secret becomes a
// key everywhere, so this door and the get-user door cannot disagree about which
// rows answer. That is not tidiness — a private query here matched the plaintext
// column the minter stopped writing, so this door saw only the rows minted before
// digests and none of the ones minted since.
//
// Fail closed on every non-resolution — an empty value, a non-sk- shape, or a
// secret that answers to no honored row resolves to (nil, nil). WHICH refusal it
// was is keyBySecret's word and is dropped here: this door asks whether a key
// speaks, not what to tell a holder, and its caller has nobody to explain to.
func KeyBySecret(ctx context.Context, db orm.DB, secret string) (*schema.Key, error) {
	secret = strings.TrimSpace(secret)
	if !strings.HasPrefix(secret, "sk-") {
		return nil, nil
	}
	k, err := keyBySecret(ctx, db, secret)
	if errors.Is(err, orm.ErrNotFound) {
		return nil, nil
	}
	return k, err
}

// PublishableKeyByAccessKey resolves a WRITE-ONLY publishable pk- to the schema.Key it
// belongs to, or orm.ErrNotFound — the ORG-ONLY dual of UserByAccessKey, for the ingest
// resolver (/v1/iam/keys/org). It NEVER touches or returns a
// user: a publishable key speaks for just its org, never a principal, which is why the
// pk- path lives here and not in UserByAccessKey.
//
// Fail-closed on every non-resolution, so this door can only ever speak for a live key
// that was explicitly minted as a browser key: a value that is not a pk-, an unknown
// key, a non-publishable (secret) key even when addressed by its OWN pk- half
// (Scope != KeyScopePublish), or an expired key all yield orm.ErrNotFound. Revocation
// is deletion (the row is gone → not found), so a present, unexpired, publish-scoped
// key is live.
func PublishableKeyByAccessKey(ctx context.Context, db orm.DB, key string, now time.Time) (*schema.Key, error) {
	key = strings.TrimSpace(key)
	if !strings.HasPrefix(key, "pk-") {
		return nil, notFound(KeyWrongDoor)
	}
	k, err := orm.TypedQuery[schema.Key](db).Filter("AccessKey=", key).First()
	if err == orm.ErrNotFound {
		return nil, notFound(KeyUnknown)
	}
	if err != nil {
		return nil, err
	}
	// Two different refusals, told apart. "Not publishable" means the holder used a
	// secret key's public half at the ingest door and should present its pk-;
	// "expired" means the right key simply ran out and must be re-minted. Collapsing
	// them sent the second holder hunting for a configuration error they did not have.
	// The CLASS, not the whole scope: a limited publishable key carries its reach
	// in the same field ("publish,model:zen5"), and comparing the whole string
	// would refuse it here — the browser key would resolve to no org and every
	// beacon it sends would be dropped.
	if schema.ClassOf(k.Scope) != schema.KeyScopePublish {
		return nil, notFound(KeyNotPublishable)
	}
	if r := dead(k, now); r != "" {
		return nil, notFound(r)
	}
	return k, nil
}

// dead says WHY a key is no longer honored, or "" while it still is. Two ways a
// present row stops answering, one predicate, so every door refuses the same rows
// for the same stated reason:
//
//   - State is the lifecycle flag the minter writes ("Active", or "test" for a
//     test-env credential; empty on rows minted before the flag existed). Any
//     other value is a key somebody switched off.
//   - ExpireTime is when it stops being honored, empty meaning never. An
//     unparseable stamp reads as expired — fail secure, never honor a key whose
//     lifetime cannot be read.
func dead(k *schema.Key, now time.Time) KeyFailure {
	switch k.State {
	case "", "Active", "test":
	default:
		return KeyDisabled
	}
	if k.ExpireTime == "" {
		return ""
	}
	exp, err := time.Parse(time.RFC3339, k.ExpireTime)
	if err != nil || !now.Before(exp) {
		return KeyExpired
	}
	return ""
}
