// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store

import (
	"context"
	"errors"
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
// Only a SECRET credential authenticates a reader — a PUBLIC value never does:
//
//   - hk-  LEGACY, accept-only. The durable Cloud API key stamped on the User row
//          itself (schema.User.AccessKey). Nothing mints this shape any more —
//          newAccessKey() has minted sk- since the key seam was unified — so the
//          population is fixed and can only shrink. The branch stays until the
//          remaining stored values are re-keyed; dropping it earlier would reject
//          every credential still carrying the old prefix.
//   - sk-  the confidential half of a schema.Key credential (Key.AccessSecret) —
//          resolve the key row, then its owning user (same-tenant pinned).
//
// A pk- (a schema.Key's PUBLISHABLE half, Key.AccessKey) is deliberately NOT a case
// here: it is WRITE-ONLY and MUST NEVER resolve to a principal. A pk- is public — it
// ships in client JS — so turning it into a read identity is the browser-key
// catastrophe. It falls through to orm.ErrNotFound, on EVERY caller of this function
// (get-user?accessKey AND the registry token path), so a public key authenticates no
// read anywhere. Its ONLY resolution is org-only, at the ingest door
// (keys.resolve → /v1/iam/resolve-key), and only for a publishable key.

// ── why a key did not resolve ────────────────────────────────────────────────
//
// FAILING CLOSED AND FAILING SILENTLY ARE DIFFERENT THINGS, and this file used to do
// both. Every non-resolution collapsed into a bare orm.ErrNotFound, which the compat
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
	// KeyWrongDoor: a shape this door does not answer for. A pk- (or anything
	// unrecognized) at the SECRET door, or a non-pk- at the publishable one. The
	// credential may be perfectly valid — it was presented at the wrong door.
	KeyWrongDoor KeyFailure = "key_wrong_door"
	// KeyUnknown: a well-shaped key that no row bears. Never minted, already
	// revoked, or — for the legacy hk- population — clobbered when a later mint
	// overwrote schema.User.AccessKey (see keys.MintUserKey). The holder's cure is
	// to mint a new key; nothing about their org is wrong.
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
	// out. Only the publishable door can report this — see the note on keyLive.
	KeyExpired KeyFailure = "key_expired"
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
// KeyError (an orm.ErrNotFound naming its cause) for an empty/unknown/unrecognized/
// publishable key. It never returns a wrong user: each SECRET shape (hk-/sk-)
// resolves through its own exact-match lookup, an sk- key whose row names no
// resolvable user fails closed rather than guessing one, and a public pk- resolves to
// nobody at all.
//
// NOTE ON EXPIRY: neither secret shape can report KeyExpired, because neither has an
// expiry to read. An hk- lives on the User row, which carries no lifetime at all; an
// sk- resolves through userOwningKey, which does not consult keyLive. Revocation is
// deletion (or clearing the field), so for a secret key "gone" is the only
// termination and KeyUnknown is the honest answer.
func UserByAccessKey(ctx context.Context, db orm.DB, key string) (*schema.User, error) {
	key = strings.TrimSpace(key)
	switch {
	case strings.HasPrefix(key, "hk-"):
		return userByField(ctx, db, "AccessKey", key)
	case strings.HasPrefix(key, "sk-"):
		return userOwningKey(ctx, db, "AccessSecret", key)
	default:
		// A pk- publishable half lands here with every other unrecognized value: it
		// is WRITE-ONLY and never a principal (see the package note above). Fail closed.
		return nil, notFound(KeyWrongDoor)
	}
}

// userByField resolves the single User row whose `field` equals val (the hk- path:
// the credential lives on the User itself). Not-found is orm.ErrNotFound.
func userByField(_ context.Context, db orm.DB, field, val string) (*schema.User, error) {
	u, err := orm.TypedQuery[schema.User](db).Filter(field+"=", val).First()
	if err == orm.ErrNotFound {
		return nil, notFound(KeyUnknown)
	}
	return u, err
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
func userOwningKey(ctx context.Context, db orm.DB, field, val string) (*schema.User, error) {
	k, err := orm.TypedQuery[schema.Key](db).Filter(field+"=", val).First()
	if err == orm.ErrNotFound {
		return nil, notFound(KeyUnknown)
	}
	if err != nil {
		return nil, err
	}
	owner, name := keyUserRef(k)
	// Same-tenant pin: the resolved user MUST live in the key row's own org. A
	// "/"-qualified User naming a foreign owner is a forgery attempt — fail closed,
	// and say WHICH refusal this was: a cross-tenant reference is an attack signal
	// and must not read to an operator as a mistyped key.
	if owner == "" || name == "" || owner != k.Owner {
		return nil, notFound(KeyForeignUser)
	}
	u, err := GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, notFound(KeyDanglingUser)
	}
	return u, nil
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

// PublishableKeyByAccessKey resolves a WRITE-ONLY publishable pk- to the schema.Key it
// belongs to, or orm.ErrNotFound — the ORG-ONLY dual of UserByAccessKey, for the ingest
// resolver (compat resolve-key → /v1/iam/resolve-key). It NEVER touches or returns a
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
	if k.Scope != schema.KeyScopePublish {
		return nil, notFound(KeyNotPublishable)
	}
	if !keyLive(k, now) {
		return nil, notFound(KeyExpired)
	}
	return k, nil
}

// keyLive reports whether a key is still honored: a row with no expiry, or one whose
// RFC3339 ExpireTime is still in the future. An unparseable expiry is treated as
// expired — fail secure, never honor a key whose lifetime cannot be read.
func keyLive(k *schema.Key, now time.Time) bool {
	if k.ExpireTime == "" {
		return true
	}
	exp, err := time.Parse(time.RFC3339, k.ExpireTime)
	if err != nil {
		return false
	}
	return now.Before(exp)
}
