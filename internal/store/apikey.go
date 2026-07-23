// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store

import (
	"context"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// API-key → principal resolution: the ONE way an opaque Hanzo API key is turned
// into the user it authenticates, for the get-user?accessKey path cloud's identity
// boundary calls. Every shape FAILS CLOSED — an unknown, empty, or unrecognized-shape
// key resolves to orm.ErrNotFound, never a fallback or wrong user, so a bad key can
// never inherit another principal's identity.
//
// Only a SECRET credential authenticates a reader — a PUBLIC value never does:
//
//   - hk-  the durable Cloud API key stamped on the User row itself
//          (schema.User.AccessKey), minted by issue-user-token OR by a service
//          account (both store an hk- key on the User). The user IS the principal.
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

// UserByAccessKey resolves an opaque API key to the user it authenticates, or
// orm.ErrNotFound for an empty/unknown/unrecognized/publishable key. It never returns
// a wrong user: each SECRET shape (hk-/sk-) resolves through its own exact-match
// lookup, an sk- key whose row names no resolvable user fails closed rather than
// guessing one, and a public pk- resolves to nobody at all.
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
		return nil, orm.ErrNotFound
	}
}

// userByField resolves the single User row whose `field` equals val (the hk- path:
// the credential lives on the User itself). Not-found is orm.ErrNotFound.
func userByField(_ context.Context, db orm.DB, field, val string) (*schema.User, error) {
	u, err := orm.TypedQuery[schema.User](db).Filter(field+"=", val).First()
	if err == orm.ErrNotFound {
		return nil, orm.ErrNotFound
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
		return nil, orm.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	owner, name := keyUserRef(k)
	// Same-tenant pin: the resolved user MUST live in the key row's own org. A
	// "/"-qualified User naming a foreign owner is a forgery attempt — fail closed.
	if owner == "" || name == "" || owner != k.Owner {
		return nil, orm.ErrNotFound
	}
	u, err := GetUserByName(ctx, db, owner, name)
	if err != nil {
		return nil, err
	}
	if u == nil {
		return nil, orm.ErrNotFound
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
		return nil, orm.ErrNotFound
	}
	k, err := orm.TypedQuery[schema.Key](db).Filter("AccessKey=", key).First()
	if err == orm.ErrNotFound {
		return nil, orm.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if k.Scope != schema.KeyScopePublish || !keyLive(k, now) {
		return nil, orm.ErrNotFound
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
