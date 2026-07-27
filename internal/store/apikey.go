// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store

import (
	"context"
	"strings"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/schema"
)

// API-key → principal resolution: the ONE way an opaque Hanzo API key is turned
// into the user it authenticates, for the get-user?accessKey path cloud's identity
// boundary calls. Three key shapes, one entry point, all FAIL CLOSED — an unknown,
// empty, or unrecognized-shape key resolves to orm.ErrNotFound, never a fallback or
// wrong user, so a bad key can never inherit another principal's identity.
//
//   - hk-  LEGACY, accept-only. The durable Cloud API key stamped on the User row
//          itself (schema.User.AccessKey). Nothing mints this shape any more —
//          newAccessKey() has minted sk- since the key seam was unified — so the
//          population is fixed and can only shrink. The branch stays until the
//          remaining stored values are re-keyed; dropping it earlier would reject
//          every credential still carrying the old prefix.
//   - sk-  ALSO the shape now stamped on User.AccessKey by mint-user-keys. Both
//          resolutions below are live: on the User row (this file's userByField)
//          and as the confidential half of a schema.Key (userOwningKey).
//   - pk-  the publishable half of a schema.Key credential (Key.AccessKey) — resolve
//          the key row, then its owning user.
//   - sk-  the confidential half of a schema.Key credential (Key.AccessSecret) —
//          same resolution, keyed on the secret half.

// UserByAccessKey resolves an opaque API key to the user it authenticates, or
// orm.ErrNotFound for an empty/unknown/unrecognized key. It never returns a wrong
// user: each shape resolves through its own exact-match lookup, and a pk-/sk- key
// whose row names no resolvable user fails closed rather than guessing one.
func UserByAccessKey(ctx context.Context, db orm.DB, key string) (*schema.User, error) {
	key = strings.TrimSpace(key)
	switch {
	case strings.HasPrefix(key, "hk-"):
		return userByField(ctx, db, "AccessKey", key)
	case strings.HasPrefix(key, "pk-"):
		return userOwningKey(ctx, db, "AccessKey", key)
	case strings.HasPrefix(key, "sk-"):
		return userOwningKey(ctx, db, "AccessSecret", key)
	default:
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

// userOwningKey resolves the schema.Key whose `field` equals val (pk- → AccessKey,
// sk- → AccessSecret), then the user that key belongs to — CONSTRAINED to the key
// row's OWN tenant. A key that resolves no user (a key with no User reference — an
// org/app-scoped credential) fails closed with orm.ErrNotFound: this path attributes
// a key to a USER principal in the key's own org, or to none.
//
// The same-tenant pin is the F1 forgery gate. Key.User, AccessKey, and AccessSecret
// are all attacker-controlled at write time and keys CRUD authorizes only
// (Key.Owner, Key.Name) — never the User field — so a tenant admin could plant a Key
// in its OWN org whose User names "admin/z" (a SuperAdmin) or a victim tenant's user
// and, presenting the known secret, have get-user?accessKey resolve it to that
// foreign identity. Refusing any resolved owner != k.Owner makes that impossible: a
// key can only ever speak for a user in the org that owns the key, and a non-super
// can never own a key under a reserved org (authorize gates keys writes), so no
// pk-/sk- key can resolve to a SuperAdmin or cross-tenant identity.
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
