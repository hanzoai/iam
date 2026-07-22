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
//   - hk-  the durable Cloud API key stamped on the User row itself
//          (schema.User.AccessKey), minted by issue-user-token OR by a service
//          account (both store an hk- key on the User). The user IS the principal.
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
// sk- → AccessSecret), then the user that key belongs to. A key that resolves no
// user (a key with no User reference — an org/app-scoped credential) fails closed
// with orm.ErrNotFound: this path attributes a key to a USER principal or to none.
func userOwningKey(ctx context.Context, db orm.DB, field, val string) (*schema.User, error) {
	k, err := orm.TypedQuery[schema.Key](db).Filter(field+"=", val).First()
	if err == orm.ErrNotFound {
		return nil, orm.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	owner, name := keyUserRef(k)
	if owner == "" || name == "" {
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
// key's own tenant (Key.Owner). An empty User yields ("",""), which the caller
// treats as fail-closed.
func keyUserRef(k *schema.Key) (owner, name string) {
	if o, n, ok := strings.Cut(k.User, "/"); ok && o != "" && n != "" {
		return o, n
	}
	if k.User != "" {
		return k.Owner, k.User
	}
	return "", ""
}
