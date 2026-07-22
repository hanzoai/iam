// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package store

import (
	"context"
	"errors"
	"testing"

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

// UserByAccessKey resolves each key shape to the correct user and FAILS CLOSED on
// everything else — the security invariant a wrong resolution would violate.
func TestUserByAccessKey_ResolvesEachShape(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()

	u := seedKeyUser(t, db, "hanzo", "alice", "alice@hanzo.ai", "hk-live-ALICEKEY")
	// A schema.Key credential (pk-/sk-) belonging to hanzo/alice.
	seedKey(t, db, "hanzo", "alice-key", "hanzo/alice", "pk-live-PROJ", "sk-live-SECRET")

	for _, tc := range []struct{ name, key string }{
		{"hk on the user row", "hk-live-ALICEKEY"},
		{"pk publishable half", "pk-live-PROJ"},
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
}

// A key whose row references a user by bare username (no owner/name) resolves within
// the key's own tenant — never across tenants.
func TestUserByAccessKey_BareUserRefWithinTenant(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedKeyUser(t, db, "hanzo", "bob", "bob@hanzo.ai", "")
	seedKey(t, db, "hanzo", "bob-key", "bob", "pk-live-BOB", "sk-live-BOB")

	got, err := UserByAccessKey(ctx, db, "pk-live-BOB")
	if err != nil || got == nil || got.Owner != "hanzo" || got.Name != "bob" {
		t.Fatalf("bare-user pk resolved %+v err=%v, want hanzo/bob", got, err)
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
