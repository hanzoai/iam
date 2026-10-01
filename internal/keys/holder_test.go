// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keys

import (
	"context"
	"fmt"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// speaksFor asserts a secret authenticates as owner/name, acting in org.
func speaksFor(t *testing.T, db orm.DB, secret, owner, name, org string) {
	t.Helper()
	h, err := store.HolderByAccessKey(context.Background(), db, secret)
	if err != nil {
		t.Fatalf("the secret does not authenticate: %s", store.Reason(err))
	}
	if h.User.Owner != owner || h.User.Name != name || h.Org != org {
		t.Fatalf("the secret speaks for %s/%s in %s, want %s/%s in %s", h.User.Owner, h.User.Name, h.Org, owner, name, org)
	}
}

// A person who creates a key holds it: naming nobody binds the key to the caller,
// and naming themselves — qualified or bare — is the same key.
func TestCreate_APersonsKeyIsTheirOwn(t *testing.T) {
	db := memDB(t)
	seedUser(t, db, "acme", "boss")
	boss := principal.Bind(context.Background(), &principal.Principal{Org: "acme", User: "boss", Admin: true})

	k, err := create(db)(boss, &schema.Key{Owner: "acme", Name: "mine"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if k.User != "acme/boss" {
		t.Fatalf("key holder = %q, want the caller acme/boss", k.User)
	}
	speaksFor(t, db, k.AccessSecret, "acme", "boss", "acme")

	for i, self := range []string{"acme/boss", "boss"} {
		k, err := create(db)(boss, &schema.Key{Owner: "acme", Name: fmt.Sprintf("self-%d", i), User: self})
		if err != nil {
			t.Fatalf("naming yourself as %q was refused: %v", self, err)
		}
		if k.User != "acme/boss" {
			t.Fatalf("naming yourself as %q stored holder %q, want acme/boss", self, k.User)
		}
	}
}

// An org's admin by membership holds their key in that org: it names them, and it
// acts in the key's org, not in their home.
func TestCreate_AnAdminByMembershipHoldsTheirKeyInThatOrg(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedUser(t, db, "agency", "josh")
	if _, err := store.EnsureMembership(ctx, db, "agency/josh", "client", store.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	josh := principal.Bind(ctx, &principal.Principal{
		Org: "agency", User: "josh",
		Orgs: map[string]policy.Role{"client": policy.Role(store.RoleAdmin)},
	})

	k, err := create(db)(josh, &schema.Key{Owner: "client", Name: "josh"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if k.User != "agency/josh" {
		t.Fatalf("key holder = %q, want the caller agency/josh", k.User)
	}
	speaksFor(t, db, k.AccessSecret, "agency", "josh", "client")
}

// A person never creates a key that speaks for someone else, however the holder is
// spelled, and nothing is written when they try.
func TestCreate_APersonNamesNoOtherHolder(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedUser(t, db, "acme", "boss")
	seedUser(t, db, "acme", "ada")
	seedUser(t, db, "agency", "josh")
	if _, err := store.EnsureMembership(ctx, db, "agency/josh", "acme", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	boss := principal.Bind(ctx, &principal.Principal{Org: "acme", User: "boss", Admin: true})

	for _, other := range []string{"acme/ada", "ada", "agency/josh", "admin/z", "acme/", "/boss", "acme/boss/x"} {
		_, err := create(db)(boss, &schema.Key{Owner: "acme", Name: "planted", User: other})
		if err == nil {
			t.Fatalf("a person created a key held by %q", other)
		}
		if got := status(t, err); got != 403 {
			t.Fatalf("holder %q: status=%d, want 403", other, got)
		}
	}
	if _, err := orm.Get[schema.Key](db, "acme/planted"); err == nil {
		t.Fatal("a refused create wrote a key")
	}
}

// A SuperAdmin names the person a key is for — how an existing org's owner is
// given their default key — within the rule every holder obeys: an account of
// the org or a member of it, never a stranger. Naming nobody leaves the key
// with no holder, because a SuperAdmin holds no key.
func TestCreate_ASuperAdminNamesTheHolder(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedUser(t, db, "acme", "ada")
	seedUser(t, db, "agency", "josh")
	if _, err := store.EnsureMembership(ctx, db, "agency/josh", "acme", store.RoleMember); err != nil {
		t.Fatal(err)
	}
	root := principal.Bind(ctx, &principal.Principal{Org: policy.AdminOrg, User: "root", Sudo: true})

	k, err := create(db)(root, &schema.Key{Owner: "acme", Name: "default", DisplayName: "Default", User: "acme/ada"})
	if err != nil {
		t.Fatalf("a SuperAdmin could not give ada her key: %v", err)
	}
	if k.User != "acme/ada" {
		t.Fatalf("key holder = %q, want acme/ada", k.User)
	}
	speaksFor(t, db, k.AccessSecret, "acme", "ada", "acme")

	if k, err := create(db)(root, &schema.Key{Owner: "acme", Name: "josh", User: "agency/josh"}); err != nil || k.User != "agency/josh" {
		t.Fatalf("a SuperAdmin could not give a member their key: %v", err)
	}
	if _, err := create(db)(root, &schema.Key{Owner: "acme", Name: "stray", User: "elsewhere/stray"}); err == nil {
		t.Fatal("a SuperAdmin created a key for someone who is neither in nor a member of the org")
	}
	if k, err := create(db)(root, &schema.Key{Owner: "acme", Name: "unheld"}); err != nil || k.User != "" {
		t.Fatalf("a SuperAdmin's key that names nobody = %+v, %v; want no holder", k, err)
	}
}

// A confidential client mints for the person it names, as before; naming nobody
// leaves the key with no holder, because the client is no person.
func TestCreate_AnAppMintsForThePersonItNames(t *testing.T) {
	db := memDB(t)
	seedUser(t, db, "acme", "ada")
	minter := principal.Bind(context.Background(), &principal.Principal{App: &policy.App{Name: "hanzo-console", Owner: policy.AdminOrg}, Org: "acme"})

	k, err := create(db)(minter, &schema.Key{Owner: "acme", Name: "ada", User: "acme/ada"})
	if err != nil || k.User != "acme/ada" {
		t.Fatalf("the minter could not write ada's key: %+v, %v", k, err)
	}
	if k, err := create(db)(minter, &schema.Key{Owner: "acme", Name: "unheld"}); err != nil || k.User != "" {
		t.Fatalf("the minter's key that names nobody = %+v, %v; want no holder", k, err)
	}
}

// A key names its holder for as long as it exists when a person edits it: the
// secret is in the holder's hands, so repointing it would hand them whoever it
// named next. A person's create-then-repoint is therefore refused like a create
// that names someone else, and an edit that keeps the holder goes through.
func TestUpdate_APersonCannotRepointAKey(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	seedUser(t, db, "acme", "boss")
	seedUser(t, db, "acme", "ada")
	boss := principal.Bind(ctx, &principal.Principal{Org: "acme", User: "boss", Admin: true})

	k, err := create(db)(boss, &schema.Key{Owner: "acme", Name: "mine"})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, to := range []string{"acme/ada", "ada", ""} {
		_, err := update(db)(boss, &schema.Key{Owner: "acme", Name: "mine", User: to})
		if err == nil {
			t.Fatalf("a person repointed their key at %q", to)
		}
		if got := status(t, err); got != 403 {
			t.Fatalf("repoint to %q: status=%d, want 403", to, got)
		}
	}
	if _, err := update(db)(boss, &schema.Key{Owner: "acme", Name: "mine", User: k.User, DisplayName: "renamed"}); err != nil {
		t.Fatalf("an edit that keeps the holder was refused: %v", err)
	}
	speaksFor(t, db, k.AccessSecret, "acme", "boss", "acme")
}
