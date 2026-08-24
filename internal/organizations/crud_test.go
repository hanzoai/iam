// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package organizations_test

// The organization handlers are transport over the store: the Guard has already
// decided WHO may act and on WHICH row, so what is left to each handler is to
// answer with the right status when the request cannot be honoured — a missing
// selector is 400, an absent row is 404, a name already taken is 409, and a store
// that cannot answer is 500. These cases call the handlers directly, because that
// is the level the status lives at: the same refusals hold however the request
// arrived, and a store error is reachable in no other way.

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/organizations"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// freshDB opens an isolated store the way the serving binary does — one open
// path, so a handler under test reads the store the server writes.
func freshDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := store.Open("sqlite", filepath.Join(t.TempDir(), "x.db"), "")
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// put files an organization under the reserved owner, which is where the registry
// holds every tenant. MasterPassword is seeded so a masked answer is visible.
func put(t *testing.T, db orm.DB, name string) {
	t.Helper()
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name = policy.AdminOrg, name
	o.DisplayName = name
	o.MasterPassword = "hunter2"
	o.PasswordType = "bcrypt"
	o.CreatedTime = time.Now().UTC().Format(time.RFC3339)
	o.SetId(policy.AdminOrg + "/" + name)
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s: %v", name, err)
	}
}

// code reads the HTTP status a handler refusal carries.
func code(t *testing.T, err error) int {
	t.Helper()
	var he *zip.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("error %v is not an *zip.HTTPError", err)
	}
	return he.Status
}

func createIn(owner, name string) *organizations.CreateOrganizationInput {
	in := &organizations.CreateOrganizationInput{}
	in.Owner, in.Name = owner, name
	return in
}

func updateIn(owner, name string) *organizations.UpdateOrganizationInput {
	in := &organizations.UpdateOrganizationInput{}
	in.Owner, in.Name = owner, name
	return in
}

// A write with no target is refused loudly, never run against every row. The same
// missing-selector 400 is the first thing every handler checks, so one table
// pins it across the whole surface.
func TestHandlers_missingSelectorIs400(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()

	for _, c := range []struct {
		name string
		call func() error
	}{
		{"create", func() error { _, e := api.Create(ctx, createIn("", "")); return e }},
		{"get", func() error { _, e := api.Get(ctx, &organizations.GetOrganizationInput{}); return e }},
		{"update", func() error { _, e := api.Update(ctx, updateIn("", "")); return e }},
		{"delete", func() error { _, e := api.Delete(ctx, &organizations.DeleteOrganizationInput{}); return e }},
		{"setAvatar", func() error { _, e := api.SetAvatar(ctx, &organizations.SetAvatarInput{Emoji: "🦁"}); return e }},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := code(t, c.call()); got != 400 {
				t.Fatalf("status=%d, want 400", got)
			}
		})
	}
}

// A row that is not there is 404 at its own address — not an empty success, and
// not a 500. SetAvatar carries a valid mark so the miss is the row, not the mark.
func TestHandlers_absentRowIs404(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	const gone = "nosuchorg"

	for _, c := range []struct {
		name string
		call func() error
	}{
		{"get", func() error {
			_, e := api.Get(ctx, &organizations.GetOrganizationInput{Owner: policy.AdminOrg, Name: gone})
			return e
		}},
		{"update", func() error { _, e := api.Update(ctx, updateIn(policy.AdminOrg, gone)); return e }},
		{"delete", func() error {
			_, e := api.Delete(ctx, &organizations.DeleteOrganizationInput{Owner: policy.AdminOrg, Name: gone})
			return e
		}},
		{"setAvatar", func() error {
			_, e := api.SetAvatar(ctx, &organizations.SetAvatarInput{Owner: policy.AdminOrg, Name: gone, Emoji: "🦁"})
			return e
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := code(t, c.call()); got != 404 {
				t.Fatalf("status=%d, want 404", got)
			}
		})
	}
}

// A name already in use is refused rather than taken over — the first write in a
// tenant must not silently adopt another's account.
func TestCreate_existingNameIs409(t *testing.T) {
	db := freshDB(t)
	put(t, db, "acme")
	api := organizations.NewOrganizationAPI(db)

	if got := code(t, must(api.Create(context.Background(), createIn(policy.AdminOrg, "acme")))); got != 409 {
		t.Fatalf("status=%d, want 409", got)
	}
}

// The built-in admin organization cannot be deleted — losing it would leave the
// account with no way back in — so the refusal is 403 and comes before the store
// is ever asked whether the row is there.
func TestDelete_adminOrgIsForbidden(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)

	if got := code(t, must(api.Delete(context.Background(),
		&organizations.DeleteOrganizationInput{Owner: policy.AdminOrg, Name: policy.AdminOrg}))); got != 403 {
		t.Fatalf("status=%d, want 403", got)
	}
}

// A store that cannot be read is 500, not a false 404: the row's absence and the
// store's silence are different answers. A closed store fails the lookup every
// handler does first, so one table pins the arm across the surface.
func TestHandlers_storeReadErrorIs500(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	for _, c := range []struct {
		name string
		call func() error
	}{
		{"create", func() error { _, e := api.Create(ctx, createIn(policy.AdminOrg, "acme")); return e }},
		{"get", func() error {
			_, e := api.Get(ctx, &organizations.GetOrganizationInput{Owner: policy.AdminOrg, Name: "acme"})
			return e
		}},
		{"update", func() error { _, e := api.Update(ctx, updateIn(policy.AdminOrg, "acme")); return e }},
		{"delete", func() error {
			_, e := api.Delete(ctx, &organizations.DeleteOrganizationInput{Owner: policy.AdminOrg, Name: "acme"})
			return e
		}},
		{"setAvatar", func() error {
			_, e := api.SetAvatar(ctx, &organizations.SetAvatarInput{Owner: policy.AdminOrg, Name: "acme", Emoji: "🦁"})
			return e
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := code(t, c.call()); got != 500 {
				t.Fatalf("status=%d, want 500", got)
			}
		})
	}
}

// A store that reads but cannot write is 500 too. The row is there — the lookup
// takes no context and finds it — so a cancelled context fails at the write and
// nowhere else, which is the arm each mutation carries past its lookup. Get is
// absent here: it never writes, so a cancelled context leaves it a clean read.
func TestHandlers_storeWriteErrorIs500(t *testing.T) {
	db := freshDB(t)
	put(t, db, "acme") // update/delete/setAvatar resolve this; create must not
	api := organizations.NewOrganizationAPI(db)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	for _, c := range []struct {
		name string
		call func() error
	}{
		{"create", func() error { _, e := api.Create(ctx, createIn(policy.AdminOrg, "fresh")); return e }},
		{"update", func() error { _, e := api.Update(ctx, updateIn(policy.AdminOrg, "acme")); return e }},
		{"delete", func() error {
			_, e := api.Delete(ctx, &organizations.DeleteOrganizationInput{Owner: policy.AdminOrg, Name: "acme"})
			return e
		}},
		{"setAvatar", func() error {
			_, e := api.SetAvatar(ctx, &organizations.SetAvatarInput{Owner: policy.AdminOrg, Name: "acme", Emoji: "🦁"})
			return e
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := code(t, c.call()); got != 500 {
				t.Fatalf("status=%d, want 500", got)
			}
		})
	}
}

// Create makes the account. It stamps a creation instant when the caller sends
// none and keeps the caller's when they do, and it answers with the masked row —
// the credential settings it just stored never ride back out.
func TestCreate_success(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()

	t.Run("stamps a creation instant when none is sent", func(t *testing.T) {
		in := createIn(policy.AdminOrg, "acme")
		in.MasterPassword = "hunter2"
		got, err := api.Create(ctx, in)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if got.Name != "acme" || got.Owner != policy.AdminOrg {
			t.Fatalf("created (%q,%q), want (%s,acme)", got.Owner, got.Name, policy.AdminOrg)
		}
		if got.CreatedTime == "" {
			t.Fatal("createdTime was not stamped")
		}
		if got.MasterPassword != "***" {
			t.Fatalf("masterPassword = %q, want it masked", got.MasterPassword)
		}
	})

	t.Run("keeps the creation instant the caller sends", func(t *testing.T) {
		in := createIn(policy.AdminOrg, "orgb")
		in.CreatedTime = "2020-01-02T03:04:05Z"
		got, err := api.Create(ctx, in)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		if got.CreatedTime != "2020-01-02T03:04:05Z" {
			t.Fatalf("createdTime = %q, want the one sent", got.CreatedTime)
		}
	})
}

// List reads the caller's scope off the principal the Guard resolved. Reached
// with none — the way the MCP server hands a typed op straight to a handler — it
// answers no one with nothing rather than the whole registry.
func TestList_withoutAPrincipalIsForbidden(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)

	if got := code(t, must(api.List(context.Background(), &organizations.ListOrganizationsInput{}))); got != 403 {
		t.Fatalf("status=%d, want 403", got)
	}
}

// must discards a handler's typed value so a status-only case reads as one
// expression. The value is nil on the error paths under test.
func must[T any](_ *T, err error) error { return err }
