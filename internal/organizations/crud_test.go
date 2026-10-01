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
	"fmt"
	"path/filepath"
	"sync"
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

// Creates racing one name leave one org and one winner. The lookup before the
// insert misses for every racer at once, so only an insert that writes when the
// key is free can decide; a create that upserted let every racer succeed and the
// last one overwrite the row the first was told it made.
func TestCreate_racingCreatorsLeaveOneWinner(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()

	const racers = 8
	for round := 0; round < 20; round++ {
		name := fmt.Sprintf("race-%d", round)
		var wg sync.WaitGroup
		start := make(chan struct{})
		results := make([]error, racers)
		for i := range racers {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				in := createIn(policy.AdminOrg, name)
				in.DisplayName = fmt.Sprintf("racer %d", i)
				_, results[i] = api.Create(ctx, in)
			}(i)
		}
		close(start)
		wg.Wait()

		won := -1
		for i, err := range results {
			switch {
			case err == nil && won >= 0:
				t.Fatalf("%s: racers %d and %d were both told they created it", name, won, i)
			case err == nil:
				won = i
			case code(t, err) != 409:
				t.Fatalf("%s: racer %d got %v, want 409", name, i, err)
			}
		}
		if won < 0 {
			t.Fatalf("%s: no racer created the org", name)
		}
		got, err := api.Get(ctx, &organizations.GetOrganizationInput{Owner: policy.AdminOrg, Name: name})
		if err != nil {
			t.Fatalf("%s: get: %v", name, err)
		}
		if want := fmt.Sprintf("racer %d", won); got.DisplayName != want {
			t.Fatalf("%s: stored row is %q, want the winner's %q", name, got.DisplayName, want)
		}
	}
}

// Memberships of a removed org of the same name hold the name: they would put
// their holders in the new org the moment it exists.
func TestCreate_leftoverMembershipsHoldTheName(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	if _, err := store.EnsureMembership(ctx, db, "acme/mallory", "widgets", store.RoleOwner); err != nil {
		t.Fatalf("seed membership: %v", err)
	}
	if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, "widgets")))); got != 409 {
		t.Fatalf("status=%d, want 409", got)
	}
}

// Deleting an org takes the rows that name it: its memberships, the keys members
// held in it, and the applications it owns. Its tombstone keeps the name held.
func TestDelete_forgetsTheRowsThatNameTheOrg(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	put(t, db, "widgets")
	for _, u := range []string{"acme/bob", "acme/carol"} {
		if _, err := store.EnsureMembership(ctx, db, u, "widgets", store.RoleMember); err != nil {
			t.Fatalf("seed membership: %v", err)
		}
	}
	for _, k := range []struct{ name, user string }{
		{"bob-secret", "acme/bob"},
		{"default", "widgets/ada"},
	} {
		row := orm.New[schema.Key](db)
		row.Owner, row.Name, row.User = "widgets", k.name, k.user
		row.SetId("widgets/" + k.name)
		if err := row.CreateCtx(ctx); err != nil {
			t.Fatalf("seed key: %v", err)
		}
	}
	a := orm.New[schema.Application](db)
	a.Owner, a.Name, a.Organization = "widgets", "widgets-agent", "widgets"
	a.SetId("widgets/widgets-agent")
	if err := a.CreateCtx(ctx); err != nil {
		t.Fatalf("seed application: %v", err)
	}

	if _, err := api.Delete(ctx, &organizations.DeleteOrganizationInput{Owner: policy.AdminOrg, Name: "widgets"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if rows, err := store.MembershipsByOrg(ctx, db, "widgets"); err != nil || len(rows) != 0 {
		t.Fatalf("memberships outlived the org: %v %v", rows, err)
	}
	if keys, _ := orm.TypedQuery[schema.Key](db).Filter("Owner=", "widgets").GetAll(ctx); len(keys) != 0 {
		t.Fatalf("%d keys owned by the org outlived it", len(keys))
	}
	if _, err := orm.Get[schema.Application](db, "widgets/widgets-agent"); !errors.Is(err, orm.ErrNotFound) {
		t.Fatalf("owned application outlived the org: %v", err)
	}
	// The rows are gone and the name stays held, by its tombstone.
	if left, err := store.OrgRemains(ctx, db, "widgets"); err != nil || len(left) != 0 {
		t.Fatalf("rows outlived the org: %v %v", left, err)
	}
	if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, "widgets")))); got != 409 {
		t.Fatalf("re-found: status=%d, want 409", got)
	}
}

// seedAccount files an account in org.
func seedAccount(t *testing.T, db orm.DB, org, name, typ string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Type = org, name, typ
	u.SetId(org + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed account %s/%s: %v", org, name, err)
	}
}

// An org whose people still live in it is not removed, however it is asked: its
// name would be free with an admin filed under it, and the next org of that name
// would open with them inside. Every account counts — a service account named
// after the org as much as a person. Nothing is removed on the refusal.
func TestDelete_refusedWhileAccountsLiveInIt(t *testing.T) {
	for _, acct := range []struct{ name, typ string }{
		{"mallory", "normal-user"},
		{"widgets-default", schema.ServiceAccount},
	} {
		t.Run(acct.name, func(t *testing.T) {
			db := freshDB(t)
			api := organizations.NewOrganizationAPI(db)
			ctx := context.Background()
			put(t, db, "widgets")
			seedAccount(t, db, "widgets", acct.name, acct.typ)
			if _, err := store.EnsureMembership(ctx, db, "acme/bob", "widgets", store.RoleMember); err != nil {
				t.Fatal(err)
			}

			err := must(api.Delete(ctx, &organizations.DeleteOrganizationInput{Owner: policy.AdminOrg, Name: "widgets"}))
			if got := code(t, err); got != 409 {
				t.Fatalf("status=%d, want 409", got)
			}
			if org, _ := store.GetOrganizationByName(ctx, db, "widgets"); org == nil {
				t.Fatal("org removed with an account still in it")
			}
			if rows, _ := store.MembershipsByOrg(ctx, db, "widgets"); len(rows) != 1 {
				t.Fatalf("a refused delete removed memberships: %v", rows)
			}
		})
	}
}

// A name an account or a key still points to is held: the new org would open with
// that account inside it, or that key authenticating into it.
func TestCreate_nameHeldByAnAccountOrAKey(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	seedAccount(t, db, "ghost", "mallory", "normal-user")
	k := orm.New[schema.Key](db)
	k.Owner, k.Name, k.User = "spectre", "old-key", "spectre/ada"
	k.SetId("spectre/old-key")
	if err := k.CreateCtx(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ghost", "spectre"} {
		if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, name)))); got != 409 {
			t.Fatalf("%s: status=%d, want 409", name, got)
		}
	}
}

// seedRow files one row of T under id, with fill setting its fields.
func seedRow[T any, P interface {
	*T
	SetId(string)
	CreateCtx(context.Context) error
}](t *testing.T, db orm.DB, id string, fill func(P)) {
	t.Helper()
	row := P(orm.New[T](db))
	fill(row)
	row.SetId(id)
	if err := row.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed %s: %v", id, err)
	}
}

// Every row that names a removed org goes with it: an invitation would admit its
// holder to the next org of that name, and an application serving it from another
// owner would mint tokens for that org. The same list decides what holds a name.
func TestDelete_forgetsEveryRowThatNamesTheOrg(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	put(t, db, "widgets")
	seedRow(t, db, "widgets/join-1", func(r *schema.Invitation) { r.Owner, r.Name = "widgets", "join-1" })
	seedRow(t, db, "admin/widgets-portal", func(r *schema.Application) {
		r.Owner, r.Name, r.Organization = "admin", "widgets-portal", "widgets"
	})
	seedRow(t, db, "widgets/editor", func(r *schema.Role) { r.Owner, r.Name = "widgets", "editor" })
	seedRow(t, db, "widgets/read", func(r *schema.Permission) { r.Owner, r.Name = "widgets", "read" })
	seedRow(t, db, "widgets/okta", func(r *schema.Provider) { r.Owner, r.Name = "widgets", "okta" })
	seedRow(t, db, "widgets/site", func(r *schema.Project) { r.Owner, r.Name, r.Organization = "widgets", "site", "widgets" })
	seedRow(t, db, "widgets/main", func(r *schema.Workspace) { r.Owner, r.Name, r.Organization = "widgets", "main", "widgets" })

	if held, err := store.OrgHeld(ctx, db, "widgets"); err != nil || !held {
		t.Fatalf("the rows must hold the name: held=%v err=%v", held, err)
	}
	if _, err := api.Delete(ctx, &organizations.DeleteOrganizationInput{Owner: policy.AdminOrg, Name: "widgets"}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	// The rows are gone and the name stays held, by its tombstone.
	if left, err := store.OrgRemains(ctx, db, "widgets"); err != nil || len(left) != 0 {
		t.Fatalf("rows outlived the org: %v %v", left, err)
	}
	if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, "widgets")))); got != 409 {
		t.Fatalf("re-found: status=%d, want 409", got)
	}
}

// A name an invitation or a serving application still points to is held.
func TestCreate_nameHeldByAnInvitationOrAServingApp(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	seedRow(t, db, "ghost/join-1", func(r *schema.Invitation) { r.Owner, r.Name = "ghost", "join-1" })
	seedRow(t, db, "admin/spectre-portal", func(r *schema.Application) {
		r.Owner, r.Name, r.Organization = "admin", "spectre-portal", "spectre"
	})
	for _, name := range []string{"ghost", "spectre"} {
		if got := code(t, must(api.Create(ctx, createIn(policy.AdminOrg, name)))); got != 409 {
			t.Fatalf("%s: status=%d, want 409", name, got)
		}
	}
}

// One of the platform's own applications serving the org holds it: the seed would
// restore that application pointing at whoever takes the name next, so a
// SuperAdmin re-points it before the org can go. Nothing is removed on refusal.
func TestDelete_refusedWhileAPlatformAppServesIt(t *testing.T) {
	db := freshDB(t)
	api := organizations.NewOrganizationAPI(db)
	ctx := context.Background()
	put(t, db, "maxpower")
	seedRow(t, db, "admin/maxpower-console", func(r *schema.Application) {
		r.Owner, r.Name, r.Organization, r.Platform = "admin", "maxpower-console", "maxpower", true
	})
	seedRow(t, db, "maxpower/join-1", func(r *schema.Invitation) { r.Owner, r.Name = "maxpower", "join-1" })

	err := must(api.Delete(ctx, &organizations.DeleteOrganizationInput{Owner: policy.AdminOrg, Name: "maxpower"}))
	if got := code(t, err); got != 409 {
		t.Fatalf("status=%d, want 409", got)
	}
	if a, _ := orm.Get[schema.Application](db, "admin/maxpower-console"); a == nil {
		t.Fatal("the platform application was removed")
	}
	if i, _ := orm.Get[schema.Invitation](db, "maxpower/join-1"); i == nil {
		t.Fatal("a refused delete removed rows")
	}
}
