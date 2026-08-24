// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package keys

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/principal"
	"github.com/hanzoai/iam/pkg/schema"
)

// closedDB is an open store that has already been shut, so every read the
// handlers issue (orm.Get, TypedQuery.First/GetAll) returns a real store error
// rather than ErrNotFound — the shape that must surface as a 500, never a 404.
func closedDB(t *testing.T) orm.DB {
	t.Helper()
	db := memDB(t)
	if err := db.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	return db
}

// cancelled is a context already past its end, so the ctx-carrying WRITES
// (CreateCtx/UpdateCtx/DeleteCtx) fail even though the ctx-free lookups that
// precede them still see the store — this is how the write-side 500 arms are
// reached without breaking the read that guards them.
func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// status reads the HTTP status a handler refused with, failing the test if the
// error is not a zip refusal at all — so a 400 arm and a 500 arm are told apart
// by the code they carry, not merely by being non-nil.
func status(t *testing.T, err error) int {
	t.Helper()
	var he *zip.HTTPError
	if !errors.As(err, &he) {
		t.Fatalf("error is not a *zip.HTTPError: %v", err)
	}
	return he.Status
}

// seedSharedRow plants the org-wide secret row an older build addressed as
// (owner, UserKeyName) — the row MintUserKey retires on the next secret mint.
func seedSharedRow(t *testing.T, db orm.DB, owner string) {
	t.Helper()
	k := orm.New[schema.Key](db)
	k.SetId(id(owner, UserKeyName))
	k.Owner, k.Name = owner, UserKeyName
	k.Type, k.User = "User", "someone"
	k.AccessKey, k.AccessSecret = Mint("pk", ""), Mint("sk", "")
	k.State = "Active"
	if err := k.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed shared row: %v", err)
	}
}

// Every ITEM handler names its key by (owner, name); with neither supplied there
// is nothing to act on, and the refusal is a 400 — the request was malformed, not
// the store. list is not among them: a listing's tenant comes from the credential,
// so an absent owner is a question about the caller, never a malformed request.
func TestHandlers_RequireIdentity(t *testing.T) {
	cases := []struct {
		name string
		call func(db orm.DB, ctx context.Context) error
	}{
		{"get", func(db orm.DB, ctx context.Context) error { _, e := get(db)(ctx, &Ref{Name: "svc"}); return e }},
		{"create", func(db orm.DB, ctx context.Context) error {
			_, e := create(db)(ctx, &schema.Key{Name: "svc"})
			return e
		}},
		{"update", func(db orm.DB, ctx context.Context) error {
			_, e := update(db)(ctx, &schema.Key{Name: "svc"})
			return e
		}},
		{"del", func(db orm.DB, ctx context.Context) error { _, e := del(db)(ctx, &Ref{Name: "svc"}); return e }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := status(t, tc.call(memDB(t), context.Background())); got != 400 {
				t.Fatalf("%s without an owner = %d, want 400", tc.name, got)
			}
		})
	}
}

// A read or write addressed at a key that isn't there is a 404 — a definite
// "no such key", which a caller can act on, and never the 500 a store fault
// would raise.
func TestHandlers_AbsentKeyIs404(t *testing.T) {
	cases := []struct {
		name string
		call func(db orm.DB, ctx context.Context) error
	}{
		{"get", func(db orm.DB, ctx context.Context) error {
			_, e := get(db)(ctx, &Ref{Owner: "acme", Name: "ghost"})
			return e
		}},
		{"update", func(db orm.DB, ctx context.Context) error {
			_, e := update(db)(ctx, &schema.Key{Owner: "acme", Name: "ghost"})
			return e
		}},
		{"del", func(db orm.DB, ctx context.Context) error {
			_, e := del(db)(ctx, &Ref{Owner: "acme", Name: "ghost"})
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := status(t, tc.call(memDB(t), context.Background())); got != 404 {
				t.Fatalf("%s of an absent key = %d, want 404", tc.name, got)
			}
		})
	}
}

// A name already minted in the org is REFUSED with a 409 rather than reissued,
// so creating twice never silently invalidates a key that is live in production.
func TestCreate_DuplicateNameIsConflict(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	if _, err := create(db)(ctx, &schema.Key{Owner: "acme", Name: "svc"}); err != nil {
		t.Fatalf("first create: %v", err)
	}
	_, err := create(db)(ctx, &schema.Key{Owner: "acme", Name: "svc"})
	if got := status(t, err); got != 409 {
		t.Fatalf("re-create of an existing name = %d, want 409", got)
	}
}

// When the STORE ITSELF is broken, the read each handler issues returns an error
// that is not ErrNotFound, and that must surface as a 500 — a broken store is
// never a 400 or a 404.
func TestHandlers_StoreFaultIs500(t *testing.T) {
	cases := []struct {
		name string
		call func(db orm.DB, ctx context.Context) error
	}{
		{"list", func(db orm.DB, ctx context.Context) error {
			_, e := list(db)(as("acme"), &ListRequest{Owner: "acme"})
			return e
		}},
		{"get", func(db orm.DB, ctx context.Context) error {
			_, e := get(db)(ctx, &Ref{Owner: "acme", Name: "svc"})
			return e
		}},
		{"create", func(db orm.DB, ctx context.Context) error {
			_, e := create(db)(ctx, &schema.Key{Owner: "acme", Name: "svc"})
			return e
		}},
		{"update", func(db orm.DB, ctx context.Context) error {
			_, e := update(db)(ctx, &schema.Key{Owner: "acme", Name: "svc"})
			return e
		}},
		{"del", func(db orm.DB, ctx context.Context) error {
			_, e := del(db)(ctx, &Ref{Owner: "acme", Name: "svc"})
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := status(t, tc.call(closedDB(t), context.Background())); got != 500 {
				t.Fatalf("%s against a broken store = %d, want 500", tc.name, got)
			}
		})
	}
}

// The lookup succeeds and the WRITE is what fails: the ctx-free guard read sees
// the store (an empty one for create, a seeded row for update/del), then the
// ctx-carrying write is refused on a dead context — the write-side 500 arm.
func TestHandlers_WriteFaultIs500(t *testing.T) {
	seed := func(t *testing.T, db orm.DB) {
		t.Helper()
		if _, err := create(db)(context.Background(), &schema.Key{Owner: "acme", Name: "svc"}); err != nil {
			t.Fatalf("seed key: %v", err)
		}
	}
	cases := []struct {
		name  string
		setup func(t *testing.T, db orm.DB) // nil when the fresh store is the fixture
		call  func(db orm.DB, ctx context.Context) error
	}{
		{"create", nil, func(db orm.DB, ctx context.Context) error {
			_, e := create(db)(ctx, &schema.Key{Owner: "acme", Name: "svc"})
			return e
		}},
		{"update", seed, func(db orm.DB, ctx context.Context) error {
			_, e := update(db)(ctx, &schema.Key{Owner: "acme", Name: "svc", DisplayName: "renamed"})
			return e
		}},
		{"del", seed, func(db orm.DB, ctx context.Context) error {
			_, e := del(db)(ctx, &Ref{Owner: "acme", Name: "svc"})
			return e
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db := memDB(t)
			if tc.setup != nil {
				tc.setup(t, db)
			}
			if got := status(t, tc.call(db, cancelled())); got != 500 {
				t.Fatalf("%s whose write faulted = %d, want 500", tc.name, got)
			}
		})
	}
}

// del removes the key and reports it: afterwards the same address reads back a
// 404, so the delete was a real removal and not just a truthful-looking reply.
func TestDel_RemovesTheKey(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	if _, err := create(db)(ctx, &schema.Key{Owner: "acme", Name: "svc"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	out, err := del(db)(ctx, &Ref{Owner: "acme", Name: "svc"})
	if err != nil || out == nil || !out.Deleted {
		t.Fatalf("del = %+v, %v; want Deleted=true", out, err)
	}
	if _, err := get(db)(ctx, &Ref{Owner: "acme", Name: "svc"}); status(t, err) != 404 {
		t.Fatal("key still readable after del")
	}
}

// Route binds all five verbs onto the app without collision, and the app builds
// — the registration that threads each handler its one entity store.
func TestRoute_RegistersAndBuilds(t *testing.T) {
	app := zip.New(zip.Config{AppName: "keys-route-test", DisableStartupMessage: true})
	Route(app, memDB(t))
	if err := app.Build(); err != nil {
		t.Fatalf("build: %v", err)
	}
}

// State picks the env segment: "test" mints a -test- half, anything else a
// -live- one, and the prefix is whichever half was asked for.
func TestMint_StateSelectsEnv(t *testing.T) {
	if s := Mint("sk", "test"); !strings.HasPrefix(s, "sk-") || !strings.Contains(s, "-test-") {
		t.Fatalf("Mint(sk,test) = %q, want an sk- test half", s)
	}
	if s := Mint("pk", ""); !strings.HasPrefix(s, "pk-") || !strings.Contains(s, "-live-") {
		t.Fatalf(`Mint(pk,"") = %q, want a pk- live half`, s)
	}
}

// A mint with no owner, or no user, has no row identity to write and is refused
// before it touches the store.
func TestMintUserKey_RequiresOwnerAndUser(t *testing.T) {
	db := memDB(t)
	ctx := context.Background()
	if _, err := MintUserKey(ctx, db, "  ", "ada", ""); err == nil {
		t.Fatal("MintUserKey with a blank owner succeeded")
	}
	if _, err := MintUserKey(ctx, db, "acme", "", ""); err == nil {
		t.Fatal("MintUserKey with no user succeeded")
	}
}

// Each store fault along the mint path returns the error rather than a
// half-written credential: a broken read on the shared-row retirement or the
// existing-row lookup, and a broken write on the retire, the in-place rotate,
// and the fresh create.
func TestMintUserKey_StoreFaults(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T) (orm.DB, context.Context, string) // db, ctx, scope
	}{
		// Retiring the shared row reads first; a broken store surfaces there.
		{"shared-lookup", func(t *testing.T) (orm.DB, context.Context, string) {
			return closedDB(t), context.Background(), ""
		}},
		// A publish mint skips retirement and faults on the existing-row read.
		{"existing-lookup", func(t *testing.T) (orm.DB, context.Context, string) {
			return closedDB(t), context.Background(), schema.KeyScopePublish
		}},
		// The shared row is found, and its DELETE is what fails.
		{"shared-delete", func(t *testing.T) (orm.DB, context.Context, string) {
			db := memDB(t)
			seedSharedRow(t, db, "acme")
			return db, cancelled(), ""
		}},
		// The existing row is found, and the in-place UPDATE is what fails.
		{"existing-update", func(t *testing.T) (orm.DB, context.Context, string) {
			db := memDB(t)
			if _, err := MintUserKey(context.Background(), db, "acme", "ada", schema.KeyScopePublish); err != nil {
				t.Fatalf("seed publishable key: %v", err)
			}
			return db, cancelled(), schema.KeyScopePublish
		}},
		// No row yet, so the CREATE of the fresh row is what fails.
		{"create-new", func(t *testing.T) (orm.DB, context.Context, string) {
			return memDB(t), cancelled(), schema.KeyScopePublish
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, ctx, scope := tc.setup(t)
			if _, err := MintUserKey(ctx, db, "acme", "ada", scope); err == nil {
				t.Fatal("MintUserKey returned nil through a store fault")
			}
		})
	}
}

// Revoke's guard returns success when the row is absent, and First yields a nil
// entity on ANY read error (never an entity beside an error), so a broken store
// read lands on the same `k == nil` arm — reported as the "already absent"
// success a revoke is entitled to assert. This pins that the non-NotFound error
// still resolves through the nil guard rather than escaping.
func TestRevokeUserKey_BrokenReadIsAbsent(t *testing.T) {
	if err := RevokeUserKey(context.Background(), closedDB(t), "acme", "ada", ""); err != nil {
		t.Fatalf("revoke over a broken read = %v, want nil (the nil-row guard subsumes it)", err)
	}
}

// as returns a context carrying an ordinary member of org — the caller a listing
// is scoped to. A handler that resolves its tenant from the credential needs one
// to answer at all.
func as(org string) context.Context {
	return principal.Bind(context.Background(), &principal.Principal{Org: org})
}

// A listing with NOBODY behind it is refused, not answered. principal.Scope has
// no credential to resolve a tenant from, and "no tenant" would mean no filter —
// every organization's keys in one page.
func TestList_WithoutACallerIsRefused(t *testing.T) {
	if got := status(t, func() error { _, e := list(memDB(t))(context.Background(), &ListRequest{}); return e }()); got != 403 {
		t.Fatalf("list with no principal = %d, want 403", got)
	}
}

// And a member of one organization never receives another's, however the request
// spells it. A key row carries the publishable half and the scope it may reach,
// so a foreign page is a map of somebody else's integrations.
func TestList_NeverAnswersWithAnotherOrgsKeys(t *testing.T) {
	db := memDB(t)
	for _, o := range []string{"acme", "other"} {
		k := orm.New[schema.Key](db)
		k.Owner, k.Name = o, "svc"
		k.AccessKey, k.AccessSecret = Mint("pk", ""), Mint("sk", "")
		k.SetId(id(o, "svc"))
		if err := k.CreateCtx(context.Background()); err != nil {
			t.Fatalf("seed %s: %v", o, err)
		}
	}
	if _, err := list(db)(as("acme"), &ListRequest{Owner: "other"}); err == nil {
		t.Fatal("a member of acme named other and was not refused")
	}
	out, err := list(db)(as("acme"), &ListRequest{})
	if err != nil {
		t.Fatalf("acme listing its own keys: %v", err)
	}
	for _, k := range out.Keys {
		if k.Owner != "acme" {
			t.Fatalf("LEAK: acme named no owner and received %q's key %q", k.Owner, k.Name)
		}
	}
	if len(out.Keys) != 1 {
		t.Fatalf("acme's own page returned %d keys, want 1 — the assertion above cannot "+
			"fail against an empty page", len(out.Keys))
	}
}
