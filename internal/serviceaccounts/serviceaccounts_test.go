// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package serviceaccounts

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	policy "github.com/hanzoai/authz"
	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/internal/authz"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// mint is the security core, and its whole job is that the credential it hands
// out can actually be USED. It writes a schema.Key row — the one place the
// resolver looks — holding the secret's DIGEST and never the secret.
//
// The credential must live where the resolver looks. store.UserByAccessKey
// resolves an sk- through schema.Key, and cred.Verify is never called against a
// User's AccessSecretHash — so a key written onto the User row instead would
// answer "not recognized" on every call, unresolvable from the moment it was
// issued. This test asserts the RESOLUTION, not merely the storage, so a
// credential home no resolver reads cannot pass.
func TestMint_IssuesAResolvableCredentialAndStoresNoPlaintext(t *testing.T) {
	ctx, db := context.Background(), memDB(t)
	sa := orm.New[schema.User](db)
	sa.Owner, sa.Name, sa.Type = "hanzo", "hanzo-bot", "service-account"
	sa.SetId("hanzo/hanzo-bot")
	if err := sa.CreateCtx(ctx); err != nil {
		t.Fatalf("seed account: %v", err)
	}

	key, secret, err := mint(ctx, db, sa)
	if err != nil {
		t.Fatal(err)
	}
	if key == "" || secret == "" {
		t.Fatal("mint returned an empty credential")
	}

	// THE POINT: the secret resolves to its own service account.
	u, err := store.UserByAccessKey(ctx, db, secret)
	if err != nil {
		t.Fatalf("the minted secret does not resolve: %v", err)
	}
	if u.Owner != "hanzo" || u.Name != "hanzo-bot" {
		t.Fatalf("resolved %s/%s, want hanzo/hanzo-bot", u.Owner, u.Name)
	}

	// The row holds a digest and no plaintext; the User row holds nothing at all.
	k, err := orm.TypedQuery[schema.Key](db).Filter("AccessSecretDigest=", schema.DigestSecret(secret)).First()
	if err != nil || k == nil {
		t.Fatalf("no key row answers the secret's digest: %v", err)
	}
	if k.AccessSecret != "" {
		t.Fatalf("the key row stored the plaintext secret: %q", k.AccessSecret)
	}
	if sa.AccessSecret != "" || sa.AccessSecretHash != "" || sa.AccessKey != "" {
		t.Fatal("the User row must carry no credential material — nothing resolves it")
	}

	// Rotation replaces: the prior secret stops resolving, the new one starts.
	_, secret2, err := mint(ctx, db, sa)
	if err != nil {
		t.Fatal(err)
	}
	if secret2 == secret {
		t.Fatal("rotation must mint a fresh secret")
	}
	if _, err := store.UserByAccessKey(ctx, db, secret); err == nil {
		t.Fatal("the superseded secret still resolves — a rotated key would stay live")
	}
	if _, err := store.UserByAccessKey(ctx, db, secret2); err != nil {
		t.Fatalf("the rotated secret does not resolve: %v", err)
	}
}

// memDB is a real SQLite the ORM can index, because this test asserts on an
// indexed lookup and a fake would prove nothing about it.
func memDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "sa.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// admin gates every credential MUTATION: a mint-capable app, a SuperAdmin, or an
// admin of the target org itself — never a foreign-org admin, never a read-only
// app, never a regular user.
func TestAdminGate(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-team")
	t.Setenv("IAM_SA_LIST_ALLOWED_APPS", "hanzo-reader")
	for _, c := range []struct {
		name string
		p    *authz.Principal
		org  string
		want bool
	}{
		{"mint-cap app (admin-owned)", &authz.Principal{App: &policy.App{Name: "hanzo-team", Owner: "admin"}}, "hanzo", true},
		{"tenant-owned mint-named app denied", &authz.Principal{App: &policy.App{Name: "hanzo-team", Owner: "evil"}}, "hanzo", false},
		{"non-cap app", &authz.Principal{App: &policy.App{Name: "rogue", Owner: "admin"}}, "hanzo", false},
		{"read-only app cannot mint", &authz.Principal{App: &policy.App{Name: "hanzo-reader", Owner: "admin"}}, "hanzo", false},
		{"super human", &authz.Principal{Org: "admin", Sudo: true}, "orgb", true},
		{"org admin own org", &authz.Principal{Org: "hanzo", Admin: true}, "hanzo", true},
		{"org admin foreign org", &authz.Principal{Org: "hanzo", Admin: true}, "orgb", false},
		{"regular human", &authz.Principal{Org: "hanzo"}, "hanzo", false},
		{"nil principal", nil, "hanzo", false},
	} {
		if got := admin(c.p, c.org); got != c.want {
			t.Fatalf("%s: admin(%v,%q) = %v, want %v", c.name, c.p, c.org, got, c.want)
		}
	}
}

// A RESERVED SYSTEM ORG IS NOT A TENANT, and no app may provision into one.
//
// create takes the target org from the request BODY, and a principal's home org is
// part of its platform authority — authz resolves Principal.Sudo from
// memberOf(policy.AdminOrg), which answers home-or-membership. A minted row is
// therefore an identity with whatever the named org confers, carrying pk-/sk- keys
// of its own, so the org a mint may name has to be a tenant.
//
// The signup org carries the same weight for a different reason: a machine-typed
// row there names the platform's own balance as its payer. One org boundary
// answers both.
//
// A human SuperAdmin keeps the ability: that authority IS what the reserved org
// denotes, so refusing it there would deny the only principal allowed to hold it.
func TestAdminGate_ReservedOrgIsNotATenant(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-team")
	minter := &authz.Principal{App: &policy.App{Name: "hanzo-team", Owner: "admin"}}
	for _, org := range []string{"admin", "built-in", "app"} {
		if admin(minter, org) {
			t.Errorf("a mint-cap app must NOT provision into the reserved org %q", org)
		}
		// …and the same refusal holds for a human org admin, whose authority is
		// its OWN tenant and never a system org.
		if admin(&authz.Principal{Org: org, Admin: true}, org) {
			t.Errorf("a non-super org admin must NOT provision into the reserved org %q", org)
		}
		if !admin(&authz.Principal{Org: "admin", Sudo: true}, org) {
			t.Errorf("a SuperAdmin must still provision into %q", org)
		}
	}
	// A TENANT IS UNAFFECTED — including the signup org, which is not reserved
	// (making it reserved would refuse every self-serve signup). The refusal above
	// must narrow the reserved set and nothing else.
	for _, org := range []string{"hanzo", "lux", "zoo", "acme"} {
		if !admin(minter, org) {
			t.Errorf("a mint-cap app must still provision into the tenant org %q", org)
		}
	}
}

// read gates the LIST surface: the mint cap is a superset (any org); the read-only
// cap suffices but ONLY within the org the app's <org>-<app> name binds it to, so
// a leaked reader credential enumerates one tenant and never another.
func TestReadGate_TenantBound(t *testing.T) {
	t.Setenv("IAM_KEY_MINT_ALLOWED_APPS", "hanzo-team")
	t.Setenv("IAM_SA_LIST_ALLOWED_APPS", "hanzo-reader")
	if !read(&authz.Principal{App: &policy.App{Name: "hanzo-team", Owner: "admin"}}, "lux") {
		t.Fatal("a mint-cap app may enumerate any org")
	}
	if !read(&authz.Principal{App: &policy.App{Name: "hanzo-reader", Owner: "admin"}}, "hanzo") {
		t.Fatal("hanzo-reader may list its own tenant")
	}
	if read(&authz.Principal{App: &policy.App{Name: "hanzo-reader", Owner: "admin"}}, "lux") {
		t.Fatal("hanzo-reader must NOT list lux — a cross-tenant roster leak")
	}
	if read(&authz.Principal{App: &policy.App{Name: "rogue", Owner: "admin"}}, "hanzo") {
		t.Fatal("an uncapable app must list nothing")
	}
	// A tenant-owned app spoofing an allow-listed NAME reads nothing — the owner-pin
	// denies the capability before the tenant-binding is even consulted.
	if read(&authz.Principal{App: &policy.App{Name: "hanzo-reader", Owner: "evil"}}, "hanzo") {
		t.Fatal("a tenant-owned app named like the reader must NOT enumerate any org")
	}
	if read(&authz.Principal{App: &policy.App{Name: "hanzo-team", Owner: "evil"}}, "lux") {
		t.Fatal("a tenant-owned app named like the minter must NOT enumerate any org")
	}
}

// canonical maps a request pair to the <org>-<agent> handle and refuses a
// malformed one at the boundary rather than persisting it.
func TestCanonicalAndValid(t *testing.T) {
	if got := canonical("hanzo", "bot"); got != "hanzo-bot" {
		t.Fatalf("a bare agent must be prefixed, got %q", got)
	}
	if got := canonical("hanzo", "hanzo-bot"); got != "hanzo-bot" {
		t.Fatalf("an already-canonical name is kept, got %q", got)
	}
	for _, bad := range []string{"", "bad--name", "-bad", "bad-", "a b"} {
		if canonical("hanzo", bad) != "" {
			t.Fatalf("malformed name %q must be refused", bad)
		}
	}
}

// cancelled is a context already cancelled, so a ctx-bound write (CreateCtx/
// UpdateCtx) fails while mint's non-ctx key lookup still answers — the one seam
// that reaches mint's own write-error branches without a torn-down store.
func cancelled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// mint's three store faults each surface as an error and never a half-issued
// credential: the schema.Key row IS the security record, so a store that cannot
// answer the lookup, the rotate-update, or the first-create must fail loudly
// rather than hand back a secret that resolves to nothing.
func TestMint_StoreErrors(t *testing.T) {
	seed := func(db orm.DB) *schema.User {
		sa := orm.New[schema.User](db)
		sa.Owner, sa.Name, sa.Type = "hanzo", "hanzo-bot", serviceAccount
		sa.SetId("hanzo/hanzo-bot")
		if err := sa.CreateCtx(context.Background()); err != nil {
			t.Fatalf("seed account: %v", err)
		}
		return sa
	}
	t.Run("lookup fault", func(t *testing.T) {
		db := memDB(t)
		sa := seed(db)
		db.Close() // the key lookup is a non-ctx query, so a closed store is what fails it
		if k, s, err := mint(context.Background(), db, sa); err == nil {
			t.Fatalf("a closed store must fail the key lookup, got key=%q secret=%q", k, s)
		}
	})
	t.Run("first-create fault", func(t *testing.T) {
		db := memDB(t)
		sa := seed(db)
		// No existing key: the lookup answers not-found, so the dead context is
		// what the first key's CreateCtx fails on.
		if _, _, err := mint(cancelled(), db, sa); err == nil {
			t.Fatal("a dead context must fail the first key create")
		}
	})
	t.Run("rotate-update fault", func(t *testing.T) {
		db := memDB(t)
		sa := seed(db)
		if _, _, err := mint(context.Background(), db, sa); err != nil {
			t.Fatalf("seed key: %v", err) // an existing key, so the next mint takes the update path
		}
		if _, _, err := mint(cancelled(), db, sa); err == nil {
			t.Fatal("a dead context must fail the rotate update")
		}
	})
}

// find resolves one principal by (owner,name): a present row, a clean (nil,nil)
// miss the callers turn into "create it" or a 404, and a store fault surfaced as
// an error rather than mistaken for absence.
func TestFind(t *testing.T) {
	ctx, db := context.Background(), memDB(t)
	sa := orm.New[schema.User](db)
	sa.Owner, sa.Name, sa.Type = "hanzo", "hanzo-bot", serviceAccount
	sa.SetId("hanzo/hanzo-bot")
	if err := sa.CreateCtx(ctx); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if got, err := find(ctx, db, "hanzo", "hanzo-bot"); err != nil || got == nil {
		t.Fatalf("find present = %v, %v; want the row", got, err)
	}
	if got, err := find(ctx, db, "hanzo", "ghost"); err != nil || got != nil {
		t.Fatalf("find absent = %v, %v; want nil, nil", got, err)
	}
	db.Close()
	if _, err := find(ctx, db, "hanzo", "hanzo-bot"); err == nil {
		t.Fatal("a closed store must surface as an error, never a silent miss")
	}
}

// paginate returns the 1-indexed page clamped to the slice, and the whole slice
// when either paging value is unset — v1's contract for a caller that pages and
// one that does not.
func TestPaginate(t *testing.T) {
	all := make([]*schema.User, 5)
	for i := range all {
		all[i] = &schema.User{}
	}
	for _, c := range []struct {
		name       string
		page, size int
		wantLen    int
	}{
		{"no paging returns all", 0, 0, 5},
		{"page zero returns all", 0, 3, 5},
		{"size zero returns all", 2, 0, 5},
		{"first page", 1, 2, 2},
		{"last partial page", 3, 2, 1},
		{"page past the end is empty", 9, 2, 0},
		{"size past the end clamps to the tail", 1, 99, 5},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := len(paginate(all, c.page, c.size)); got != c.wantLen {
				t.Fatalf("paginate(_, %d, %d) len = %d, want %d", c.page, c.size, got, c.wantLen)
			}
		})
	}
}

// orgFromBody reads the organization out of a JSON body and answers "" for
// anything it cannot — an absent body, a non-object, an object without the field,
// malformed bytes — because the caller is then simply one that named no
// organization, which load already refuses.
func TestOrgFromBody(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"empty body", "", ""},
		{"well-formed", `{"organization":"hanzo"}`, "hanzo"},
		{"object without the field", `{"name":"bot"}`, ""},
		{"not an object", `["hanzo"]`, ""},
		{"malformed json", `not json`, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := orgFromBody([]byte(c.body)); got != c.want {
				t.Fatalf("orgFromBody(%q) = %q, want %q", c.body, got, c.want)
			}
		})
	}
}

// read fails closed on a nil principal or an empty org before it consults any
// capability — the same guard admin applies, so the gate is never reached with
// nothing to decide on.
func TestReadGate_NilAndEmpty(t *testing.T) {
	if read(nil, "hanzo") {
		t.Fatal("a nil principal may read nothing")
	}
	if read(&authz.Principal{Sudo: true}, "") {
		t.Fatal("an empty org names no tenant to read")
	}
}

// canonical re-checks the length bound AFTER binding: prefixing a legal agent
// segment with "<org>-" can push the STORED handle past what a username allows,
// and the bound name is what gets persisted, so it is what must fit.
func TestCanonical_BindPastLengthIsRefused(t *testing.T) {
	agent := strings.Repeat("a", 60) // legal alone (<=63), 66 once "hanzo-" is prepended
	if _, err := schema.Username(agent); err != nil {
		t.Fatalf("the agent segment must be legal on its own for this test to prove the bind check: %v", err)
	}
	if got := canonical("hanzo", agent); got != "" {
		t.Fatalf("a name that only overflows after binding must be refused, got %q", got)
	}
}
