// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// seedUser inserts a user (owner, name) so provision has a caller to move. Mirrors
// the (owner/name) storage-id convention the bootstrap upsert uses.
func seedUserIn(t *testing.T, db orm.DB, owner, name, email string) {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name = owner, name
	u.Email = email
	u.EmailVerified = true
	u.Type = "normal-user"
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user %s/%s: %v", owner, name, err)
	}
}

// countKeys / countOrgs report how many rows an owner/name owns — used to prove a
// retry converges to exactly ONE, never a duplicate.
func countKeys(t *testing.T, db orm.DB, owner string) int {
	t.Helper()
	ks, err := orm.TypedQuery[schema.User](db).Filter("Owner=", owner).Filter("Type=", "service-account").GetAll(context.Background())
	if err != nil {
		t.Fatalf("count keys: %v", err)
	}
	return len(ks)
}

func countOrgs(t *testing.T, db orm.DB, name string) int {
	t.Helper()
	os, err := orm.TypedQuery[schema.Organization](db).Filter("Name=", name).GetAll(context.Background())
	if err != nil {
		t.Fatalf("count orgs: %v", err)
	}
	return len(os)
}

// ── fault injection ──────────────────────────────────────────────────────────
// faultyDB wraps an orm.DB and fails the Nth Put inside the NEXT transaction, so a
// test can prove provision() is ATOMIC: a fault at any step (org create, user move,
// key mint) must roll the WHOLE converge back — no org, no moved user, no key left
// behind — so a retry re-drives cleanly to ONE correct end state.

type faultyDB struct {
	orm.DB
	failOnPut int // 1-based Put ordinal to fail; 0 = never
	puts      int // Puts seen so far this run
}

// trip advances the Put counter and returns the injected fault when this is the
// configured ordinal. Shared so a fault fires whether provision writes through a
// real transaction (faultyTx, the SQLite path) or directly against the db (the
// autocommit path, where RunInTransaction does not wrap the writes).
func (f *faultyDB) trip(key orm.Key) error {
	f.puts++
	if f.failOnPut != 0 && f.puts == f.failOnPut {
		return fmt.Errorf("injected fault at put #%d (kind=%s)", f.puts, key.Kind())
	}
	return nil
}

func (f *faultyDB) Put(ctx context.Context, key orm.Key, src interface{}) (orm.Key, error) {
	if err := f.trip(key); err != nil {
		return nil, err
	}
	return f.DB.Put(ctx, key, src)
}

func (f *faultyDB) RunInTransactionWith(ctx context.Context, opts *orm.TxOptions, fn func(tx orm.DB) error) error {
	return f.DB.RunInTransactionWith(ctx, opts, func(tx orm.DB) error {
		return fn(&faultyTx{DB: tx, f: f})
	})
}

type faultyTx struct {
	orm.DB
	f *faultyDB
}

func (t *faultyTx) Put(ctx context.Context, key orm.Key, src interface{}) (orm.Key, error) {
	if err := t.f.trip(key); err != nil {
		return nil, err
	}
	return t.DB.Put(ctx, key, src)
}

// ── tests ────────────────────────────────────────────────────────────────────

// TestProvision_PersonalHappyPath: one signup converges to a personal org, the user
// as its admin, and a metered org-scoped key with a one-time secret.
func TestProvision_PersonalHappyPath(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, db, "landing", "dave", "dave@example.com")

	out, err := provision(ctx, db, claim{owner: "landing", name: "dave", slug: "dave", display: "Dave", personal: true})
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if out.org != "dave" || !out.orgCreated || !out.keyCreated {
		t.Fatalf("unexpected result: %+v", out)
	}
	if out.accessKey == "" || out.accessSecret == "" {
		t.Fatalf("first mint must reveal pk+sk, got %+v", out)
	}

	org, err := store.GetOrganizationByName(ctx, db, "dave")
	if err != nil || org == nil || !org.IsPersonal {
		t.Fatalf("org row: %+v err=%v", org, err)
	}
	// User is now admin of its OWN org, resolvable under the new natural key.
	moved, err := store.GetUserByName(ctx, db, "dave", "dave")
	if err != nil || moved == nil {
		t.Fatalf("user not resolvable at dave/dave: %v", err)
	}
	if moved.Owner != "dave" || !moved.IsAdmin {
		t.Fatalf("user is not admin of its own org: %+v", moved)
	}
	// Stale landing identity is gone.
	if stale, _ := store.GetUserByName(ctx, db, "landing", "dave"); stale != nil {
		t.Fatalf("stale identity landing/dave still present")
	}
	// Credential is a hashed, org-scoped (metered) service account — no plaintext at rest.
	sa, err := store.GetUserByName(ctx, db, "dave", "dave-default")
	if err != nil || sa == nil || sa.Type != "service-account" {
		t.Fatalf("credential not an org service account: %+v err=%v", sa, err)
	}
	if sa.Owner != "dave" {
		t.Fatalf("credential not org-scoped (metered): owner=%q", sa.Owner)
	}
	if sa.AccessKey != out.accessKey {
		t.Fatalf("returned accessKey %q != stored %q", out.accessKey, sa.AccessKey)
	}
	if sa.AccessSecret != "" {
		t.Fatalf("secret must NOT be stored plaintext at rest, got %q", sa.AccessSecret)
	}
	if sa.AccessSecretHash == "" {
		t.Fatalf("credential secret must be hashed (argon2id) at rest")
	}
	if out.accessSecret == "" {
		t.Fatalf("first mint must reveal the plaintext secret once")
	}
}

// TestProvision_Idempotent: re-driving the SAME signup converges to ONE org + ONE
// user + ONE key, and the secret is revealed only on the first mint.
func TestProvision_Idempotent(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, db, "landing", "dave", "dave@example.com")

	first, err := provision(ctx, db, claim{owner: "landing", name: "dave", slug: "dave", display: "Dave", personal: true})
	if err != nil {
		t.Fatalf("first provision: %v", err)
	}

	// Second call resolves the caller under its NEW identity (owner==name==dave),
	// exactly as callerOf would after the re-key.
	second, err := provision(ctx, db, claim{owner: "dave", name: "dave", slug: "dave", display: "Dave", personal: true})
	if err != nil {
		t.Fatalf("second provision (replay): %v", err)
	}

	if second.orgCreated || second.keyCreated {
		t.Fatalf("replay must create nothing, got %+v", second)
	}
	if second.accessKey != first.accessKey {
		t.Fatalf("replay returned a different key: %q != %q", second.accessKey, first.accessKey)
	}
	if second.accessSecret != "" {
		t.Fatalf("replay must NOT re-reveal the secret, got %q", second.accessSecret)
	}
	if n := countOrgs(t, db, "dave"); n != 1 {
		t.Fatalf("want exactly 1 org, got %d", n)
	}
	if n := countKeys(t, db, "dave"); n != 1 {
		t.Fatalf("want exactly 1 key, got %d", n)
	}
}

// TestProvision_AtomicRollbackAndRedrive: inject a failure at EACH step; every one
// must leave the store untouched (no org, no moved user, no key), and a clean
// re-drive must then converge to exactly ONE correct tenant.
func TestProvision_AtomicRollbackAndRedrive(t *testing.T) {
	for _, tc := range []struct {
		name string
		step int // 1=org create, 2=user move, 3=key mint
	}{
		{"fail at org create", 1},
		{"fail at user move", 2},
		{"fail at key mint", 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			real := openTestDB(t)
			ctx := context.Background()
			seedUserIn(t, real, "landing", "dave", "dave@example.com")

			// Inject the fault.
			fdb := &faultyDB{DB: real, failOnPut: tc.step}
			cl := claim{owner: "landing", name: "dave", slug: "dave", display: "Dave", personal: true}
			if _, err := provision(ctx, fdb, cl); err == nil {
				t.Fatalf("step %d: expected provision to fail", tc.step)
			}

			// Nothing persisted — full rollback.
			if org, _ := store.GetOrganizationByName(ctx, real, "dave"); org != nil {
				t.Fatalf("step %d: org leaked after rollback", tc.step)
			}
			if moved, _ := store.GetUserByName(ctx, real, "dave", "dave"); moved != nil {
				t.Fatalf("step %d: user move leaked after rollback", tc.step)
			}
			if landing, _ := store.GetUserByName(ctx, real, "landing", "dave"); landing == nil || landing.Owner != "landing" {
				t.Fatalf("step %d: caller not left intact in landing org", tc.step)
			}
			if n := countKeys(t, real, "dave"); n != 0 {
				t.Fatalf("step %d: %d key(s) leaked after rollback", tc.step, n)
			}

			// Re-drive on the clean db → exactly one correct tenant.
			out, err := provision(ctx, real, cl)
			if err != nil {
				t.Fatalf("step %d: re-drive failed: %v", tc.step, err)
			}
			if !out.orgCreated || !out.keyCreated || out.accessSecret == "" {
				t.Fatalf("step %d: re-drive did not freshly provision: %+v", tc.step, out)
			}
			if n := countOrgs(t, real, "dave"); n != 1 {
				t.Fatalf("step %d: want 1 org after re-drive, got %d", tc.step, n)
			}
			if n := countKeys(t, real, "dave"); n != 1 {
				t.Fatalf("step %d: want 1 key after re-drive, got %d", tc.step, n)
			}
			if moved, _ := store.GetUserByName(ctx, real, "dave", "dave"); moved == nil || !moved.IsAdmin {
				t.Fatalf("step %d: user not admin of own org after re-drive", tc.step)
			}
		})
	}
}

// TestProvision_TenantIsolation: a second identity can NOT claim, join, or hijack an
// org another identity already founded — it is refused, and the first tenant's key
// stays sole.
func TestProvision_TenantIsolation(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, db, "landing", "alice", "alice@example.com")
	seedUserIn(t, db, "landing", "mallory", "mallory@example.com")

	if _, err := provision(ctx, db, claim{owner: "landing", name: "alice", slug: "acme", display: "Acme", personal: false}); err != nil {
		t.Fatalf("alice provision: %v", err)
	}

	// Mallory tries to claim acme.
	_, err := provision(ctx, db, claim{owner: "landing", name: "mallory", slug: "acme", display: "Acme", personal: false})
	if err == nil {
		t.Fatalf("mallory must not claim alice's org")
	}
	ft, ok := err.(*fault)
	if !ok || ft.status != 409 {
		t.Fatalf("want 409 conflict, got %v", err)
	}
	// Mallory was NOT moved into acme; acme still has exactly Alice's key.
	if m, _ := store.GetUserByName(ctx, db, "acme", "mallory"); m != nil {
		t.Fatalf("mallory leaked into acme")
	}
	if still, _ := store.GetUserByName(ctx, db, "landing", "mallory"); still == nil {
		t.Fatalf("mallory should remain in landing org")
	}
	if n := countKeys(t, db, "acme"); n != 1 {
		t.Fatalf("acme must have exactly 1 key, got %d", n)
	}
}

// TestProvision_ReservedRejected: a self-service tenant can never be provisioned
// into a reserved system org — above all the SuperAdmin `admin` org (provision, do
// not promote). Enforced in the primitive itself, before any write.
func TestProvision_ReservedRejected(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, db, "landing", "eve", "eve@example.com")

	for _, slug := range []string{"admin", "built-in", "app"} {
		_, err := provision(ctx, db, claim{owner: "landing", name: "eve", slug: slug, display: slug, personal: false})
		ft, ok := err.(*fault)
		if !ok || ft.status != 400 {
			t.Fatalf("slug %q: want 400 reserved, got %v", slug, err)
		}
		// Eve was not promoted into the reserved org.
		if e, _ := store.GetUserByName(ctx, db, slug, "eve"); e != nil {
			t.Fatalf("eve promoted into reserved org %q", slug)
		}
	}
	// Crucially, the real admin org membership is untouched.
	if e, _ := store.GetUserByName(ctx, db, "admin", "eve"); e != nil {
		t.Fatalf("eve leaked into the SuperAdmin admin org")
	}
}

// ── autocommit (ZAP-contract) emulation ──────────────────────────────────────
// The production `sql`/`datastore` backend autocommits every write independently —
// its RunInTransaction opens NO transaction, so a fault mid-provision does NOT roll
// back. autocommitDB emulates that contract over the SQLite store: RunInTransaction*
// runs fn directly (each Put/Get autocommits, no rollback), so a test can prove
// provision converges on the backend production actually runs, not just on SQLite's
// serialized transaction. Composed with faultyDB it proves the Founder RESUME path:
// a fault after the org write leaves the org committed, and a retry completes it.

type autocommitDB struct{ orm.DB }

func (a *autocommitDB) RunInTransactionWith(ctx context.Context, _ *orm.TxOptions, fn func(tx orm.DB) error) error {
	return fn(a.DB)
}
func (a *autocommitDB) RunInTransaction(ctx context.Context, fn func(tx orm.DB) error) error {
	return fn(a.DB)
}

// TestProvision_ResumeUnderAutocommit: with NO transaction rollback (production
// contract), a fault after the org is written leaves it committed and the caller not
// yet moved. A retry must RESUME via the Founder stamp — complete the move — instead
// of the permanent "already exists" 409 that stranded the original bug. This is the
// backend production runs, proven without a live ZAP server.
func TestProvision_ResumeUnderAutocommit(t *testing.T) {
	real := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, real, "landing", "dave", "dave@example.com")
	cl := claim{owner: "landing", name: "dave", slug: "dave", display: "Dave", personal: true}

	// Autocommit (no rollback) + fault at the user-move write (Put #2).
	faulty := &autocommitDB{DB: &faultyDB{DB: real, failOnPut: 2}}
	if _, err := provision(ctx, faulty, cl); err == nil {
		t.Fatalf("expected the injected fault to fail provision")
	}
	// Under autocommit the org is NOT rolled back — it persists, founder-stamped,
	// with the caller NOT yet moved (the exact orphan state that stranded on 409).
	org, _ := store.GetOrganizationByName(ctx, real, "dave")
	if org == nil {
		t.Fatalf("autocommit should have left the org committed")
	}
	if moved, _ := store.GetUserByName(ctx, real, "dave", "dave"); moved != nil {
		t.Fatalf("user should NOT have been moved before the fault")
	}

	// Retry on the same autocommit backend → RESUME (not 409), converging to one
	// org + admin + key.
	out, err := provision(ctx, &autocommitDB{DB: real}, cl)
	if err != nil {
		t.Fatalf("retry must RESUME the founder's own org, got: %v", err)
	}
	if out.orgCreated {
		t.Fatalf("retry should have found the existing org, not recreated it")
	}
	if moved, _ := store.GetUserByName(ctx, real, "dave", "dave"); moved == nil || !moved.IsAdmin {
		t.Fatalf("retry did not move the caller in as admin")
	}
	if n := countOrgs(t, real, "dave"); n != 1 {
		t.Fatalf("want exactly 1 org after resume, got %d", n)
	}
	if n := countKeys(t, real, "dave"); n != 1 {
		t.Fatalf("want exactly 1 key after resume, got %d", n)
	}
}

// TestProvision_FounderFencesResume: a DIFFERENT identity can never complete an org
// another identity founded — even under autocommit, where the org may sit
// half-provisioned. The Founder stamp fences it to one tenant.
func TestProvision_FounderFencesResume(t *testing.T) {
	real := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, real, "landing", "alice", "alice@example.com")
	seedUserIn(t, real, "landing", "mallory", "mallory@example.com")

	// Alice's onboard faults after the org write (autocommit → org persists, founder=alice).
	faulty := &autocommitDB{DB: &faultyDB{DB: real, failOnPut: 2}}
	if _, err := provision(ctx, faulty, claim{owner: "landing", name: "alice", slug: "acme", display: "Acme"}); err == nil {
		t.Fatalf("expected Alice's provision to fault")
	}
	if org, _ := store.GetOrganizationByName(ctx, real, "acme"); org == nil {
		t.Fatalf("acme should be half-provisioned (autocommit)")
	}

	// Mallory tries to complete/claim Alice's half-provisioned org → refused.
	_, err := provision(ctx, &autocommitDB{DB: real}, claim{owner: "landing", name: "mallory", slug: "acme", display: "Acme"})
	if ft, ok := err.(*fault); !ok || ft.status != 409 {
		t.Fatalf("mallory must be refused (409) on Alice's founded org, got %v", err)
	}
	if m, _ := store.GetUserByName(ctx, real, "acme", "mallory"); m != nil {
		t.Fatalf("mallory leaked into Alice's org")
	}

	// Alice retries → resumes her own org.
	if _, err := provision(ctx, &autocommitDB{DB: real}, claim{owner: "landing", name: "alice", slug: "acme", display: "Acme"}); err != nil {
		t.Fatalf("alice must resume her own org, got %v", err)
	}
	if a, _ := store.GetUserByName(ctx, real, "acme", "alice"); a == nil || !a.IsAdmin {
		t.Fatalf("alice did not become admin of her resumed org")
	}
}

// TestProvision_SecondOrgRefused: once an identity admins its OWN org, founding a
// SECOND via onboarding is refused — a move would orphan the first (its billing
// account + metered key left ownerless).
func TestProvision_SecondOrgRefused(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, db, "landing", "dave", "dave@example.com")

	if _, err := provision(ctx, db, claim{owner: "landing", name: "dave", slug: "dave", display: "Dave", personal: true}); err != nil {
		t.Fatalf("first onboard: %v", err)
	}
	// Now admin of "dave"; founding "daveteam" must be refused.
	_, err := provision(ctx, db, claim{owner: "dave", name: "dave", slug: "daveteam", display: "Dave Team"})
	if ft, ok := err.(*fault); !ok || ft.status != 409 {
		t.Fatalf("founding a second org must be refused 409, got %v", err)
	}
	if n := countOrgs(t, db, "daveteam"); n != 0 {
		t.Fatalf("the refused second org must NOT be created, got %d", n)
	}
	// The first org is intact and still admined.
	if a, _ := store.GetUserByName(ctx, db, "dave", "dave"); a == nil || !a.IsAdmin {
		t.Fatalf("first org's admin was disturbed")
	}
}

// TestProvision_StaleCredentialReplay: a retry carrying the PRE-move credential
// (owner still the landing org, because the client has not re-authenticated yet)
// still converges — the caller is re-resolved under the target slug.
func TestProvision_StaleCredentialReplay(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, db, "landing", "dave", "dave@example.com")

	if _, err := provision(ctx, db, claim{owner: "landing", name: "dave", slug: "dave", display: "Dave", personal: true}); err != nil {
		t.Fatalf("first onboard: %v", err)
	}
	// Replay with the STALE pre-move owner ("landing") — dave now lives in "dave".
	out, err := provision(ctx, db, claim{owner: "landing", name: "dave", slug: "dave", display: "Dave", personal: true})
	if err != nil {
		t.Fatalf("stale-credential replay must converge, got %v", err)
	}
	if out.orgCreated {
		t.Fatalf("replay must not recreate the org")
	}
	if n := countOrgs(t, db, "dave"); n != 1 {
		t.Fatalf("want exactly 1 org, got %d", n)
	}
}

// TestProvision_ConcurrentSameSlugOneWinner: N distinct callers race for the SAME
// org name. Exactly ONE wins the tenant; the rest are refused. The store converges
// to ONE org + ONE key — no duplicate billing account, no orphan — under real
// contention (run with -race).
func TestProvision_ConcurrentSameSlugOneWinner(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	const n = 6
	for i := 0; i < n; i++ {
		seedUserIn(t, db, "landing", fmt.Sprintf("u%d", i), fmt.Sprintf("u%d@example.com", i))
	}

	var wg sync.WaitGroup
	var success int64
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, err := provision(ctx, db, claim{owner: "landing", name: fmt.Sprintf("u%d", i), slug: "team", display: "Team", personal: false}); err == nil {
				atomic.AddInt64(&success, 1)
			}
		}(i)
	}
	wg.Wait()

	if success != 1 {
		t.Fatalf("want exactly 1 winner, got %d", success)
	}
	if c := countOrgs(t, db, "team"); c != 1 {
		t.Fatalf("want exactly 1 org, got %d", c)
	}
	if c := countKeys(t, db, "team"); c != 1 {
		t.Fatalf("want exactly 1 key, got %d", c)
	}
}

// TestProvision_ConcurrentSameCallerConverges: the SAME caller double-submits N
// times at once (a console retry storm). The store converges to exactly ONE org,
// ONE key, and ONE admin — never a duplicate or an orphan.
func TestProvision_ConcurrentSameCallerConverges(t *testing.T) {
	db := openTestDB(t)
	ctx := context.Background()
	seedUserIn(t, db, "landing", "dave", "dave@example.com")

	var wg sync.WaitGroup
	const n = 6
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = provision(ctx, db, claim{owner: "landing", name: "dave", slug: "dave", display: "Dave", personal: true})
		}()
	}
	wg.Wait()

	if c := countOrgs(t, db, "dave"); c != 1 {
		t.Fatalf("want exactly 1 org, got %d", c)
	}
	if c := countKeys(t, db, "dave"); c != 1 {
		t.Fatalf("want exactly 1 key, got %d", c)
	}
	admins := 0
	us, _ := orm.TypedQuery[schema.User](db).Filter("Owner=", "dave").GetAll(ctx)
	for _, u := range us {
		if u.IsAdmin {
			admins++
		}
	}
	if admins != 1 {
		t.Fatalf("want exactly 1 admin of dave, got %d", admins)
	}
}
