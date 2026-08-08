// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package otp

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A delivered code is a CREDENTIAL — a first factor at sign-in and a second factor
// at the gate — and these are the properties that make six digits strong enough to
// be one: it stands for exactly one account in exactly one tenant, it is spent
// exactly once no matter how many submissions race, and there is never more than
// one of it outstanding per address.

// file persists a code directly, so a test can state the exact record shape the
// spend path is being asked about (an issue always delivers, and delivery is what
// tells a test the code).
func file(t *testing.T, db orm.DB, owner, receiver, user, code string, now time.Time) *schema.VerificationRecord {
	t.Helper()
	ctx := context.Background()
	id, err := newID()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.AddVerificationRecord(ctx, db, &schema.VerificationRecord{
		Owner: owner, Name: id, CreatedTime: now.UTC().Format(time.RFC3339),
		Type: Channel(receiver), Receiver: Receiver(receiver), Code: code,
		User: user, Time: now.Unix(),
	}); err != nil {
		t.Fatalf("file a code: %v", err)
	}
	rec, err := store.GetLatestVerificationRecord(ctx, db, owner, Receiver(receiver))
	if err != nil || rec == nil {
		t.Fatalf("re-read the filed code: %v", err)
	}
	return rec
}

// The code stands for the account it was minted FOR, not for whoever the request
// says it stands for.
//
// The record has always stamped the resolved account and nothing ever read it, so
// the code was keyed on an ADDRESS — and an address is not an identity here.
// Sign-in resolves an identifier NAME first, so org hanzo holding both `hanzo/z`
// (email z@hanzo.ai) and `hanzo/z@hanzo.ai` gives two rows that one address
// reaches: the code was minted for one and would have signed in the other.
func TestCodeIsBoundToTheAccountItWasMintedFor(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Now()
	mine := account(t, db, "hanzo", "z", "z@hanzo.ai", "")
	other := account(t, db, "hanzo", "z@hanzo.ai", "z@hanzo.ai", "")

	file(t, db, "hanzo", "z@hanzo.ai", "hanzo/z", "424242", now)

	if ok, err := Consume(ctx, db, other, "z@hanzo.ai", "424242", now); err != nil || ok {
		t.Fatalf("a code minted for hanzo/z was accepted for %s: ok=%v err=%v", other.Name, ok, err)
	}
	// The account it WAS minted for still spends it — the binding refuses the wrong
	// account, it does not break the right one.
	if ok, err := Consume(ctx, db, mine, "z@hanzo.ai", "424242", now); err != nil || !ok {
		t.Fatalf("the account the code was minted for must spend it: ok=%v err=%v", ok, err)
	}
}

// An unattributed record was filed for an address with no account — the signup
// gate's case. It proves an address, and it is a credential for nobody.
func TestUnattributedCodeSignsNobodyIn(t *testing.T) {
	db := openDB(t)
	now := time.Now()
	late := account(t, db, "hanzo", "late", "late@hanzo.ai", "")
	file(t, db, "hanzo", "late@hanzo.ai", "", "424242", now)

	if ok, err := Consume(context.Background(), db, late, "late@hanzo.ai", "424242", now); err != nil || ok {
		t.Fatalf("a code filed before the account existed was accepted: ok=%v err=%v", ok, err)
	}
}

// One address, two organizations, two accounts — and the lookup answers "the latest
// live code for this receiver".
//
// Unscoped, that question spans tenants: a newer record filed in the other org wins
// the ordering, so the person's OWN live code is not even the row the compare runs
// against and their sign-in fails while a code sits in their inbox. Scoping by owner
// is what makes the two orgs' codes independent; the account binding then refuses
// the foreign row on top of it.
func TestCodeDoesNotCrossOrganizations(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	start := time.Unix(1_800_000_000, 0)
	victim := account(t, db, "hanzo", "alice", "alice@example.com", "")
	account(t, db, "elsewhere", "alice", "alice@example.com", "")

	file(t, db, "hanzo", "alice@example.com", "hanzo/alice", "111111", start)
	// Filed LATER in `elsewhere`, where somebody else holds the same address.
	file(t, db, "elsewhere", "alice@example.com", "elsewhere/alice", "424242", start.Add(time.Minute))

	if ok, err := Consume(ctx, db, victim, "alice@example.com", "424242", start); err != nil || ok {
		t.Fatalf("the other org's code was accepted for hanzo/alice: ok=%v err=%v", ok, err)
	}
	if ok, err := Consume(ctx, db, victim, "alice@example.com", "111111", start); err != nil || !ok {
		t.Fatalf("her own live code did not resolve: ok=%v err=%v", ok, err)
	}
}

// The five-guess bound must hold under parallelism, or it is not a bound.
//
// Read → compare → bump → write is the lost-update class internal/users/lockout.go
// documents: every concurrent guess captured the same pre-increment snapshot, so
// measured, 16 simultaneous wrong codes advanced the counter by 3 and left the real
// code live. A six-digit secret is only a credential because the count is what
// shrinks a million guesses to five.
func TestWrongGuessesAreCountedAtomically(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Now()
	ada := account(t, db, "hanzo", "ada", "ada@example.com", "")
	rec := file(t, db, "hanzo", "ada@example.com", "hanzo/ada", "424242", now)

	const guesses = 16
	var wg sync.WaitGroup
	for i := 0; i < guesses; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = Consume(ctx, db, ada, "ada@example.com", "000000", now)
		}()
	}
	wg.Wait()

	after, err := orm.Get[schema.VerificationRecord](db, rec.Key().Encode())
	if err != nil {
		t.Fatalf("re-read the record: %v", err)
	}
	if after.Attempts < MaxAttempts {
		t.Errorf("attempts = %d after %d concurrent wrong guesses, want >= %d: a counter that "+
			"loses updates is not a bound", after.Attempts, guesses, MaxAttempts)
	}
	if !after.IsUsed {
		t.Error("the record survived the attempt bound — the run can continue")
	}
	if ok, _ := Consume(ctx, db, ada, "ada@example.com", "424242", now); ok {
		t.Error("the real code still verified after the attempt bound was exhausted")
	}
}

// Two racing CORRECT submissions spend one code once. The row lock is held from the
// read through the IsUsed write, so the loser reads it spent rather than observing
// the same unused row.
func TestOneCodeIsSpentOnce(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	now := time.Now()
	ada := account(t, db, "hanzo", "ada", "ada@example.com", "")
	file(t, db, "hanzo", "ada@example.com", "hanzo/ada", "424242", now)

	const racers = 8
	accepted := make(chan bool, racers)
	var wg sync.WaitGroup
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, _ := Consume(ctx, db, ada, "ada@example.com", "424242", now)
			accepted <- ok
		}()
	}
	wg.Wait()
	close(accepted)

	wins := 0
	for ok := range accepted {
		if ok {
			wins++
		}
	}
	if wins != 1 {
		t.Errorf("%d of %d racing submissions spent one code, want exactly 1", wins, racers)
	}
}

// A reissue is a deliberate replacement, never a race.
//
// Two issues used to leave two redeemable records ordered by a UNIX SECOND, so a
// double-click made "the latest code" a coin flip: the one the person is holding may
// be the one that no longer resolves, and a wrong guess is charged to whichever row
// won the tie. Anyone who knew an address could do that on purpose, unthrottled,
// spending the org's carrier budget each time on SMS.
func TestOnlyTheNewestCodeForAnAddressIsRedeemable(t *testing.T) {
	db := openDB(t)
	ctx := context.Background()
	r := &recorder{}
	bind(t, r)
	start := time.Unix(1_800_000_000, 0)
	ada := account(t, db, "hanzo", "ada", "ada@example.com", "")

	if err := Issue(ctx, db, "hanzo", "ada@example.com", "", ada, start); err != nil {
		t.Fatalf("first issue: %v", err)
	}
	first, _ := store.GetLatestVerificationRecord(ctx, db, "hanzo", "ada@example.com")
	if first == nil {
		t.Fatal("the first issue filed nothing")
	}

	// Inside the window: refused, and the code already in flight survives.
	if err := Issue(ctx, db, "hanzo", "ada@example.com", "", ada, start.Add(time.Second)); err != ErrTooSoon {
		t.Fatalf("an immediate reissue = %v, want ErrTooSoon", err)
	}
	if again, _ := store.GetLatestVerificationRecord(ctx, db, "hanzo", "ada@example.com"); again == nil || again.Code != first.Code {
		t.Fatal("a refused reissue must leave the outstanding code alone")
	}

	// Past the window: a real replacement. Exactly one code is redeemable, and it is
	// the new one — so there is no tie to break.
	later := start.Add(ResendInterval + time.Second)
	if err := Issue(ctx, db, "hanzo", "ada@example.com", "", ada, later); err != nil {
		t.Fatalf("reissue after the window: %v", err)
	}
	second, _ := store.GetLatestVerificationRecord(ctx, db, "hanzo", "ada@example.com")
	if second == nil || second.Code == first.Code {
		t.Fatal("the reissue did not mint a new code")
	}
	if ok, _ := Consume(ctx, db, ada, "ada@example.com", first.Code, later); ok {
		t.Error("the retired code still verified — two live codes for one address")
	}
	if ok, err := Consume(ctx, db, ada, "ada@example.com", second.Code, later); err != nil || !ok {
		t.Fatalf("the code actually delivered must verify: ok=%v err=%v", ok, err)
	}
}
