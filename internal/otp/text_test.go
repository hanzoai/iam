// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package otp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/keyring"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// signing seeds the platform signing cert the texting ledger's digests are keyed by.
func signing(t *testing.T, db orm.DB) {
	t.Helper()
	keyring.Set("cert-otp", "otp test key material")
	c := orm.New[schema.Cert](db)
	c.Owner, c.Name, c.CryptoAlgorithm = "admin", "cert-otp", "RS256"
	c.SetId("admin/cert-otp")
	if err := c.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed cert: %v", err)
	}
}

// texter takes texts handed over from another goroutine. With gate set, a send
// blocks until the gate is closed.
type texter struct {
	mu   sync.Mutex
	sent []Message
	gate chan struct{}
}

func (x *texter) Send(_ context.Context, m Message) error {
	if x.gate != nil {
		<-x.gate
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	x.sent = append(x.sent, m)
	return nil
}

func (x *texter) count() int {
	x.mu.Lock()
	defer x.mu.Unlock()
	return len(x.sent)
}

// await waits until n texts were handed over and returns them.
func (x *texter) await(t *testing.T, n int) []Message {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for x.count() < n {
		if time.Now().After(deadline) {
			t.Fatalf("%d text(s) handed over, want %d", x.count(), n)
		}
		time.Sleep(5 * time.Millisecond)
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	return slices.Clone(x.sent)
}

// texting is a store with a signing cert and a texter bound.
func texting(t *testing.T) (orm.DB, *texter) {
	t.Helper()
	db := openDB(t)
	signing(t, db)
	x := &texter{}
	bind(t, x)
	return db, x
}

// t0 is the fake clock's start.
var t0 = time.Unix(1_800_000_000, 0)

const app = "admin/hanzo-app"

// asked is an open request from client at the application.
func asked(client string) Ask { return Ask{App: app, Client: client} }

// number is the nth of a run of distinct valid US numbers.
func number(n int) string { return fmt.Sprintf("+1415555%04d", 100+n) }

// ledger is every row the budgets count.
func ledger(t *testing.T, db orm.DB) []*schema.Text {
	t.Helper()
	rows, err := orm.TypedQuery[schema.Text](db).GetAll(context.Background())
	if err != nil && !errors.Is(err, orm.ErrNotFound) {
		t.Fatal(err)
	}
	return rows
}

// seedLedger writes n rows straight into the ledger at at, in one transaction, for
// a bound whose limit is too high to reach by asking.
func seedLedger(t *testing.T, db orm.DB, n int, row schema.Text) {
	t.Helper()
	err := db.RunInTransaction(context.Background(), func(tx orm.DB) error {
		for i := 0; i < n; i++ {
			r := row
			r.Number = fmt.Sprintf("seed-%d", i)
			if err := enter(context.Background(), tx, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("seed the ledger: %v", err)
	}
}

// spent asserts err is the bound named, and returns it.
func spent(t *testing.T, err error, bound string) *Spent {
	t.Helper()
	var s *Spent
	if !errors.As(err, &s) || s.Bound != bound {
		t.Fatalf("err = %v, want the %q budget spent", err, bound)
	}
	if s.Retry <= 0 || s.Retry > s.Window {
		t.Fatalf("retry = %v, want within the %v window", s.Retry, s.Window)
	}
	return s
}

// Only a number a person can be texted at, in a country the deployment texts.
func TestTextable(t *testing.T) {
	for _, tc := range []struct {
		dest string
		ok   bool
	}{
		{"+1 (415) 555-0134", true}, // US
		{"+1 416 555 0134", true},   // Canada
		{"+44 7400 123456", true},   // UK mobile
		{"+33 6 12 34 56 78", true}, // France mobile
		{"+61 412 345 678", true},   // Australia mobile
		{"+1 787 555 0100", true},   // Puerto Rico
		{"+1 876 555 0100", false},  // Jamaica: +1, and not the US
		{"+1 809 555 0100", false},  // Dominican Republic
		{"+44 7781 123456", false},  // Guernsey: +44, and not the UK
		{"+1 900 555 0100", false},  // premium rate
		{"+44 901 234 5678", false}, // premium rate
		{"+1 800 555 0100", false},  // toll free
		{"+44 70 1111 1111", false}, // personal-number redirect
		{"+1 500 555 0001", false},  // personal number (the carrier's test range)
		{"+882 12345 6789", false},  // international network
		{"+1 555 000 1111", false},  // no such area code
		{"415-555-0134", false},     // national: names no country
		{"004415551234", false},     // a dialling prefix is not a country code
		{"ada@example.com", false},  // not a number
		{"+358 18 123 4567", false}, // a landline (Åland)
	} {
		err := Textable(tc.dest)
		if tc.ok && err != nil {
			t.Errorf("Textable(%q) = %v, want nil", tc.dest, err)
		}
		if !tc.ok && err != ErrRegion {
			t.Errorf("Textable(%q) = %v, want ErrRegion", tc.dest, err)
		}
	}
}

// The countries are configuration. A value that names something that is not a
// country keeps the default, so a typo never opens the world.
func TestRegionsAreConfig(t *testing.T) {
	const us, jm = "+14155550134", "+18765550100"
	for _, tc := range []struct {
		env    string
		us, jm bool
	}{
		{"", true, false},
		{"JM", false, true},
		{"jm, us", true, true},
		{"*", true, true},
		{"US,XX", true, false},
		{"everywhere", true, false},
	} {
		t.Setenv(EnvRegions, tc.env)
		if got := Textable(us) == nil; got != tc.us {
			t.Errorf("%s=%q: US textable = %v, want %v", EnvRegions, tc.env, got, tc.us)
		}
		if got := Textable(jm) == nil; got != tc.jm {
			t.Errorf("%s=%q: Jamaica textable = %v, want %v", EnvRegions, tc.env, got, tc.jm)
		}
	}
}

// A number is texted only for an account that holds it. A number nobody holds is
// charged the same, answered the same, and texted nothing: no code is minted for it.
func TestTextOnlyTextsAHolder(t *testing.T) {
	db, x := texting(t)
	ctx := context.Background()
	carol := account(t, db, "hanzo", "carol", "", "+14155550134")

	if err := Text(ctx, db, "hanzo", "+1 (415) 555-0134", asked("203.0.113.7"), carol, true, t0); err != nil {
		t.Fatalf("held: %v", err)
	}
	if err := Text(ctx, db, "hanzo", "+1 (415) 555-0199", asked("203.0.113.7"), nil, false, t0); err != nil {
		t.Fatalf("nobody: %v", err)
	}

	got := x.await(t, 1)
	if len(got) != 1 || got[0].To != "+14155550134" || got[0].Channel != Phone || got[0].Org != "hanzo" {
		t.Fatalf("texts = %+v, want one to the holder's number", got)
	}
	rec, _ := store.GetLatestVerificationRecord(ctx, db, "hanzo", "+14155550134")
	if rec == nil || rec.User != "hanzo/carol" || rec.Code != sixDigits.FindString(got[0].Body) {
		t.Fatalf("record = %+v, want the texted code bound to hanzo/carol", rec)
	}
	if rec, _ := store.GetLatestVerificationRecord(ctx, db, "hanzo", "+14155550199"); rec != nil {
		t.Fatalf("a code was minted for a number nobody holds: %+v", rec)
	}

	rows := ledger(t, db)
	if len(rows) != 2 {
		t.Fatalf("ledger rows = %d, want one per request", len(rows))
	}
	for _, r := range rows {
		if r.Owner != "hanzo" || r.Application != app || r.Factor || r.Time != t0.Unix() || r.Number == "" || r.Client == "" {
			t.Fatalf("row = %+v", r)
		}
	}
	if rows[0].Number == rows[1].Number || rows[0].Client != rows[1].Client {
		t.Fatal("two numbers share a digest, or one client has two")
	}
	if rows[0].Sent == rows[1].Sent {
		t.Fatal("the ledger does not say which request went out")
	}
}

// The ledger names no number and no address: only keyed digests.
func TestLedgerHoldsNoNumberOrAddress(t *testing.T) {
	db, _ := texting(t)
	carol := account(t, db, "hanzo", "carol", "", "+14155550134")
	if err := Text(context.Background(), db, "hanzo", "+14155550134", asked("203.0.113.7"), carol, true, t0); err != nil {
		t.Fatal(err)
	}
	if err := Text(context.Background(), db, "hanzo", "+14155550199", Ask{App: app, Client: "2001:db8::1"}, nil, false, t0); err != nil {
		t.Fatal(err)
	}
	for _, r := range ledger(t, db) {
		raw, _ := json.Marshal(r)
		for _, leak := range []string{"5550134", "5550199", "203.0.113", "2001:db8"} {
			if strings.Contains(string(raw), leak) {
				t.Fatalf("ledger row carries %q: %s", leak, raw)
			}
		}
	}
}

// A held number's text is handed to the carrier after the answer and not waited
// for: the carrier's round trip is the tell an answer would otherwise carry.
func TestTextDoesNotWaitForTheCarrier(t *testing.T) {
	db := openDB(t)
	signing(t, db)
	x := &texter{gate: make(chan struct{})}
	bind(t, x)
	carol := account(t, db, "hanzo", "carol", "", "+14155550134")

	answered := make(chan error, 1)
	go func() {
		answered <- Text(context.Background(), db, "hanzo", "+14155550134", asked("203.0.113.7"), carol, true, t0)
	}()
	select {
	case err := <-answered:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the answer waited for the carrier")
	}
	if x.count() != 0 {
		t.Fatal("premise: the carrier has not answered yet")
	}
	close(x.gate)
	x.await(t, 1)
}

// One number is asked for at most once a resend interval, read from the ledger, so
// a number nobody holds is paced exactly like a held one.
func TestTextPacesANumber(t *testing.T) {
	db, x := texting(t)
	ctx := context.Background()
	carol := account(t, db, "hanzo", "carol", "", "+14155550134")

	for _, tc := range []struct {
		name string
		dest string
		user *schema.User
		send bool
	}{
		{"held", "+14155550134", carol, true},
		{"nobody", "+14155550199", nil, false},
	} {
		if err := Text(ctx, db, "hanzo", tc.dest, asked("203.0.113.7"), tc.user, tc.send, t0); err != nil {
			t.Fatalf("%s: first: %v", tc.name, err)
		}
		// From another client, too: the number is what is paced.
		if err := Text(ctx, db, "hanzo", tc.dest, asked("198.51.100.9"), tc.user, tc.send, t0.Add(ResendInterval-time.Second)); err != ErrTooSoon {
			t.Fatalf("%s: inside the interval = %v, want ErrTooSoon", tc.name, err)
		}
		if err := Text(ctx, db, "hanzo", tc.dest, asked("203.0.113.7"), tc.user, tc.send, t0.Add(ResendInterval)); err != nil {
			t.Fatalf("%s: after the interval: %v", tc.name, err)
		}
	}
	if got := x.await(t, 2); len(got) != 2 {
		t.Fatalf("texts = %d, want the holder's two", len(got))
	}
}

// PerNumber open requests for one number in a day, then 429 until the oldest ages
// out.
func TestTextPerNumber(t *testing.T) {
	db, _ := texting(t)
	ctx := context.Background()
	at := t0
	for i := 0; i < PerNumber; i++ {
		// Each from a client of its own, so only the number's budget is spent.
		if err := Text(ctx, db, "hanzo", "+14155550199", asked(fmt.Sprintf("203.0.113.%d", i+1)), nil, false, at); err != nil {
			t.Fatalf("ask %d: %v", i+1, err)
		}
		at = at.Add(ResendInterval)
	}
	err := Text(ctx, db, "hanzo", "+14155550199", asked("198.51.100.9"), nil, false, at)
	s := spent(t, err, "number")
	if s.Limit != PerNumber || s.Window != 24*time.Hour {
		t.Fatalf("spent = %+v", s)
	}
	// The oldest ask was at t0, so the day admits one more at t0+24h.
	if want := t0.Add(24 * time.Hour).Sub(at); s.Retry != want {
		t.Fatalf("retry = %v, want %v", s.Retry, want)
	}
	if err := Text(ctx, db, "hanzo", "+14155550199", asked("198.51.100.9"), nil, false, at.Add(s.Retry-time.Second)); !errors.As(err, new(*Spent)) {
		t.Fatalf("a second early = %v, want still spent", err)
	}
	if err := Text(ctx, db, "hanzo", "+14155550199", asked("198.51.100.9"), nil, false, at.Add(s.Retry)); err != nil {
		t.Fatalf("after the retry: %v", err)
	}
	// Another number is untouched.
	if err := Text(ctx, db, "hanzo", "+14155550198", asked("198.51.100.9"), nil, false, at); err != nil {
		t.Fatalf("another number: %v", err)
	}
}

// PerClient texted codes from one client in an hour, whatever the numbers. An IPv6
// client is its /64; a request naming no address is one client with every other.
func TestTextPerClient(t *testing.T) {
	for _, tc := range []struct{ name, first, next, other string }{
		{"ipv4", "203.0.113.7", "203.0.113.7", "203.0.113.8"},
		{"ipv6 /64", "2001:db8:1:2::1", "2001:db8:1:2:ffff::9", "2001:db8:1:3::1"},
		{"no address", "", "", "203.0.113.7"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, _ := texting(t)
			ctx := context.Background()
			for i := 0; i < PerClient; i++ {
				c := tc.first
				if i%2 == 1 {
					c = tc.next
				}
				if err := Text(ctx, db, "hanzo", number(i), asked(c), nil, false, t0); err != nil {
					t.Fatalf("ask %d: %v", i+1, err)
				}
			}
			s := spent(t, Text(ctx, db, "hanzo", number(PerClient), asked(tc.next), nil, false, t0.Add(time.Minute)), "client")
			if s.Limit != PerClient || s.Window != time.Hour || s.Retry != time.Hour-time.Minute {
				t.Fatalf("spent = %+v", s)
			}
			if err := Text(ctx, db, "hanzo", number(PerClient), asked(tc.other), nil, false, t0.Add(time.Minute)); err != nil {
				t.Fatalf("another client: %v", err)
			}
			if err := Text(ctx, db, "hanzo", number(PerClient+1), asked(tc.first), nil, false, t0.Add(time.Hour)); err != nil {
				t.Fatalf("an hour later: %v", err)
			}
		})
	}
}

// PerApp texts that went out from one application in a day. Asks that texted
// nothing do not spend it, and another application is untouched.
func TestTextPerApp(t *testing.T) {
	db, _ := texting(t)
	ctx := context.Background()
	seedLedger(t, db, PerApp-1, schema.Text{Owner: "hanzo", Time: t0.Unix(), Application: app, Client: "seed", Sent: true})
	seedLedger(t, db, 50, schema.Text{Owner: "hanzo", Time: t0.Unix(), Application: app, Client: "seed", Sent: false})
	carol := account(t, db, "hanzo", "carol", "", "+14155550134")

	if err := Text(ctx, db, "hanzo", "+14155550134", asked("203.0.113.7"), carol, true, t0.Add(time.Hour)); err != nil {
		t.Fatalf("the last text of the day: %v", err)
	}
	// Spent now for every number, held or not.
	spent(t, Text(ctx, db, "hanzo", "+14155550199", asked("203.0.113.8"), nil, false, t0.Add(time.Hour)), "application")
	s := spent(t, Text(ctx, db, "hanzo", "+14155550198", asked("203.0.113.8"), nil, false, t0.Add(time.Hour)), "application")
	if s.Limit != PerApp || s.Retry != 23*time.Hour {
		t.Fatalf("spent = %+v", s)
	}
	if err := Text(ctx, db, "hanzo", "+14155550199", Ask{App: "admin/other", Client: "203.0.113.8"}, nil, false, t0.Add(time.Hour)); err != nil {
		t.Fatalf("another application: %v", err)
	}
}

// PerDay texts in all, every application and every second factor together.
func TestTextPerDay(t *testing.T) {
	db, _ := texting(t)
	ctx := context.Background()
	seedLedger(t, db, PerDay, schema.Text{Owner: "hanzo", Time: t0.Unix(), Client: "seed", Sent: true, Factor: true})
	carol := account(t, db, "hanzo", "carol", "", "+14155550134")

	s := spent(t, Text(ctx, db, "hanzo", "+14155550199", asked("203.0.113.7"), nil, false, t0.Add(time.Minute)), "day")
	if s.Limit != PerDay {
		t.Fatalf("spent = %+v", s)
	}
	// A second factor is held by it too, and nothing is minted.
	err := Issue(ctx, db, "hanzo", "+14155550134", "203.0.113.7", carol, t0.Add(time.Minute))
	spent(t, err, "day")
	if rec, _ := store.GetLatestVerificationRecord(ctx, db, "hanzo", "+14155550134"); rec != nil {
		t.Fatal("a refused second factor minted a code")
	}
	if err := Text(ctx, db, "hanzo", "+14155550199", asked("203.0.113.7"), nil, false, t0.Add(24*time.Hour)); err != nil {
		t.Fatalf("a day later: %v", err)
	}
}

// Ceiling requests in a day, texted or not: it bounds the ledger a flood of
// numbers nobody holds can write.
func TestTextCeiling(t *testing.T) {
	if testing.Short() {
		t.Skip("writes the whole ceiling")
	}
	db, _ := texting(t)
	seedLedger(t, db, Ceiling, schema.Text{Owner: "hanzo", Time: t0.Unix(), Client: "seed"})
	s := spent(t, Text(context.Background(), db, "hanzo", "+14155550199", asked("203.0.113.7"), nil, false, t0.Add(time.Minute)), "ceiling")
	if s.Limit != Ceiling {
		t.Fatalf("spent = %+v", s)
	}
}

// A second factor's code to the holder's own number is charged as a factor: it does
// not count toward what a stranger asking for the same number is told, and it is
// paced by the code it would replace.
func TestFactorCodesDoNotSpeakToStrangers(t *testing.T) {
	db, x := texting(t)
	ctx := context.Background()
	carol := account(t, db, "hanzo", "carol", "", "+14155550134")

	at := t0
	for i := 0; i < PerNumber+2; i++ {
		if err := Issue(ctx, db, "hanzo", "+14155550134", fmt.Sprintf("203.0.113.%d", i+1), carol, at); err != nil {
			t.Fatalf("factor code %d: %v", i+1, err)
		}
		at = at.Add(ResendInterval)
	}
	x.mu.Lock()
	sent := len(x.sent)
	x.mu.Unlock()
	if sent != PerNumber+2 {
		t.Fatalf("factor codes sent = %d", sent)
	}
	// The stranger's view of the number is the same as of any number: admitted.
	if err := Text(ctx, db, "hanzo", "+14155550134", asked("198.51.100.9"), carol, true, at); err != nil {
		t.Fatalf("an open request after the holder's factor codes = %v, want admitted", err)
	}
	if err := Issue(ctx, db, "hanzo", "+14155550134", "", carol, at.Add(time.Second)); err != ErrTooSoon {
		t.Fatalf("a factor code inside the interval = %v, want ErrTooSoon", err)
	}
	// And a factor send is refused where a number may not be texted.
	t.Setenv(EnvRegions, "GB")
	if err := Issue(ctx, db, "hanzo", "+14155550134", "", carol, at.Add(time.Hour)); err != ErrRegion {
		t.Fatalf("a factor code outside the countries = %v, want ErrRegion", err)
	}
}

// Five wrong answers spend a code, and asking again cannot buy a fresh five faster
// than the number's budget allows: a stranger gets at most PerNumber*MaxAttempts
// guesses a day.
func TestGuessesAreBoundedByTheNumbersBudget(t *testing.T) {
	db, x := texting(t)
	ctx := context.Background()
	carol := account(t, db, "hanzo", "carol", "", "+14155550134")

	// A code, five wrong answers, and the right one no longer works.
	if err := Text(ctx, db, "hanzo", "+14155550134", asked("203.0.113.7"), carol, true, t0); err != nil {
		t.Fatal(err)
	}
	code := sixDigits.FindString(x.await(t, 1)[0].Body)
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	for i := 0; i < MaxAttempts; i++ {
		if ok, _ := Consume(ctx, db, carol, "+14155550134", wrong, t0); ok {
			t.Fatal("a wrong code verified")
		}
	}
	if ok, _ := Consume(ctx, db, carol, "+14155550134", code, t0); ok {
		t.Fatalf("the code survived %d wrong answers", MaxAttempts)
	}
	// A fresh code (and a fresh five) is not available inside the interval.
	if err := Text(ctx, db, "hanzo", "+14155550134", asked("198.51.100.9"), carol, true, t0.Add(time.Second)); err != ErrTooSoon {
		t.Fatalf("asking again at once = %v, want ErrTooSoon", err)
	}

	// Ask as fast as the budget allows for a day, spending every code on wrong guesses.
	codes, guesses := 1, MaxAttempts
	at := t0
	for at.Before(t0.Add(24 * time.Hour)) {
		at = at.Add(ResendInterval)
		err := Text(ctx, db, "hanzo", "+14155550134", asked(fmt.Sprintf("198.51.100.%d", codes%250+1)), carol, true, at)
		var s *Spent
		if errors.As(err, &s) {
			if next := at.Add(s.Retry); next.Before(t0.Add(24 * time.Hour)) {
				t.Fatalf("the number's budget admits another code at %v, inside the day", next)
			}
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		codes++
		for i := 0; i < MaxAttempts; i++ {
			if ok, _ := Consume(ctx, db, carol, "+14155550134", wrong, at); !ok {
				guesses++
			}
		}
	}
	if codes != PerNumber || guesses != PerNumber*MaxAttempts {
		t.Fatalf("a day bought %d codes and %d guesses, want %d and %d", codes, guesses, PerNumber, PerNumber*MaxAttempts)
	}
}

// The SMS consent is recorded with the request that carried it: when, for which
// number (its digest), at which application.
func TestConsentIsRecorded(t *testing.T) {
	db, _ := texting(t)
	ctx := context.Background()
	ask := asked("203.0.113.7")
	ask.Consent = true
	if err := Text(ctx, db, "hanzo", "+1 415 555 0199", ask, nil, false, t0); err != nil {
		t.Fatal(err)
	}
	if err := Text(ctx, db, "hanzo", "+14155550198", asked("203.0.113.7"), nil, false, t0); err != nil {
		t.Fatal(err)
	}
	key, err := keyed(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	var consented []*schema.Text
	for _, r := range ledger(t, db) {
		if r.Consent {
			consented = append(consented, r)
		}
	}
	if len(consented) != 1 {
		t.Fatalf("consent rows = %d, want 1", len(consented))
	}
	r := consented[0]
	if r.Number != digest(key, "number", "+14155550199") || r.Application != app || r.Time != t0.Unix() {
		t.Fatalf("consent row = %+v", r)
	}
}

// A refused request writes nothing: neither a region refusal nor a spent budget
// leaves a row, so neither is charged.
func TestRefusalsWriteNothing(t *testing.T) {
	db, x := texting(t)
	ctx := context.Background()
	if err := Text(ctx, db, "hanzo", "+18765550100", asked("203.0.113.7"), nil, true, t0); err != ErrRegion {
		t.Fatalf("Jamaica = %v, want ErrRegion", err)
	}
	if err := Text(ctx, db, "hanzo", "+14155550199", asked("203.0.113.7"), nil, false, t0); err != nil {
		t.Fatal(err)
	}
	if err := Text(ctx, db, "hanzo", "+14155550199", asked("203.0.113.7"), nil, false, t0); err != ErrTooSoon {
		t.Fatalf("again = %v, want ErrTooSoon", err)
	}
	if n := len(ledger(t, db)); n != 1 {
		t.Fatalf("ledger rows = %d, want only the admitted request", n)
	}
	BindSender(nil)
	if err := Text(ctx, db, "hanzo", "+14155550198", asked("203.0.113.7"), nil, false, t0); err != ErrNoDelivery {
		t.Fatalf("unbound = %v, want ErrNoDelivery", err)
	}
	if x.count() != 0 {
		t.Fatal("something was texted")
	}
}
