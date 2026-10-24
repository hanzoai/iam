// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package otp

import (
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/orm"
	ormdb "github.com/hanzoai/orm/db"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

func openDB(t *testing.T) orm.DB {
	t.Helper()
	_ = schema.Kinds()
	db, err := orm.OpenSQLite(&ormdb.SQLiteDBConfig{
		Path:   filepath.Join(t.TempDir(), "otp.db"),
		Config: ormdb.SQLiteConfig{BusyTimeout: 5000, JournalMode: "WAL"},
	})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// recorder captures what was handed to delivery, which is the only way to learn the
// code that actually went out.
type recorder struct{ sent []string }

func (r *recorder) Send(_ context.Context, m Message) error {
	r.sent = append(r.sent, strings.Join([]string{m.Org, m.Channel, m.To, sixDigits.FindString(m.Body)}, ":"))
	return nil
}

// sixDigits finds the code inside a worded message — where a person reads it, and the
// only place a test can learn it from.
var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// account creates the user a code is minted FOR. A code is bound to an account, so a
// test that spends one needs a row to bind to — an address alone is not an identity.
func account(t *testing.T, db orm.DB, owner, name, email, phone string) *schema.User {
	t.Helper()
	u := orm.New[schema.User](db)
	u.Owner, u.Name, u.Email = owner, name, email
	u.Phone = store.NormalizePhone(phone)
	u.SetId(owner + "/" + name)
	if err := u.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	got, err := store.GetUserByName(context.Background(), db, owner, name)
	if err != nil || got == nil {
		t.Fatalf("re-read user: %v", err)
	}
	return got
}

func bind(t *testing.T, s Sender) {
	t.Helper()
	BindSender(s)
	t.Cleanup(func() { BindSender(nil) })
}

// THE defect. A phone number is punctuated differently every place it is typed, so a
// record filed under what somebody typed and looked up under the account's stored
// digits do not meet: the correct code, delivered to the correct phone, was refused,
// and the SMS second factor could not be completed by anyone.
func TestOneNumberIsOneReceiverHoweverItIsTyped(t *testing.T) {
	db := openDB(t)
	r := &recorder{}
	bind(t, r)
	now := time.Now()

	carol := account(t, db, "hanzo", "carol", "", "+14155550134")

	// The code verifies against every PUNCTUATION of the same digits, because the
	// digits are the key on both sides. The middle one is the exact pair that was
	// broken: a record filed as the caller typed it, presented as the account stores it.
	// Each spelling spends its own code, sent a resend interval after the last.
	for i, presented := range []string{
		"+1 (415) 555-0134",  // what the person typed at the send
		"+14155550134",       // what the account stores, and what the gate looks up
		"+1-415-555-0134",    // dashes instead of brackets
		" +1 415 555 0134  ", // and whatever whitespace came along
	} {
		at := now.Add(time.Duration(i) * ResendInterval)
		if err := Issue(context.Background(), db, "hanzo", "+1 (415) 555-0134", "", carol, at); err != nil {
			t.Fatalf("issue: %v", err)
		}
		code := r.sent[i][strings.LastIndex(r.sent[i], ":")+1:]

		// A number missing its country code is a DIFFERENT address, not the same one
		// spelled differently. Normalizing punctuation is safe; inferring a country is
		// a guess, and a guess here routes somebody's second factor to another country.
		if ok, _ := Consume(context.Background(), db, carol, "415-555-0134", code, at); ok {
			t.Fatal("a national-format number matched an E.164 record — the key is inferring a country code")
		}
		ok, err := Consume(context.Background(), db, carol, presented, code, at)
		if err != nil {
			t.Fatalf("consume %q: %v", presented, err)
		}
		if !ok {
			t.Fatalf("the delivered code was refused for %q — filing and finding disagree about punctuation", presented)
		}
	}

	// And the delivery itself went out normalized, which is what a carrier wants.
	if !strings.HasPrefix(r.sent[0], "hanzo:phone:+14155550134:") {
		t.Fatalf("sent %q, want the normalized number", r.sent[0])
	}
}

// A code is spent by the use that succeeds, so it cannot be replayed.
func TestConsumeSpendsTheCode(t *testing.T) {
	db := openDB(t)
	r := &recorder{}
	bind(t, r)
	now := time.Now()

	ada := account(t, db, "hanzo", "ada", "ada@example.com", "")
	if err := Issue(context.Background(), db, "hanzo", "ada@example.com", "", ada, now); err != nil {
		t.Fatalf("issue: %v", err)
	}
	code := r.sent[0][strings.LastIndex(r.sent[0], ":")+1:]

	if ok, err := Consume(context.Background(), db, ada, "ada@example.com", code, now); err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v", ok, err)
	}
	if ok, _ := Consume(context.Background(), db, ada, "ada@example.com", code, now); ok {
		t.Fatal("the same code was accepted twice — a replayable credential is left in the table")
	}
}

// A wrong guess counts, and the run ends at MaxAttempts with the record spent — the
// bound that makes a six-digit code usable as a credential rather than only as a
// signup gate.
func TestWrongGuessesAreBounded(t *testing.T) {
	db := openDB(t)
	r := &recorder{}
	bind(t, r)
	now := time.Now()

	ada := account(t, db, "hanzo", "ada", "ada@example.com", "")
	if err := Issue(context.Background(), db, "hanzo", "ada@example.com", "", ada, now); err != nil {
		t.Fatalf("issue: %v", err)
	}
	code := r.sent[0][strings.LastIndex(r.sent[0], ":")+1:]

	for i := 0; i < MaxAttempts; i++ {
		if ok, _ := Consume(context.Background(), db, ada, "ada@example.com", "000000", now); ok {
			t.Fatal("a wrong code verified")
		}
	}
	if ok, _ := Consume(context.Background(), db, ada, "ada@example.com", code, now); ok {
		t.Fatalf("the code survived %d wrong guesses — the search space is not bounded", MaxAttempts)
	}
}

// An expired code is a plain refusal, indistinguishable from an absent one: telling
// them apart answers "that address has a code outstanding" to anyone who asks.
func TestExpiredCodeIsRefused(t *testing.T) {
	db := openDB(t)
	bind(t, &recorder{})
	now := time.Now()

	ada := account(t, db, "hanzo", "ada", "ada@example.com", "")
	if err := Issue(context.Background(), db, "hanzo", "ada@example.com", "", ada, now); err != nil {
		t.Fatalf("issue: %v", err)
	}
	rec, err := store.GetLatestVerificationRecord(context.Background(), db, "hanzo", "ada@example.com")
	if err != nil || rec == nil {
		t.Fatalf("record not persisted: %v", err)
	}
	if ok, _ := Consume(context.Background(), db, ada, "ada@example.com", rec.Code, now.Add(TTL+time.Second)); ok {
		t.Fatal("a code outlived its TTL")
	}
}

// With nothing bound to deliver, the caller is TOLD the send did not happen and
// NOTHING IS MINTED. Reporting success would leave somebody waiting for a message
// that is not coming — the exact {status:"ok"} lie this refusal exists to remove —
// and filing the record anyway left a code nobody could receive for a redeeming
// caller to nonetheless have to trust.
func TestUnboundDeliveryIsReportedNotFaked(t *testing.T) {
	db := openDB(t)
	BindSender(nil)

	err := Issue(context.Background(), db, "hanzo", "ada@example.com", "", nil, time.Now())
	if err != ErrNoDelivery {
		t.Fatalf("issue with nothing bound = %v, want ErrNoDelivery", err)
	}
	if DeliveryConfigured() {
		t.Fatal("delivery reported configured with no sender bound")
	}
	if rec, _ := store.GetLatestVerificationRecord(context.Background(), db, "hanzo", "ada@example.com"); rec != nil {
		t.Fatal("a send that cannot happen left a redeemable code behind")
	}
}

// The words are OTP policy: the sentence a person reads renders the SAME constant
// that expires the record, so the two cannot part company when the TTL moves. A
// transport composing its own sentence would be restating a policy it cannot read.
func TestTheMessageStatesTheRealExpiry(t *testing.T) {
	m := message("hanzo", Email, "ada@example.com", "123456")
	want := fmt.Sprintf("It expires in %d minutes.", int(TTL.Minutes()))
	if !strings.Contains(m.Body, want) {
		t.Errorf("body = %q, want it to state %q", m.Body, want)
	}
	if !strings.Contains(m.Body, "123456") {
		t.Errorf("body = %q, want it to carry the code", m.Body)
	}
	if m.Subject == "" {
		t.Error("an email needs a subject")
	}
	// An SMS has nowhere to put one.
	if s := message("hanzo", Phone, "+14155550134", "123456"); s.Subject != "" {
		t.Errorf("sms subject = %q, want none", s.Subject)
	}
}

// The channel is read off the address, so no caller carries a mapping table.
func TestChannelComesFromTheAddress(t *testing.T) {
	if got := Channel("ada@example.com"); got != Email {
		t.Errorf("Channel(email) = %q, want %q", got, Email)
	}
	if got := Channel("+14155550134"); got != Phone {
		t.Errorf("Channel(number) = %q, want %q", got, Phone)
	}
}

// capture keeps every message handed to delivery, whole.
type capture struct{ sent []Message }

func (c *capture) Send(_ context.Context, m Message) error {
	c.sent = append(c.sent, m)
	return nil
}

// The plain wording is pinned byte for byte: the link is added beside it, never by
// editing it.
func TestMessageWording(t *testing.T) {
	m := message("hanzo", Email, "ada@example.com", "123456")
	if m.Subject != "Your verification code" {
		t.Errorf("subject = %q", m.Subject)
	}
	want := "Your verification code is 123456. It expires in 10 minutes. " +
		"If you did not request it, ignore this message and do not share it with anyone."
	if m.Body != want {
		t.Errorf("body =\n%q\nwant\n%q", m.Body, want)
	}
	if sms := message("hanzo", Phone, "+14155550134", "123456"); sms.Subject != "" || sms.Body != want {
		t.Errorf("sms = %+v, want no subject and the same body", sms)
	}
}

// IssueLink words a link only into an email, and only when it has one; an email
// without one is the code mail, and a number is the plain message.
func TestIssueLinkWording(t *testing.T) {
	const link = "https://hanzo.ai/auth/callback"
	for _, tc := range []struct {
		name, dest, link string
		linked           bool
	}{
		{"email with link", "ada@example.com", link, true},
		{"email without link", "ada@example.com", "", false},
		{"phone with link", "+14155550134", link, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openDB(t)
			c := &capture{}
			bind(t, c)
			if err := IssueLink(context.Background(), db, hanzo, tc.dest, "", nil, time.Now(), tc.link); err != nil {
				t.Fatalf("issue: %v", err)
			}
			if len(c.sent) != 1 {
				t.Fatalf("sent %d messages, want 1", len(c.sent))
			}
			got := c.sent[0]
			code := sixDigits.FindString(got.Body)
			want := message("hanzo", Channel(tc.dest), Receiver(tc.dest), code)
			if Channel(tc.dest) == Email {
				var err error
				if want, err = verification(hanzo, tc.dest, code); err != nil {
					t.Fatal(err)
				}
			}
			if tc.linked {
				var err error
				if want, err = signin(hanzo, tc.dest, code, tc.link); err != nil {
					t.Fatal(err)
				}
			}
			if got != want {
				t.Errorf("sent %+v\nwant %+v", got, want)
			}
			rec, err := store.GetLatestVerificationRecord(context.Background(), db, "hanzo", Receiver(tc.dest))
			if err != nil || rec == nil || rec.Code != code {
				t.Fatalf("filed record %+v (err %v) does not hold the delivered code %q", rec, err, code)
			}
		})
	}
}

// Issue sends an email as the designed code mail, from the org's own row: a second
// factor and a code asked for anywhere a link cannot go read like the sign-in mail.
// A number is the plain message, and an org with no row is still designed, naming
// nobody.
func TestIssueDesignsTheEmail(t *testing.T) {
	db := openDB(t)
	o := orm.New[schema.Organization](db)
	o.Owner, o.Name, o.DisplayName, o.WebsiteUrl = "admin", "hanzo", "Hanzo", "https://hanzo.ai"
	o.SetId("admin/hanzo")
	if err := o.CreateCtx(context.Background()); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	for _, tc := range []struct{ org, dest string }{
		{"hanzo", "ada@example.com"},
		{"nowhere", "bob@example.com"},
		{"hanzo", "+14155550134"},
	} {
		c := &capture{}
		bind(t, c)
		if err := Issue(context.Background(), db, tc.org, tc.dest, "", nil, time.Now()); err != nil {
			t.Fatalf("%s %s: issue: %v", tc.org, tc.dest, err)
		}
		if len(c.sent) != 1 {
			t.Fatalf("%s %s: sent %d messages, want 1", tc.org, tc.dest, len(c.sent))
		}
		got := c.sent[0]
		code := sixDigits.FindString(got.Body)
		want := message(tc.org, Channel(tc.dest), Receiver(tc.dest), code)
		if Channel(tc.dest) == Email {
			org := &schema.Organization{Name: tc.org}
			if tc.org == "hanzo" {
				org = hanzo
			}
			var err error
			if want, err = verification(org, tc.dest, code); err != nil {
				t.Fatal(err)
			}
		}
		if got != want {
			t.Errorf("%s %s: sent %+v\nwant %+v", tc.org, tc.dest, got, want)
		}
	}
}
