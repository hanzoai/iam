// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

// Package otp is the one-time code: mint it, file it, deliver it, spend it. It is
// the whole life of a secret sent to an address in order to prove that somebody
// holds that address (RFC 4226's "OTP", not the TOTP an authenticator app derives
// — that secret never travels and lives in internal/mfa/factor).
//
// It is a LEAF: store + schema + cred, no authz, no oidc, no mfa. That is what
// lets every caller share ONE code surface — the front-door send endpoint, sign-in
// by emailed or texted code, enrolling a delivered second factor, and the
// second-factor challenge itself. They all file and find a code by the same key,
// by construction rather than by each one remembering the rule.
//
// The rule they used to get wrong is [Receiver]. A code was filed under the string
// somebody typed and looked up under the digits the account stores, so the correct
// code, delivered to the correct phone, was refused.
//
// There is no clock here. `now` is a parameter, like the login challenge's, so a
// test states the time rather than reaching into a package variable.
package otp

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/hanzoai/orm"

	"github.com/hanzoai/iam/internal/cred"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The channels a code travels over — the VerificationRecord.Type vocabulary,
// verbatim from v1 (controllers/verification.go). "phone" is the channel; "sms" is
// the second FACTOR carried over it (internal/mfa/factor), and the two words are
// deliberately not merged: one names a transport, the other names a credential.
const (
	Email = "email"
	Phone = "phone"
)

// Channel names the transport an address is reached over, read off the ADDRESS by
// the same shape test [Receiver] keys on — so the channel a code is filed under and
// the channel it is carried over are one decision.
//
// Derived rather than passed in so that no caller has to carry a factor-to-channel
// table around: the address it already holds says which channel it is.
func Channel(dest string) string {
	if store.LooksLikePhone(dest) {
		return Phone
	}
	return Email
}

// Length is the OTP digit count (v1 getRandomCode(6)).
const Length = 6

// TTL bounds how long a sent code stays redeemable (v1's verificationCodeTimeout
// default, 10 minutes).
const TTL = 10 * time.Minute

// MaxAttempts bounds wrong guesses against ONE delivered code.
//
// Five, not one. Burning the code on the first miss is the strongest bound and the
// wrong trade: anyone who knows your address can post a wrong code while your real
// one is live and destroy it, so a one-attempt rule hands out a denial of service
// to any stranger. Five leaves a typo survivable and still cuts the search space
// from a million to five.
const MaxAttempts = 5

// Message is one code, worded and addressed, ready to carry.
//
// It is a message rather than a code because the WORDS are OTP policy and belong to
// the OTP. The text says how long the code lasts, and that number is [TTL] — one
// constant, read by the thing that expires the record and by the sentence that tells
// a person about it. A transport that composed its own sentence would be restating a
// policy it cannot see, and the two would drift the first time the TTL moved.
//
// So this side owns the content and the transport owns the wire. Channel is IAM's
// word ([Email] or [Phone]); translating it into whatever the carrier calls it
// happens at the transport, which is the only place that knows.
type Message struct {
	// Org is the tenant whose record this code was minted under — not a brand string
	// and not a default. A carrier resolves the sending account from the org's own
	// credential, so the wrong org reaches the wrong account and none cannot be
	// routed at all.
	Org string
	// Channel is [Email] or [Phone].
	Channel string
	// To is the address or number the code goes to.
	To string
	// Subject rides email only; an SMS has nowhere to put one.
	Subject string
	// Body is the text the person reads.
	Body string
}

// Sender carries one [Message]. It is the ONE seam between this package and the
// delivery service, and it holds the transport and nothing else — no wording, no
// provider, no credential.
type Sender interface {
	// Send delivers m. A non-nil error means the person did NOT receive it.
	Send(ctx context.Context, m Message) error
}

// message words one code for one person.
//
// It NAMES NO BRAND. One process answers for every white-label identity host, so a
// hardcoded name would be the wrong name on most of them; the identity a recipient
// sees is the org's own sending account, which the carrier resolves per tenant.
//
// The expiry is rendered from [TTL], so the sentence a person reads and the deadline
// the record is checked against are the same fact.
func message(org, channel, to, code string) Message {
	m := Message{
		Org:     org,
		Channel: channel,
		To:      to,
		Body: fmt.Sprintf("Your verification code is %s. It expires in %d minutes. "+
			"If you did not request it, ignore this message and do not share it with anyone.",
			code, int(TTL.Minutes())),
	}
	if channel == Email {
		m.Subject = "Your verification code"
	}
	return m
}

// sender is bound once at boot, before the server accepts a request, and read
// thereafter. nil means nothing can deliver.
var sender Sender

// BindSender installs the delivery transport. Call it at boot; a nil sender (or
// never calling this) leaves code sign-in correctly switched off everywhere.
func BindSender(s Sender) { sender = s }

// DeliveryConfigured reports whether a code this package mints can actually reach a
// person. It is the ONE authority for that question, read by the send endpoint AND
// by the login descriptor AND by the second-factor gate, so a screen can never
// offer a code the server cannot send — the same rule `offerable` applies to social
// buttons and `WalletChains` to wallet sign-in.
//
// It answers from the BOUND SENDER, not from configuration. Keying it on
// IAM_NOTIFY_ADDR instead was a trap I built and then measured: nothing else in
// this repo read that variable, so setting it would have restored the button and
// silenced the refusal below while still sending precisely nothing — the exact
// {status:"ok"} lie it was written to remove, re-armed. An address is a claim that
// delivery exists; a sender IS delivery. Bind one and this turns on by itself, with
// no second switch to remember.
func DeliveryConfigured() bool {
	return sender != nil
}

// ErrNoDelivery is the refusal when a code was minted and nothing can carry it.
// Distinguished from a transport failure because the caller's answer differs: one
// is a deployment that has no notify bound, the other is a send that went out and
// failed.
var ErrNoDelivery = errors.New("verification codes cannot be delivered: no notify service is configured")

// ErrTooSoon is the refusal when a live code for that address is younger than
// [ResendInterval]. Its own error because its answer is different in kind: nothing
// is wrong, the code is already on its way.
var ErrTooSoon = errors.New("a verification code was just sent; wait a moment before asking for another")

// ResendInterval is the minimum wait between two codes to one address. It is the
// smallest bound that makes a reissue a decision rather than a race: long enough
// that a double-click cannot strand the code already in flight, short enough that
// somebody who genuinely did not receive one is not stuck. The record's own Time
// carries it, so no counter is added anywhere.
const ResendInterval = 30 * time.Second

// Receiver is the ONE spelling a code is filed and found under.
//
// A phone number is punctuated differently everywhere it is typed — "+1 (415)
// 555-0134" and "+14155550134" are one address — so the digits are the key, on the
// send and on the check alike. An email is already canonical and is its own key.
//
// Filing and finding have to agree by CONSTRUCTION, not by whoever typed the number
// getting the punctuation right. They did not: a record written under a punctuated
// number was looked up under the account's stored digits, so the correct code,
// actually delivered to the correct phone, was refused — and the second factor over
// SMS could not be completed by anyone.
//
// Whether a destination IS a number is store.LooksLikePhone — the same shape test
// sign-in's identifier resolution asks, in the one place it is answered. Anything
// else is its own key, verbatim: NormalizePhone keeps only digits, so running it over
// an email address would leave nothing to match on, and over a username it would
// leave a different nothing.
func Receiver(dest string) string {
	dest = strings.TrimSpace(dest)
	if store.LooksLikePhone(dest) {
		return store.NormalizePhone(dest)
	}
	return dest
}

// Issue mints a code for dest, files it under [Receiver] and delivers it. It is the
// whole act of getting a code to a person and it is the ONLY one — the front-door
// send endpoint and the second-factor challenge both call it, which is what makes
// the row a code is filed under and the row that verifies it the same row.
//
// user is the account the code is FOR. It is not metadata: [Consume] refuses a
// record minted for anybody else, so this is what makes the code a credential for
// one person rather than for whoever holds the address. A caller that cannot
// resolve an account (the signup gate, proving an address before any user exists)
// passes nil, and the record it files can prove an address but can sign nobody in.
//
// ONE LIVE CODE PER ADDRESS, and a deliberate act to replace it. Two issues left
// two redeemable records ordered by a UNIX SECOND, so a double-click made "the
// latest code" a coin flip — the code the person holds may be the one that no
// longer resolves, and a wrong guess is charged to whichever row won the tie.
// Anyone who knew an address could do that on purpose, unthrottled, and on SMS
// each attempt spent the org's own carrier budget. So a reissue inside
// [ResendInterval] is refused, and otherwise the outstanding code is retired
// before its replacement is filed: there is no tie left to break.
//
// Nothing is minted when nothing can carry it. The refusal is unchanged; what it
// no longer leaves behind is a code nobody can receive that a redeeming caller
// would still have to trust. A send that FAILS keeps its record, because that code
// may well have gone out.
func Issue(ctx context.Context, db orm.DB, org, dest, remoteAddr string, user *schema.User, now time.Time) error {
	if sender == nil {
		return ErrNoDelivery
	}
	receiver := Receiver(dest)
	outstanding, err := store.GetLatestVerificationRecord(ctx, db, org, receiver)
	if err != nil {
		return err
	}
	if outstanding != nil && now.Unix()-outstanding.Time < int64(ResendInterval/time.Second) {
		return ErrTooSoon
	}
	code, err := generate(Length)
	if err != nil {
		return err
	}
	id, err := newID()
	if err != nil {
		return err
	}
	rec := &schema.VerificationRecord{
		Owner:       org,
		Name:        id,
		CreatedTime: now.UTC().Format(time.RFC3339),
		RemoteAddr:  remoteAddr,
		Type:        Channel(dest),
		Receiver:    receiver,
		Code:        code,
		Provider:    "demo",
		Time:        now.Unix(),
		IsUsed:      false,
	}
	if user != nil {
		rec.User = user.Owner + "/" + user.Name
	}
	if outstanding != nil {
		outstanding.IsUsed = true
		if err := outstanding.UpdateCtx(ctx); err != nil {
			return err
		}
	}
	if err := store.AddVerificationRecord(ctx, db, rec); err != nil {
		return err
	}
	// The persisted row is read back for every value: the code that was filed and the
	// code that goes out must be one tenant, one channel and one address, so they read
	// the one place those were decided. The normalized number is also the E.164-shaped
	// one a carrier wants.
	return sender.Send(ctx, message(rec.Owner, rec.Type, rec.Receiver, code))
}

// Consume verifies code against the latest live record for receiver and SPENDS the
// outcome — the check side for callers where the code IS the credential.
//
// It exists beside [Check] because a code that authenticates must be accounted for
// and a code that merely gates a signup need not be. Verifying and spending are one
// operation here on purpose: split across two calls, every caller would have to
// remember to spend, and the one that forgot would leave a replayable login
// credential lying in the table.
//
//   - a hit marks the record used, so the code is one-time
//   - a miss counts, and the count is what makes the code unguessable; at
//     [MaxAttempts] the record is spent so the run cannot continue
//
// The record must have been minted FOR user, in user's own organization. A code is
// delivered to an ADDRESS, and an address is not an identity: sign-in resolves an
// identifier NAME first, so org hanzo holding both `hanzo/z` (email z@hanzo.ai) and
// `hanzo/z@hanzo.ai` means the account a code was minted for and the account it
// signs in AS are two different rows. [Issue] has always stamped the account and
// nothing read it, so a code stood for whoever the request said it stood for. Every
// caller already holds the resolved user, so the binding costs nothing and tells no
// caller anything it did not know.
//
// The compare-and-spend runs inside a GetForUpdate transaction, the same guard the
// login challenge's burn uses. Read → compare → bump → write left the attempt
// counter open to the lost-update class internal/users/lockout.go exists to close:
// measured, 16 concurrent wrong guesses advanced the count by 3, so the [MaxAttempts]
// bound — the whole reason six digits is strong enough to be a credential — was
// defeated by parallelism. Serializing it also closes the window in which two racing
// correct submissions both spend one code.
//
// Reports whether the code was accepted. A spent, expired, absent or wrongly-bound
// record is a plain false: the caller must not distinguish them, or it answers "that
// address has a code outstanding" to anyone who asks.
func Consume(ctx context.Context, db orm.DB, user *schema.User, receiver, code string, now time.Time) (bool, error) {
	if user == nil {
		return false, nil
	}
	rec, err := live(ctx, db, user.Owner, receiver, code, now)
	if err != nil || rec == nil {
		return false, err
	}
	// The record names the account it was minted for, and only that account may spend
	// it. An unstamped record was filed for an address with no user — it proves the
	// address and is a credential for nobody.
	if rec.User == "" || rec.User != user.Owner+"/"+user.Name {
		return false, nil
	}
	storageID := rec.Key().Encode()

	var accepted bool
	txErr := db.RunInTransaction(ctx, func(tx orm.DB) error {
		fresh, err := orm.GetForUpdate[schema.VerificationRecord](tx, storageID)
		if err != nil {
			return err
		}
		// Re-checked under the lock, on the FRESH row: the record the query chose may
		// have been spent by a concurrent submission between the two reads.
		if fresh.IsUsed || now.Unix()-fresh.Time > int64(TTL/time.Second) {
			return nil
		}
		if cred.ConstantTimeEqual(fresh.Code, code) {
			fresh.IsUsed = true
			// The code was right, but a record that cannot be spent is a record that can
			// be replayed. The error aborts the transaction and leaves accepted false —
			// refuse rather than admit a credential we cannot retire.
			if err := fresh.UpdateCtx(ctx); err != nil {
				return err
			}
			accepted = true
			return nil
		}
		fresh.Attempts++
		if fresh.Attempts >= MaxAttempts {
			fresh.IsUsed = true
		}
		return fresh.UpdateCtx(ctx)
	})
	if txErr != nil {
		return false, txErr
	}
	return accepted, nil
}

// Check reports whether code matches the latest live record for receiver within
// owner WITHOUT spending it — for a flow that gates something else and marks the
// record used on its own completion. The compare is constant-time; an expired or
// absent record fails closed.
func Check(ctx context.Context, db orm.DB, owner, receiver, code string, now time.Time) (bool, error) {
	rec, err := live(ctx, db, owner, receiver, code, now)
	if err != nil || rec == nil {
		return false, err
	}
	return cred.ConstantTimeEqual(rec.Code, code), nil
}

// live resolves the newest unspent, unexpired record for receiver WITHIN owner,
// keyed the ONE way [Receiver] defines — so a caller that presents the number as a
// human typed it finds the row that was filed under its digits. A blank owner,
// receiver or code is nothing to look up; an expired record is nothing either, and
// all of them answer (nil, nil) so the caller cannot tell them apart.
//
// The owner scope is tenant isolation. An address is not unique across
// organizations — two orgs can each hold a user at alice@example.com — so unscoped
// this answered across every tenant at once: a newer foreign record won the
// ordering, and a person's own live code was not even the row the compare ran
// against.
func live(ctx context.Context, db orm.DB, owner, receiver, code string, now time.Time) (*schema.VerificationRecord, error) {
	if owner == "" || receiver == "" || code == "" {
		return nil, nil
	}
	rec, err := store.GetLatestVerificationRecord(ctx, db, owner, Receiver(receiver))
	if err != nil || rec == nil {
		return nil, err
	}
	if now.Unix()-rec.Time > int64(TTL/time.Second) {
		return nil, nil
	}
	return rec, nil
}

// generate returns an n-digit numeric code drawn from crypto/rand, uniformly (no
// modulo bias) and zero-padded to a fixed width.
func generate(n int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	k, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", n, k), nil
}

// newID is the opaque row name a record is filed under: 256 bits of crypto/rand,
// base64url. The record is addressed by it, never guessed at.
func newID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
