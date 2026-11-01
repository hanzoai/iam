// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package otp

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/orm"
	"github.com/nyaruka/phonenumbers"

	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// A texted code costs money on every send, and on an open endpoint the number is
// whatever a stranger types. This file is what stands between the two: which
// numbers may be texted at all ([Textable]), what each text is charged to (the
// budgets beside [ResendInterval]), and the open request ([Text]), which answers
// the same whether or not an account holds the number.

// EnvRegions names the countries a code may be texted to: ISO 3166-1 alpha-2
// codes, separated by commas or spaces ("US,CA,GB"). "*" is every country. Unset
// is [DefaultRegions]. A value naming anything that is not a country keeps
// DefaultRegions and is logged, so a typo never opens texting to the world.
const EnvRegions = "IAM_TEXT_REGIONS"

// DefaultRegions is where a code is texted when the deployment names nowhere:
// the United States with its territories, Canada, the United Kingdom, the 27
// countries of the EU, Iceland, Liechtenstein, Norway, Switzerland, Australia
// and New Zealand. The ranges SMS pumping lives on — premium-rate and
// high-termination international routes — are outside it.
var DefaultRegions = []string{
	"US", "PR", "VI", "GU", "AS", "MP",
	"CA", "GB",
	"AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE",
	"IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE",
	"IS", "LI", "NO", "CH",
	"AU", "NZ",
}

// ErrRegion is the refusal for a number that may not be texted: not a whole
// international number, not one a person carries (premium rate, toll free,
// shared cost, a landline, a personal-number redirect), or in a country
// [EnvRegions] does not name. It is a fact about the number, the same for
// everyone who asks.
var ErrRegion = errors.New("codes cannot be texted to this number")

// Textable reports whether dest may be texted a code: nil, or [ErrRegion].
//
// The number must be international (+ and its country code). A national
// number names no country, and guessing one is exactly what store.NormalizePhone
// refuses to do, so it cannot be checked against the allowed countries and is
// not texted. It must be a valid number of a kind a person receives texts on —
// mobile, mobile-or-fixed (how the US and Canada number), or VoIP — and in a
// country the deployment texts.
func Textable(dest string) error {
	n, err := phonenumbers.Parse(Receiver(dest), "")
	if err != nil || !phonenumbers.IsValidNumber(n) {
		return ErrRegion
	}
	switch phonenumbers.GetNumberType(n) {
	case phonenumbers.MOBILE, phonenumbers.FIXED_LINE_OR_MOBILE, phonenumbers.VOIP:
	default:
		return ErrRegion
	}
	if !allowed(phonenumbers.GetRegionCodeForNumber(n)) {
		return ErrRegion
	}
	return nil
}

// regions is the parsed EnvRegions, kept for the raw value it was parsed from so
// a changed environment is read again and an unchanged one is not.
var regions struct {
	sync.Mutex
	read bool
	raw  string
	set  []string
}

// allowed reports whether region is one EnvRegions names.
func allowed(region string) bool {
	if region == "" {
		return false
	}
	raw := os.Getenv(EnvRegions)
	regions.Lock()
	defer regions.Unlock()
	if !regions.read || regions.raw != raw {
		set, err := parseRegions(raw)
		if err != nil {
			log.Printf("otp: %v; texting keeps the default countries", err)
		}
		regions.read, regions.raw, regions.set = true, raw, set
	}
	return slices.Contains(regions.set, "*") || slices.Contains(regions.set, region)
}

// parseRegions reads an EnvRegions value. Blank is DefaultRegions; anything it
// cannot read whole is DefaultRegions and an error naming what it could not.
func parseRegions(raw string) ([]string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
	if len(fields) == 0 {
		return DefaultRegions, nil
	}
	known := phonenumbers.GetSupportedRegions()
	set := make([]string, 0, len(fields))
	var bad []string
	for _, f := range fields {
		r := strings.ToUpper(f)
		if r != "*" && !known[r] {
			bad = append(bad, f)
			continue
		}
		set = append(set, r)
	}
	if len(bad) > 0 {
		return DefaultRegions, errors.New(EnvRegions + " names no country as " + strings.Join(bad, ", "))
	}
	return set, nil
}

// Ask is who asks for a texted code, as the budgets count them.
type Ask struct {
	// App is the application the code is asked for ("owner/name"), or "" for a
	// second factor, which no application asks for.
	App string
	// Client is the asking client's address (httpx.Peer). "" is one client:
	// every request that names no address shares it.
	Client string
	// Consent says the person ticked the SMS consent when they asked. It is
	// recorded with the request (schema.Text.Consent).
	Consent bool
}

// Spent is a texted code a budget refused: the bound that held it, its limit and
// window, and how long until it admits one more.
type Spent struct {
	// Bound is "number", "client", "application", "day" or "ceiling".
	Bound  string
	Limit  int
	Window time.Duration
	Retry  time.Duration
}

func (e *Spent) Error() string {
	switch e.Bound {
	case "number":
		return "too many codes have been asked for this number; try again later"
	case "client":
		return "too many codes have been asked from this network; try again later"
	}
	return "too many codes have been texted; try again later"
}

// Text is the OPEN request for a code to a phone number: the one way a number
// somebody typed is texted, and the only send that never says whether an account
// holds it.
//
// user is the account that holds the number (the code is bound to it, exactly as
// [Issue] binds one), or nil. send says whether a text goes out: true when an
// account holds the number, or when the signed-in person asking is adding it to
// their own account (a code filed for nobody, which [Prove] spends). With send
// false nothing is minted and nothing is texted.
//
// Either way the request is charged to the budgets the same, and the answer is
// the same: nil, [ErrNoDelivery], [ErrRegion], [ErrTooSoon] or a *[Spent], decided
// by the number and the ledger before anything about an account is consulted.
// What follows the charge cannot change the answer: the text is handed to the
// carrier after the answer is decided and is not waited for (a carrier's round
// trip is the clearest tell there is), a code a second factor sent moments ago is
// left to stand, and a failure is logged rather than returned.
func Text(ctx context.Context, db orm.DB, org, dest string, ask Ask, user *schema.User, send bool, now time.Time) error {
	if sender == nil {
		return ErrNoDelivery
	}
	if err := Textable(dest); err != nil {
		return err
	}
	number := Receiver(dest)
	if err := admit(ctx, db, org, number, ask, false, send, now); err != nil {
		return err
	}
	if !send {
		return nil
	}
	err := issue(ctx, db, PurposeCode, org, dest, ask.Client, user, now, func(channel, to, code string) (Message, error) {
		return message(org, channel, to, code), nil
	}, func() error { return nil }, detach)
	if err != nil && !errors.Is(err, ErrTooSoon) {
		log.Printf("otp: a texted code for %s was not filed: %v", org, err)
	}
	return nil
}

// textWait bounds one detached send: the carrier's answer, or give up.
const textWait = 30 * time.Second

// detach hands m to the transport without waiting for it. The request's values
// ride along and its cancellation does not, so the send outlives the answer. A
// failure is logged with the number taken out of it.
func detach(ctx context.Context, m Message) error {
	s := sender
	ctx = context.WithoutCancel(ctx)
	go func() {
		ctx, cancel := context.WithTimeout(ctx, textWait)
		defer cancel()
		if err := s.Send(ctx, m); err != nil {
			said := strings.ReplaceAll(err.Error(), m.To, "<number>")
			said = strings.ReplaceAll(said, strings.TrimPrefix(m.To, "+"), "<number>")
			log.Printf("otp: a texted code for %s did not go out: %s", m.Org, said)
		}
	}()
	return nil
}

// admit charges one texted code to the budgets and files the row that records it
// (schema.Text), in one transaction, or refuses it with [ErrTooSoon] or a
// *[Spent] and files nothing. factor says the number is an account's own and the
// asker proved who they are, which the per-number pacing does not count; sent
// says a text goes out, which the money bounds count.
func admit(ctx context.Context, db orm.DB, org, number string, ask Ask, factor, sent bool, now time.Time) error {
	key, err := keyed(ctx, db)
	if err != nil {
		return err
	}
	row := schema.Text{
		Owner:       org,
		Time:        now.Unix(),
		Application: ask.App,
		Client:      digest(key, "client", network(clientOf(ask.Client))),
		Number:      digest(key, "number", number),
		Sent:        sent,
		Factor:      factor,
		Consent:     ask.Consent,
	}
	return db.RunInTransactionWith(ctx, &orm.TxOptions{MaxAttempts: 5}, func(tx orm.DB) error {
		if !factor {
			if err := paced(ctx, tx, row.Number, now); err != nil {
				return err
			}
		}
		for _, b := range budgets {
			if err := b.hold(ctx, tx, row, now); err != nil {
				return err
			}
		}
		return enter(ctx, tx, row)
	})
}

// paced refuses an open request for number inside [ResendInterval] of the last
// one, read from the ledger and so the same whether or not a code went out.
func paced(ctx context.Context, tx orm.DB, number string, now time.Time) error {
	last, err := orm.TypedQuery[schema.Text](tx).
		Filter("Number=", number).Filter("Factor=", false).
		Order("-Time").First()
	if errors.Is(err, orm.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	if now.Unix()-last.Time < int64(ResendInterval/time.Second) {
		return ErrTooSoon
	}
	return nil
}

// budget is one bound on texted codes: its limit, its window, the counter a row
// is charged to, and — separately — whether a request is admitted against it and
// whether an admitted row adds to it. The two are not the same, and that is the
// point: a second factor's code is admitted against the client and factor bounds
// alone, so a stranger who fills the open-request budgets cannot lock a holder
// out of their own second factor.
type budget struct {
	name   string
	limit  int
	window time.Duration
	// bucket names the counter a row of this kind is counted in. "" is one
	// deployment-wide counter.
	bucket func(schema.Text) string
	// applies says a request must be admitted against this bound before it is
	// filed.
	applies func(schema.Text) bool
	// counts says an admitted row adds one to this bound's counter.
	counts func(schema.Text) bool
}

// always admits and counts every row.
func always(schema.Text) bool { return true }

// budgets are every bound, in one place, so the counters a row is charged to and
// the counters a request is admitted against are read off the same table.
//
// The open-request bounds (number, day, ceiling) are what a caller who names a
// number they do not hold can fill: they are the ones an attacker spends, so no
// second factor is ever admitted against them. The money bounds a stranger cannot
// reach (the factor ceiling) are the ones a holder's own codes are charged to.
var budgets = []budget{
	// One number's open requests: a holder's own codes never decide what a
	// stranger asking for the same number is told.
	{"number", PerNumber, 24 * time.Hour,
		func(r schema.Text) string { return r.Number },
		func(r schema.Text) bool { return !r.Factor },
		func(r schema.Text) bool { return !r.Factor }},
	// One client, whatever it asks for: a caller hammering the endpoint is
	// throttled here whether its requests are texted or not.
	{"client", PerClient, time.Hour,
		func(r schema.Text) string { return r.Client }, always, always},
	// One application's texts, which is the surface that spends the carrier's
	// money. Application ids are "owner/name", so this is already one tenant's.
	{"application", PerApp, 24 * time.Hour,
		func(r schema.Text) string { return r.Application },
		func(r schema.Text) bool { return r.Application != "" },
		func(r schema.Text) bool { return r.Application != "" && r.Sent }},
	// One tenant's open texts. Scoped by owner so one tenant's abuse cannot
	// spend another's.
	{"day", PerDay, 24 * time.Hour,
		func(r schema.Text) string { return r.Owner },
		func(r schema.Text) bool { return !r.Factor },
		func(r schema.Text) bool { return r.Sent && !r.Factor }},
	// The deployment's open requests, texted or not: the breaker on the ledger a
	// flood of numbers nobody holds can write.
	{"ceiling", Ceiling, 24 * time.Hour,
		func(schema.Text) string { return "" },
		func(r schema.Text) bool { return !r.Factor },
		func(r schema.Text) bool { return !r.Factor }},
	// The deployment's second factors, RESERVED: only a holder's own code is
	// charged to it, and only a holder's own code is admitted against it, so an
	// open flood cannot exhaust it.
	{"factor", FactorDay, 24 * time.Hour,
		func(schema.Text) string { return "" },
		func(r schema.Text) bool { return r.Factor },
		func(r schema.Text) bool { return r.Sent && r.Factor }},
}

// hold returns a *Spent when b has no room at now, else nil. It reads ONE counter
// row — never a scan of the ledger — so a refusal costs the same as an admission
// however many rows the ledger holds.
//
// The window is sliding, like the ledger it replaces: a row counts for window
// after it was filed, and the admission that takes the bucket over the limit is
// refused until the oldest one in it ages out. Keeping the window in the counter
// row (rather than aligning it) is what makes the retry that is reported back
// match the refusal the caller actually waits for.
func (b budget) hold(ctx context.Context, tx orm.DB, r schema.Text, now time.Time) error {
	if !b.applies(r) {
		return nil
	}
	n, start, err := read(ctx, tx, b.bucketKey(r))
	if err != nil {
		return err
	}
	w := int64(b.window / time.Second)
	if n == 0 || now.Unix() >= start+w {
		// Empty or expired window: this request opens a new one.
		return nil
	}
	if n < b.limit {
		return nil
	}
	retry := start + w - now.Unix()
	if retry < 1 {
		retry = 1
	}
	return &Spent{Bound: b.name, Limit: b.limit, Window: b.window, Retry: time.Duration(retry) * time.Second}
}

// bucketKey names the counter row for this bound and bucket, without a window:
// the window lives in the row.
func (b budget) bucketKey(r schema.Text) string {
	return b.name + "/" + b.bucket(r)
}

// read is a counter row's count and the second its window opened, or zero for
// one nothing has been filed under yet.
func read(ctx context.Context, tx orm.DB, key string) (int, int64, error) {
	t, err := orm.TypedQuery[schema.TextTally](tx).Filter("Bucket=", key).First()
	if errors.Is(err, orm.ErrNotFound) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	return t.Count, t.Window, nil
}

// count adds one to the counter row key, opening a new window when the old one
// has expired. It is called inside the same transaction as the ledger insert.
// count adds one to the counter row key, opening a new window when the old one
// has expired. It is called inside the same transaction as the ledger insert.
func count(ctx context.Context, tx orm.DB, key string, now time.Time, window time.Duration) error {
	w := int64(window / time.Second)
	if w < 1 {
		w = 1
	}
	t, err := orm.TypedQuery[schema.TextTally](tx).Filter("Bucket=", key).First()
	if errors.Is(err, orm.ErrNotFound) {
		t = orm.New[schema.TextTally](tx)
		t.Bucket = key
		t.Window = now.Unix()
		t.Count = 1
		t.SetId("tally/" + key)
		return t.CreateCtx(ctx)
	}
	if err != nil {
		return err
	}
	if now.Unix() >= t.Window+w {
		t.Window = now.Unix()
		t.Count = 1
	} else {
		t.Count++
	}
	return t.UpdateCtx(ctx)
}

// network is what one client is counted as: an IPv4 address, or the /48 an IPv6
// address sits in. The zero Addr is "".
//
// A /64 is what one subscriber's LAN holds, and a subscriber delegated a /48 —
// which is what a site gets — holds 65,536 of them: bucketing by /64 would let
// one caller rotate addresses and count as thousands of clients. /48 is the
// smallest allocation a site is given, so it is the bucket that names one
// subscriber, at the cost of sharing a budget with everyone else behind them.
func enter(ctx context.Context, tx orm.DB, row schema.Text) error {
	at := time.Unix(row.Time, 0)
	for _, b := range budgets {
		if !b.counts(row) {
			continue
		}
		if err := count(ctx, tx, b.bucketKey(row), at, b.window); err != nil {
			return err
		}
	}
	id, err := newID()
	if err != nil {
		return err
	}
	t := orm.New[schema.Text](tx)
	model := t.Model
	*t = row
	t.Model = model
	t.Name = id
	t.SetId(row.Owner + "/" + id)
	return t.CreateCtx(ctx)
}

func network(ip netip.Addr) string {
	ip = ip.Unmap()
	switch {
	case !ip.IsValid():
		return ""
	case ip.Is4():
		return ip.String()
	}
	p, _ := ip.Prefix(48)
	return p.String()
}

// clientOf reads a client address handed over as text. Anything that is not an
// address is the zero Addr.
func clientOf(s string) netip.Addr {
	ip, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}
	}
	return ip.Unmap()
}

// textKey is the key the ledger's digests are made with, derived once from the
// platform signing cert: stable for the deployment, secret, and held by every
// replica, so the replicas count one ledger and a copy of the store alone cannot
// reverse a digest to a number or an address (a plain hash of an IPv4 address is
// four billion guesses away from it).
var textKey struct {
	sync.Mutex
	key []byte
}

// errNoTextKey refuses a texted code when there is no signing cert to key the
// ledger with; such a deployment cannot sign anyone in either.
var errNoTextKey = errors.New("otp: no platform signing cert to key the texting ledger")

// keyed returns the ledger key, deriving it on first use.
func keyed(ctx context.Context, db orm.DB) ([]byte, error) {
	textKey.Lock()
	defer textKey.Unlock()
	if textKey.key != nil {
		return textKey.key, nil
	}
	cert, err := store.PlatformSigningCert(ctx, db)
	if err != nil {
		return nil, err
	}
	if cert == nil || cert.PrivateKey == "" {
		return nil, errNoTextKey
	}
	sum := sha256.Sum256([]byte("iam.otp.text.v1\x00" + cert.PrivateKey))
	textKey.key = sum[:]
	return textKey.key, nil
}

// digest is the keyed digest of one value of one kind ("number", "client"),
// 128 bits in hex.
func digest(key []byte, kind, value string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(kind + "\x00" + value))
	return hex.EncodeToString(m.Sum(nil)[:16])
}
