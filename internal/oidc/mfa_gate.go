// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	fiber "github.com/zap-proto/fiber/v3"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/otp"
	"github.com/hanzoai/iam/pkg/schema"
	"github.com/hanzoai/iam/pkg/store"
)

// The login-time second-factor gate. A verified password proves ONE factor;
// everything here decides whether a SECOND is owed before any token or device
// approval is minted. It is the counterpart to the enrollment surface in
// internal/mfa — enrollment decides what factors a user HAS, this decides when the
// sign-in must present one.
//
// The two answers are v1's protocol STRINGS (object/factor.go:50-54): the client
// string-compares `data` against them, so they are serialized format, not internal
// names. Any other shape and the client reads the answer as an authorization code
// and the factor is skipped.
const (
	// RequiredMfa — the organization requires a factor this user has not enrolled;
	// the client must divert to enrollment.
	RequiredMfa = "RequiredMfa"
	// NextMfa — the user has factors; data2 carries the allowed ones and the client
	// must post one back. NO code is minted with this answer.
	NextMfa = "NextMfa"
)

// gate is the second-factor decision — the ONE place a sign-in is held. It answers
// the request itself and reports true when it did; a false means this principal has
// proven everything it owes and the caller may mint.
//
// Every path that signs a user in calls this BEFORE minting a token or approving a
// device — one function, every call site, because a gate that exists in one branch
// is not a gate.
//
// verificationType names the factor the caller already proved, so the challenge
// never offers it back. "" excludes nothing (a password proves none of the
// offerable factors).
func gate(c *zip.Ctx, db orm.DB, user *schema.User, org *schema.Organization, verificationType string) (bool, error) {
	ctx := c.Context()
	now := nowFunc()

	// The organization REQUIRES a factor this user has not enrolled: the answer is
	// enrollment, not a challenge it could never answer.
	if factor.Prompt(org, user) {
		return true, httpx.Ok(c, RequiredMfa)
	}
	if !factor.Enabled(user) {
		return false, nil
	}

	// "Remember this device" — an open window on THIS device skips the factor.
	if remembered(c, user, now) {
		return false, nil
	}

	allow := allowList(user, org, verificationType)
	if len(allow) == 0 {
		return nothingToAsk(c, user, verificationType)
	}

	// A delivered factor has to actually be delivered. Sending here — rather than
	// leaving it to a client that would have to name a destination — is what makes the
	// send key and the verify key the same value: both are factor.Destination.
	allow = deliver(c, db, user, allow, now)
	if len(allow) == 0 {
		return true, httpx.Err(c, "a second factor is required and its code could not be sent")
	}

	id, err := MintChallenge(ctx, db, KindMfa, user.Owner+"/"+user.Name, verificationType, offeredTypes(allow), now)
	if err != nil {
		return true, err
	}
	SetChallenge(c, id)
	// data is the STRING "NextMfa"; data2 carries the factors. No code is minted
	// here — that is the whole point of the gate.
	return true, httpx.Ok(c, NextMfa, allow)
}

// nothingToAsk decides a sign-in whose allow-list came out empty, which is THREE
// different situations that must not collapse into one — the old `return false` waved
// all three through:
//
//   - the account claims a factor it does not hold. Enabled() reads PreferredMfaType,
//     so such a row says "MFA is on" and offers nothing to ask for; passing it through
//     required the password alone. Enrollment is the answer, the same answer an
//     org-required-but-unenrolled factor gets.
//   - every factor the account holds needs a code and none can be sent right now (no
//     notify bound, no address on file). Fail CLOSED: a factor that cannot be served
//     is not a factor that can be waived.
//   - the first credential already WAS the account's only factor — an emailed code
//     answering an email-only account. Nothing further is owed, so the caller mints.
//
// Reports the same (gated, err) the gate does, so the third case can hand the sign-in
// back rather than answering it. Returning "gated, no answer written" here left the
// request hanging on an empty 200.
func nothingToAsk(c *zip.Ctx, user *schema.User, verificationType string) (bool, error) {
	if !factor.Has(user, user.PreferredMfaType) {
		return true, httpx.Ok(c, RequiredMfa)
	}
	for _, t := range factor.Held(user) {
		if t != verificationType {
			return true, httpx.Err(c, "a second factor is required and none of yours can be used right now")
		}
	}
	return false, nil
}

// allowList is the factors a challenge may be answered with: held by the account,
// not the one the caller just used, and ANSWERABLE — a delivered factor with no
// address on file, or with nothing bound to send it, can never be verified, and
// offering it strands the sign-in on a screen waiting for a message that is not
// coming. It is the same rule the login descriptor applies to the code-sign-in
// button: never offer a code the server cannot send.
//
// Each carries the org's remember window so the client can offer "don't ask again".
func allowList(user *schema.User, org *schema.Organization, verificationType string) []*schema.MfaProps {
	hours := 0
	if org != nil {
		hours = org.MfaRememberInHours
	}
	allow := []*schema.MfaProps{}
	for _, p := range factor.AllProps(user) {
		if !p.Enabled || p.MfaType == verificationType {
			continue
		}
		if factor.Delivered(p.MfaType) && (factor.Destination(user, p.MfaType) == "" || !otp.DeliveryConfigured()) {
			continue
		}
		p.MfaRememberInHours = hours
		allow = append(allow, p)
	}
	return allow
}

// offeredTypes names the factors an allow-list offers, which is what the challenge
// row records and the finish checks an answer against.
func offeredTypes(allow []*schema.MfaProps) []string {
	types := make([]string, 0, len(allow))
	for _, p := range allow {
		types = append(types, p.MfaType)
	}
	return types
}

// deliver sends the code for the one delivered factor this challenge will be
// answered with, and returns the factors still on offer.
//
// The target is the account's PREFERRED factor when that is a delivered one still on
// offer, else the first delivered factor on offer — so the ordinary case sends over
// the channel the person chose (which is the one a picker defaults to), and a sign-in
// that already used that channel — an emailed code on an account that prefers email —
// falls through to the other one. An authenticator-only offer sends nothing: TOTP
// needs no message.
//
// Before this, the gate answered NextMfa and delivered NOTHING. There was no send
// step anywhere on the challenge path, and the only send endpoint made the caller
// name the destination — which is the one thing a second factor must not take from
// the request. So a texted or emailed second factor could not be completed at all.
//
// A send that FAILS drops its factor from the offer rather than leaving it there.
// Offering a code nobody will receive is the {status:"ok"} lie one layer in: the
// screen asks for a number that will never arrive, and the person cannot tell that
// from having mistyped it.
func deliver(c *zip.Ctx, db orm.DB, user *schema.User, allow []*schema.MfaProps, now time.Time) []*schema.MfaProps {
	target := ""
	for _, p := range allow {
		if !factor.Delivered(p.MfaType) {
			continue
		}
		if target == "" || p.MfaType == user.PreferredMfaType {
			target = p.MfaType
		}
	}
	if target == "" {
		return allow
	}
	dest := factor.Destination(user, target)
	if err := otp.Issue(c.Context(), db, user.Owner, dest, c.Fiber().IP(), user, now); err == nil {
		return allow
	}
	kept := make([]*schema.MfaProps, 0, len(allow))
	for _, p := range allow {
		if p.MfaType != target {
			kept = append(kept, p)
		}
	}
	return kept
}

// finishMfa answers an outstanding challenge. The user is loaded from the
// CHALLENGE's subject — never from the request — so a body naming another account
// cannot redirect the ceremony. Taking the challenge spends it, so a passcode
// replayed against the same id loses. On success it completes the ORIGINAL sign-in
// through the same loginGrant every other path uses, so a second factor over a
// device approval reaches approveDevice, not a token.
func finishMfa(c *zip.Ctx, db orm.DB, id string, f loginForm) error {
	ctx := c.Context()
	ch, err := TakeChallenge(ctx, db, id, KindMfa, nowFunc())
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	ClearChallenge(c)

	owner, name, _ := strings.Cut(ch.Subject, "/")
	user, err := store.GetUserByName(ctx, db, owner, name)
	if err != nil {
		return httpx.Err(c, err.Error())
	}
	if user == nil {
		return httpx.Err(c, ErrChallenge.Error())
	}

	if err := proveFactor(ctx, db, user, ch, f.MfaType, f.Passcode, f.RecoveryCode); err != nil {
		return httpx.Err(c, err.Error())
	}

	if f.EnableMfaRemember {
		if err := remember(c, db, user); err != nil {
			return httpx.Err(c, err.Error())
		}
	}
	return loginGrant(c, db, user, f)
}

// proveFactor verifies ONE second factor against a challenge. It is the one
// implementation, shared by the password gate's finish and the federated resume —
// there were two, and they had already drifted: the password path accepted a
// delivered code and the federated path refused it, so an account holding only an
// emailed or texted factor could answer one login and not the other.
//
// A nil return means the factor is proven; the error is the message to return.
//
// SECOND-FACTOR THROTTLE (F-D1 INFO): the passcode/recovery verify below has no
// DEDICATED per-account counter, and — correcting an earlier note — the PASSWORD
// lockout does NOT stand in for one. The MFA threat model assumes the password is
// already KNOWN (that is the whole reason a second factor exists), and a CORRECT
// password RESETS the lockout counter rather than tripping it (users.Authenticate),
// so an attacker who holds the password can mint FRESH single-use challenges without
// ever locking the door. What actually makes online iteration of the 10^6 TOTP space
// infeasible is independent of the lockout: (1) each fresh challenge costs one
// deliberately-slow argon2id password verify, and (2) the 30-second TOTP step makes
// the current code a MOVING target — the ~1-3 codes valid in any window cannot be
// enumerated within that window at argon2id-throttled rates. The challenge itself is
// single-use and burned ATOMICALLY (TakeChallenge holds the row lock, GetForUpdate),
// so one captured passcode cannot be double-spent by racing finishMfa calls. A
// delivered code carries its own counter (otp.Consume spends the record after five
// misses). A dedicated second-factor counter (its own window + atomic increment,
// mirroring internal/users/lockout.go) remains an available defense-in-depth
// addition; it is not required to close an online-guessing oracle under the model
// above.
func proveFactor(ctx context.Context, db orm.DB, user *schema.User, ch *schema.LoginChallenge, mfaType, passcode, recoveryCode string) error {
	switch {
	case passcode != "":
		// Answer only what the challenge OFFERED. Checking merely that the answering
		// factor differs from the one already proven was not enough: it let an
		// authenticator-only account be passed with an emailed code, so a deliberate
		// choice of TOTP silently degraded to possession of a mailbox — the exact threat
		// TOTP is chosen to survive.
		if !offers(ch, mfaType) {
			return errors.New("invalid multi-factor authentication type")
		}
		switch mfaType {
		case factor.App:
			if !factor.Verify(user.TotpSecret, passcode) {
				return errors.New("the multi-factor authentication code is incorrect")
			}
		case factor.SMS, factor.Email:
			// A texted or emailed second factor is a delivered code, verified by the same
			// one-time machinery a code SIGN-IN uses: spent on success, counted on a miss.
			//
			// The destination is the account's OWN stored address and never anything off
			// the request. Letting the caller name it would turn the second factor inside
			// out: an attacker holding a first factor could have the code sent to an
			// address they control and answer their own challenge.
			ok, err := otp.Consume(ctx, db, factor.Destination(user, mfaType), passcode, nowFunc())
			if err != nil {
				return err
			}
			if !ok {
				return errors.New("the multi-factor authentication code is incorrect")
			}
		default:
			return errors.New("invalid multi-factor authentication type")
		}
	case recoveryCode != "":
		// A recovery code is one-time: the hit is removed and the row written whether or
		// not the rest of the sign-in succeeds, so a code cannot be spent twice. It is
		// answerable against ANY challenge — it is the way back in when no offered factor
		// can be produced, which is the whole reason it exists.
		if !factor.UseRecovery(user, recoveryCode) {
			return errors.New("the recovery code is incorrect")
		}
		if err := factor.Save(ctx, db, user); err != nil {
			return err
		}
	default:
		return errors.New("missing passcode or recovery code")
	}
	return nil
}

// offers reports whether the challenge was minted offering mfaType. The offer is
// read from the CHALLENGE ROW, not recomputed: the factors are decided once, when
// the sign-in is held, and an answer is checked against that decision — so a change
// to the account between the hold and the answer cannot widen what may answer it.
func offers(ch *schema.LoginChallenge, mfaType string) bool {
	if mfaType == "" {
		return false
	}
	for _, t := range ch.Offered {
		if t == mfaType {
			return true
		}
	}
	return false
}

// "Don't ask again on this browser" is a BEARER TOKEN, held by the browser that
// answered the factor, whose digest is on the account. Possession of the token is the
// proof; the deadline bounds it.
//
// It was a deadline alone, which is account-wide: a factor proven in one browser
// skipped the factor in EVERY browser, including one an attacker holding the password
// had just opened. Their own test showed it — a brand-new request carrying nothing
// minted a code — and the blast radius was only zero because every live organization
// leaves MfaRememberInHours at 0, which also meant the client's "don't ask again"
// checkbox silently did nothing.
//
// The token needs no signature: it is 256 bits of crypto/rand compared against a
// stored digest, the same shape as a recovery code and as the challenge id. There is
// no second auth scheme here, and nothing to verify but equality.
const rememberCookie = "hanzo_mfa_remember"

// mintRemember returns a fresh remember token for the browser and the digest to
// store. The clear value leaves in a cookie and is never persisted.
func mintRemember() (token, digest string, err error) {
	token, err = newOpaqueToken()
	if err != nil {
		return "", "", err
	}
	sum := sha256.Sum256([]byte(token))
	return token, hex.EncodeToString(sum[:]), nil
}

// setRemember writes the remember token for this browser to return, expiring exactly
// when the account's window closes.
func setRemember(c *zip.Ctx, token string, window time.Duration) {
	c.Fiber().Cookie(&fiber.Cookie{
		Name:     rememberCookie,
		Value:    token,
		Path:     "/",
		MaxAge:   int(window / time.Second),
		HTTPOnly: true,
		Secure:   true,
		SameSite: fiber.CookieSameSiteLaxMode,
	})
}

// remembered reports whether THIS browser's "don't ask again" window is still open:
// the account's deadline is in the future AND the request carries the token that
// opened it. An unparsable, empty or mismatched value is not a skip — this fails
// CLOSED, to the challenge.
func remembered(c *zip.Ctx, user *schema.User, now time.Time) bool {
	if user.MfaRememberDeadline == "" || user.MfaRememberDigest == "" {
		return false
	}
	deadline, err := time.Parse(time.RFC3339, user.MfaRememberDeadline)
	if err != nil || !deadline.After(now) {
		return false
	}
	token := c.Fiber().Cookies(rememberCookie)
	if token == "" {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(user.MfaRememberDigest)) == 1
}

// remember opens the "don't ask again" window for the browser that just answered the
// factor: now + the ORG's MfaRememberInHours, and a fresh token in that browser.
//
// A zero window — every live organization today — yields a deadline already in the
// past, so the gate keeps challenging. That is the shipped behavior and it is
// preserved: turning a zero into "forever" would silently disable the factor for
// every tenant.
func remember(c *zip.Ctx, db orm.DB, user *schema.User) error {
	ctx := c.Context()
	org, err := store.GetOrganizationByName(ctx, db, user.Owner)
	if err != nil {
		return err
	}
	hours := 0
	if org != nil {
		hours = org.MfaRememberInHours
	}
	token, digest, err := mintRemember()
	if err != nil {
		return err
	}
	window := time.Duration(hours) * time.Hour
	// Written with the SAME format `remembered` parses — a mismatch here is a
	// permanent skip or a permanent challenge, silently.
	user.MfaRememberDeadline = nowFunc().UTC().Add(window).Format(time.RFC3339)
	user.MfaRememberDigest = digest
	if err := factor.Save(ctx, db, user); err != nil {
		return err
	}
	setRemember(c, token, window)
	return nil
}
