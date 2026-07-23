// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"context"
	"strings"
	"time"

	"github.com/hanzoai/orm"
	"github.com/zap-proto/zip"

	"github.com/hanzoai/iam/internal/httpx"
	"github.com/hanzoai/iam/internal/mfa/factor"
	"github.com/hanzoai/iam/internal/schema"
	"github.com/hanzoai/iam/internal/store"
)

// The login-time second-factor gate. A verified password proves ONE factor;
// everything here decides whether a SECOND is owed before any token or device
// approval is minted. It is the counterpart to the enrollment surface in
// internal/mfa — enrollment decides what factors a user HAS, this decides when the
// sign-in must present one.
//
// The two answers are v1's wire STRINGS (object/factor.go:50-54): the client
// string-compares `data` against them, so they are wire format, not internal
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

	// The organization REQUIRES a factor this user has not enrolled: the answer is
	// enrollment, not a challenge it could never answer.
	if factor.Prompt(org, user) {
		return true, httpx.Ok(c, RequiredMfa)
	}
	if !factor.Enabled(user) {
		return false, nil
	}

	// "Remember this device" — a deadline in the FUTURE skips the factor. Written by
	// remember() with the same RFC3339 the parse below expects; a value the parser
	// cannot read is treated as no deadline, so a bad value re-challenges rather than
	// silently granting a permanent skip.
	if remembered(user, nowFunc()) {
		return false, nil
	}

	allow := allowList(user, org, verificationType)
	if len(allow) == 0 {
		// Every factor is either the one just used or not actually enrolled: there is
		// nothing left to ask for.
		return false, nil
	}

	id, err := MintChallenge(ctx, db, KindMfa, user.Owner+"/"+user.Name, verificationType, nowFunc())
	if err != nil {
		return true, err
	}
	SetChallenge(c, id)
	// data is the STRING "NextMfa"; data2 carries the factors. No code is minted
	// here — that is the whole point of the gate.
	return true, httpx.Ok(c, NextMfa, allow)
}

// allowList is the factors a challenge may be answered with: enrolled, and not the
// one the caller just used. Each carries the org's remember window so the client
// can offer "don't ask again".
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
		p.MfaRememberInHours = hours
		allow = append(allow, p)
	}
	return allow
}

// remembered reports whether the user's "don't ask again" window is still open. An
// unparsable or empty deadline is not a skip: this fails CLOSED, to the challenge.
func remembered(user *schema.User, now time.Time) bool {
	if user.MfaRememberDeadline == "" {
		return false
	}
	deadline, err := time.Parse(time.RFC3339, user.MfaRememberDeadline)
	return err == nil && deadline.After(now)
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

	// SECOND-FACTOR THROTTLE (deferred hardening, F-D1 INFO): the passcode/recovery
	// verify below has no DEDICATED per-account lockout counter of its own. It is not
	// an unthrottled brute-force oracle, because the MFA challenge is SINGLE-USE —
	// TakeChallenge above burns it (Used=true) BEFORE this verify — so each guess
	// requires a FRESH challenge, and a fresh challenge only comes from re-proving the
	// FIRST factor at the login door, which IS rate-limited by the atomic password
	// lockout (users.Authenticate). An attacker cannot rapidly iterate the 10^6 TOTP
	// space: every attempt costs one throttled, argon2id-costed password auth. A
	// dedicated second-factor counter (its own window + atomic increment, mirroring
	// internal/users/lockout.go) is a separate, tested change — deliberately NOT folded
	// into this cutover rework, to avoid destabilizing the MFA path.
	switch {
	case f.Passcode != "":
		// The challenge's payload is the factor already used to get here. Answering
		// with that same factor proves nothing new.
		if f.MfaType == "" || f.MfaType == ch.Payload {
			return httpx.Err(c, "invalid multi-factor authentication type")
		}
		if f.MfaType != factor.App {
			// Only TOTP has a verifier here. Refuse anything else rather than wave it
			// through: a factor with no verification is not a factor.
			return httpx.Err(c, "invalid multi-factor authentication type")
		}
		if !factor.Verify(user.TotpSecret, f.Passcode) {
			return httpx.Err(c, "the multi-factor authentication code is incorrect")
		}
	case f.RecoveryCode != "":
		// A recovery code is one-time: the hit is removed and the row written whether
		// or not the rest of the sign-in succeeds, so a code cannot be spent twice.
		if !factor.UseRecovery(user, f.RecoveryCode) {
			return httpx.Err(c, "the recovery code is incorrect")
		}
		if err := factor.Save(ctx, db, user); err != nil {
			return httpx.Err(c, err.Error())
		}
	default:
		return httpx.Err(c, "missing passcode or recovery code")
	}

	if f.EnableMfaRemember {
		if err := remember(ctx, db, user); err != nil {
			return httpx.Err(c, err.Error())
		}
	}
	return loginGrant(c, db, user, f)
}

// remember opens the "don't ask again" window: now + the ORG's MfaRememberInHours.
// A zero window — every live organization today — yields a deadline already in the
// past, so the gate keeps challenging. That is the shipped behavior and it is
// preserved: turning a zero into "forever" would silently disable the factor for
// every tenant.
func remember(ctx context.Context, db orm.DB, user *schema.User) error {
	org, err := store.GetOrganizationByName(ctx, db, user.Owner)
	if err != nil {
		return err
	}
	hours := 0
	if org != nil {
		hours = org.MfaRememberInHours
	}
	// Written with the SAME format `remembered` parses — a mismatch here is a
	// permanent skip or a permanent challenge, silently.
	user.MfaRememberDeadline = nowFunc().UTC().Add(time.Duration(hours) * time.Hour).Format(time.RFC3339)
	return factor.Save(ctx, db, user)
}
