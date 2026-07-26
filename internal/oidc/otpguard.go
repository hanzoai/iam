// Copyright 2026 Hanzo AI, Inc. All rights reserved.

package oidc

import (
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"
)

// The gate in front of the OTP send. It exists because of what the send BECAME
// the moment delivery was wired: POST /v1/iam/send-verification-code is
// unauthenticated by design — the cloud edge allow-lists it in iamPublic, and it
// answers on hanzo.id, lux.id, pars.id and api.hanzo.ai — and it now spends real
// money per call. An unauthenticated, unthrottled, destination-unvalidated send
// primitive attached to a telco account is an International Revenue Share Fraud
// (IRSF) payout machine: the attacker owns the premium-rate range, loops the
// endpoint, and collects a cut of a bill we pay. SMS pumping is the same trick at
// volume. Email is the cheaper cousin — arbitrary destinations from our domain,
// which spends reputation instead of cash.
//
// So the gate is not defense in depth around a working feature; it is part of the
// feature. Delivery and this file land together or neither lands.
//
// THREE independent limits, all of which must pass, cheapest first. They are
// deliberately NOT one number: each bounds a different adversary.
//
//   - destination — one address/number cannot be made to ring. Bounds harassment
//     and bounds the payout on any single attacker-owned number.
//   - application — one client cannot become the fleet's whole spend. Bounds a
//     compromised or hostile app registration.
//   - global      — the service as a whole has a ceiling. This is the money stop:
//     whatever else is wrong, the bill per hour is bounded by a number a human
//     chose. It is the only limit that holds when the attacker rotates both the
//     destination and the application.
//
// The limits are CONSTANTS, not configuration. A toll-fraud ceiling that can be
// raised by an environment variable is a toll-fraud ceiling an incident will
// raise at 3am; widening it should be a reviewed edit, and the numbers below are
// deliberately conservative enough that a legitimate login flow never notices.
//
// NOT KEYED ON THE CLIENT IP, deliberately. zip is constructed with no
// ProxyHeader/TrustedProxies configuration, so behind Cloudflare and the ingress
// the remote address is the PROXY's, identical for every caller on earth. A
// per-IP bucket keyed on it is one global bucket wearing a disguise: it would
// throttle the entire fleet to one user's quota while giving an attacker no
// resistance at all. Until the trusted-proxy chain is configured, the client
// address is not evidence of anything and this file does not consult it.
const (
	// otpDestinationWindow / Burst: a single destination may receive at most
	// Burst codes per Window. One legitimate sign-in needs one; a user who
	// mistypes and retries needs two or three.
	otpDestinationWindow = time.Hour
	otpDestinationBurst  = 3

	// otpDestinationCooldown is the floor between two codes to the SAME
	// destination. It defeats the tight loop even before the hourly count is
	// spent, and it is what makes a "resend" button safe to press twice.
	otpDestinationCooldown = 60 * time.Second

	// otpApplicationWindow / Burst bounds one registered application.
	otpApplicationWindow = time.Hour
	otpApplicationBurst  = 100

	// otpGlobalWindow / Burst is the service-wide ceiling — the money stop.
	otpGlobalWindow = time.Hour
	otpGlobalBurst  = 500
)

// otpLimiter is a fixed-window counter keyed by an opaque string. One type
// serves all three scopes; the scope is the key prefix, so there is one
// implementation of "how many in the last window" and no chance of two scopes
// disagreeing about what a window means.
//
// Fixed window (not a token bucket) because the property that matters here is a
// hard, auditable ceiling per clock window — "no more than N per hour, ever" is
// the sentence a finance incident needs answered, and it is the sentence this
// data structure answers exactly.
type otpLimiter struct {
	mu      sync.Mutex
	windows map[string]*otpWindow
}

type otpWindow struct {
	start time.Time // when the current fixed window opened
	last  time.Time // when the most recent attempt landed — the cooldown reads this
	count int
}

// newOTPLimiter builds an empty limiter.
func newOTPLimiter() *otpLimiter {
	return &otpLimiter{windows: make(map[string]*otpWindow)}
}

// otpGuardLimiter is the process-wide limiter. It is in-process, which is an
// honest bound and not a perfect one: with N replicas the effective ceiling is
// N× these constants. IAM runs a single writer against an RWO volume today, so
// N is 1 and the ceiling is exact; if IAM is ever scaled out, this must move
// behind a shared counter before the replica count is raised, or the money stop
// silently multiplies.
var otpGuardLimiter = newOTPLimiter()

// allow records an attempt against key and reports whether it is within burst
// per window. The window is fixed: the first attempt starts it, and the counter
// resets once it elapses. Expired entries for OTHER keys are swept on the way
// through so an attacker rotating destinations cannot grow the map without
// bound — the sweep is what keeps this from becoming its own memory-exhaustion
// vector.
func (l *otpLimiter) allow(key string, window time.Duration, burst int) bool {
	now := nowFunc()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)

	w, ok := l.windows[key]
	if !ok || now.Sub(w.start) >= window {
		l.windows[key] = &otpWindow{start: now, last: now, count: 1}
		return true
	}
	if w.count >= burst {
		return false
	}
	w.count++
	w.last = now
	return true
}

// lastAttempt returns when key was most recently recorded, and whether it is
// known. The cooldown reads this — NOT the window start, which would only ever
// measure from the first attempt in the window and let a caller slip a second
// code through late in a window that began an hour ago.
func (l *otpLimiter) lastAttempt(key string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	w, ok := l.windows[key]
	if !ok {
		return time.Time{}, false
	}
	return w.last, true
}

// sweepLocked drops windows that can no longer deny anything. Bounded by the
// longest window in use, so the map holds only live keys.
func (l *otpLimiter) sweepLocked(now time.Time) {
	const longest = otpGlobalWindow
	if len(l.windows) < 1024 {
		return
	}
	for k, w := range l.windows {
		if now.Sub(w.start) >= longest {
			delete(l.windows, k)
		}
	}
}

// e164 is the strict E.164 form: a leading +, a non-zero country digit, then 7
// to 14 more digits. Nothing else — no spaces, dashes, parentheses, letters, or
// control characters. The handler previously accepted `dest` for type=phone
// verbatim, which let "+900-PREMIUM-RATE", a 4096-digit string, an SQL fragment,
// and a CRLF header-injection payload all reach the transport.
var e164 = regexp.MustCompile(`^\+[1-9]\d{7,14}$`)

// otpDialingAllowed is the ALLOW-LIST of country calling codes this service will
// send SMS to. An allow-list, not a block-list: IRSF pays out through obscure
// ranges nobody thinks to block, so "everything except the bad ones" loses by
// construction and "nothing except the ones we chose" wins.
//
// It is +1 (NANP) today because that is the whole of the evidence: the Twilio
// account backing this carries exactly one number and it is +1, and there is no
// live consumer sending anywhere else. This is a POLICY choice, not a technical
// limit — widening it is one line here, and should be a deliberate decision with
// the fraud exposure of the added range understood.
var otpDialingAllowed = []string{"+1"}

// validPhone returns dest in strict E.164 form, or an error. It is the ONE place
// a phone destination is judged.
func validPhone(dest string) (string, error) {
	d := strings.TrimSpace(dest)
	if !e164.MatchString(d) {
		return "", errors.New("phone must be in E.164 form, e.g. +15551234567")
	}
	for _, cc := range otpDialingAllowed {
		if strings.HasPrefix(d, cc) {
			return d, nil
		}
	}
	// The refusal names no allowed prefix — an attacker probing for the reachable
	// ranges learns nothing beyond "not this one".
	return "", errors.New("this destination is not eligible for verification codes")
}

// validEmail returns the PARSED address, never the caller's raw string. These
// differ more often than they look: mail.ParseAddress accepts
// `Alice <victim@example.com>` (display name plus a different address) and
// `"a@b"@evil.tld` (a quoted local part). Validating the raw string and then
// DELIVERING it — which is what this handler did — means the address checked is
// not the address sent, and the display-name form lets the visible recipient and
// the actual recipient disagree. Everything downstream uses this return value.
func validEmail(dest string) (string, error) {
	a, err := mail.ParseAddress(strings.TrimSpace(dest))
	if err != nil {
		return "", errors.New("email is invalid")
	}
	// A parsed address is bare `local@domain`; anything the caller wrapped
	// around it is discarded here rather than carried to the transport.
	return strings.ToLower(a.Address), nil
}

// guardOTP is the ONE gate the send handler calls. It normalizes the
// destination, judges it, and spends quota in all three scopes — returning the
// canonical destination to deliver to, or the reason the request is refused.
//
// Quota is spent BEFORE delivery and is not refunded on a delivery failure. That
// is deliberate: a failing destination is exactly what an attacker probing for a
// reachable premium range produces, and refunding it would make failure free.
func guardOTP(typ, dest, application string) (string, error) {
	var canonical string
	var err error
	switch typ {
	case "email":
		canonical, err = validEmail(dest)
	case "phone":
		canonical, err = validPhone(dest)
	default:
		return "", errors.New("unsupported verification type: " + typ)
	}
	if err != nil {
		return "", err
	}

	// Destination cooldown first: it is the cheapest check and the one a
	// legitimate double-click hits, so it should answer before quota is spent.
	dkey := "d:" + typ + ":" + canonical
	if at, ok := otpGuardLimiter.lastAttempt(dkey); ok {
		if since := nowFunc().Sub(at); since < otpDestinationCooldown {
			return "", fmt.Errorf("a verification code was just sent; retry in %ds",
				int((otpDestinationCooldown-since).Seconds())+1)
		}
	}
	// Then the three ceilings, narrowest first, so the most specific limit is
	// the one a caller is told about.
	if !otpGuardLimiter.allow(dkey, otpDestinationWindow, otpDestinationBurst) {
		return "", errors.New("too many verification codes for this destination; try again later")
	}
	if !otpGuardLimiter.allow("a:"+application, otpApplicationWindow, otpApplicationBurst) {
		return "", errors.New("too many verification codes requested; try again later")
	}
	if !otpGuardLimiter.allow("g:", otpGlobalWindow, otpGlobalBurst) {
		return "", errors.New("verification codes are temporarily unavailable; try again later")
	}
	return canonical, nil
}
