// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0
package sessions

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// CookieName is the portal session cookie the native endpoints set on a bare
// (type=login) sign-in, that get-account resolves the caller from, and that the
// authorize endpoint reads to answer "is anyone signed in here?" without showing
// a login screen. One name, platform-wide.
//
// # Why this cookie is HOST-ONLY, and why the browser is made to enforce it
//
// It is scoped to the ISSUER ORIGIN alone (no Domain attribute), so hanzo.id
// holds it and no other host ever receives it. The alternative — Domain=.hanzo.ai
// — is what "share the session with every app" sounds like it needs, and it is
// the wrong trade:
//
//   - A Domain cookie is sent to EVERY host under that domain, and the cookie
//     spec offers no way to name a subset. There is no "all subdomains except
//     the ones a customer controls".
//   - This fleet publishes tenant-facing hosts under its own zones, and an
//     operator can add one at any time. A single XSS, a single misrouted
//     wildcard, a single parked subdomain, and the parent-domain cookie is
//     readable by a page nobody vetted. That is the whole IdP session, for every
//     app at once.
//   - Nothing about SSO requires it. The second app reaches the IdP by TOP-LEVEL
//     REDIRECT, and a host-only cookie is presented on that navigation exactly
//     as a Domain cookie would be (SameSite=Lax sends it on a top-level GET).
//     The Domain attribute would buy only the ability to read the session from
//     JavaScript on another host — which is precisely what must never happen.
//
// The `__Host-` prefix makes that decision the BROWSER's rather than ours. A
// user agent refuses to store a `__Host-`-prefixed cookie unless it is Secure,
// Path=/, and carries NO Domain — so a sibling host physically cannot set one.
//
// That is not decoration: without the prefix a hostile or merely compromised
// sibling host can Set-Cookie `hanzo_session=<its own valid session>;
// Domain=.hanzo.ai`, the browser then presents TWO cookies of this name to the
// IdP, and which one wins is a matter of ordering. The victim is silently signed
// in as the attacker — session fixation. Silent SSO makes that strictly worse,
// because the fixed session then propagates to every downstream app with no
// screen the victim could have noticed. The prefix is therefore a PRECONDITION
// of the silent flow, not an improvement on it.
//
// Renaming retires every session issued under the old name: they no longer
// resolve, and each human signs in once more. That is the intended one-time
// cost of moving the guarantee into the browser.
const CookieName = "__Host-hanzo_session"

// Cookie is the tamper-evident session a signed cookie carries. It keys the
// Session row directly — (Owner, Name, Application) — so resolution needs no
// scan, and SID is the per-cookie id checked against that row's SessionId list
// for revocation. Owner is the field the gateway admin-guard reads to derive the
// global-admin predicate, so the signature is what makes it unforgeable.
type Cookie struct {
	Owner       string `json:"o"`
	Name        string `json:"n"`
	Application string `json:"a"`
	SID         string `json:"s"`
	Expiry      int64  `json:"e"` // unix seconds

	// AuthTime is when the human actually proved who they are — the OIDC
	// `auth_time`, in unix seconds. It is NOT the cookie's issue time and must
	// not be refreshed by anything short of a real re-authentication, because
	// its whole job is to answer a relying party that asks `max_age`: "was this
	// person's password (and second factor) checked recently enough for what I
	// am about to let them do?"
	//
	// Before silent re-authentication that question answered itself — every
	// authorize hit rendered a login form, so every grant was fresh. Once a
	// session can be spent without any prompt, an ignored max_age silently
	// hands a step-up-sensitive client a months-old sign-in. So the session
	// carries the answer.
	AuthTime int64 `json:"i"`
}

var (
	// ErrCookieMalformed — not a "<payload>.<mac>" pair or not decodable.
	ErrCookieMalformed = errors.New("session cookie is malformed")
	// ErrCookieSignature — the HMAC does not verify (forged or wrong key).
	ErrCookieSignature = errors.New("session cookie signature is invalid")
	// ErrCookieExpired — past its expiry.
	ErrCookieExpired = errors.New("session cookie is expired")
)

// SessionKey derives the cookie HMAC key from the platform signing cert's private
// key material — a stable, secret, per-deployment value, so there is NO new
// secret to provision and cookies survive restarts. Domain-separated so the key
// can never collide with any other use of the cert.
func SessionKey(certPrivateKeyPEM string) []byte {
	sum := sha256.Sum256([]byte("iam.session.cookie.v1\x00" + certPrivateKeyPEM))
	return sum[:]
}

// NewSID mints a 256-bit random session id (URL-safe, no padding).
func NewSID() string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Issue serializes and signs a session cookie: base64url(payload).base64url(mac).
// A caller that leaves SID empty gets a fresh one; Expiry ≤ 0 defaults to ttl
// from now, and AuthTime ≤ 0 to now — a cookie minted without one IS the moment
// the credential was checked. A caller CARRYING one forward (a re-key) passes it
// in, so moving a session never looks like a fresh sign-in to `max_age`.
func Issue(c Cookie, key []byte, ttl time.Duration) string {
	now := time.Now()
	if c.SID == "" {
		c.SID = NewSID()
	}
	if c.Expiry <= 0 {
		c.Expiry = now.Add(ttl).Unix()
	}
	if c.AuthTime <= 0 {
		c.AuthTime = now.Unix()
	}
	payload, _ := json.Marshal(c)
	return b64(payload) + "." + b64(mac(payload, key))
}

// Verify checks the signature (constant-time) then the expiry, returning the
// carried claims. It NEVER trusts the payload before the MAC verifies — an
// attacker who flips `o` to the admin org fails the signature check.
func Verify(value string, key []byte) (*Cookie, error) {
	rawPayload, rawMac, ok := strings.Cut(value, ".")
	if !ok {
		return nil, ErrCookieMalformed
	}
	payload, err := unb64(rawPayload)
	if err != nil {
		return nil, ErrCookieMalformed
	}
	gotMac, err := unb64(rawMac)
	if err != nil {
		return nil, ErrCookieMalformed
	}
	if subtle.ConstantTimeCompare(gotMac, mac(payload, key)) != 1 {
		return nil, ErrCookieSignature
	}
	var c Cookie
	if err := json.Unmarshal(payload, &c); err != nil {
		return nil, ErrCookieMalformed
	}
	if c.Expiry > 0 && time.Now().Unix() >= c.Expiry {
		return nil, ErrCookieExpired
	}
	return &c, nil
}

func mac(payload, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(payload)
	return h.Sum(nil)
}

func b64(b []byte) string            { return base64.RawURLEncoding.EncodeToString(b) }
func unb64(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
