// Copyright 2026 Hanzo AI, Inc. All rights reserved.
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

// CookieName is the portal session cookie the native front-door sets on a bare
// (type=login) sign-in and that get-account resolves the caller from. One name,
// platform-wide.
const CookieName = "hanzo_session"

// Id is ONE signed-in identity the browser holds. It keys the Session row
// directly — (Owner, Name, Application) — so resolution needs no scan, and SID
// is the per-cookie id checked against that row's SessionId list for revocation.
// Owner is the field the gateway admin-guard reads to derive the global-admin
// predicate, so the signature is what makes it unforgeable.
//
// Owner/Name IS the identity, exactly as `hanzo auth list` prints it, and Owner
// is the billing org. One vocabulary across the CLI and the browser.
type Id struct {
	Owner       string `json:"o"`
	Name        string `json:"n"`
	Application string `json:"a"`
	SID         string `json:"s"`
}

// String renders the identity the way the CLI does — "owner/name".
func (i Id) String() string { return i.Owner + "/" + i.Name }

// Is reports whether this is the (owner, name) identity, ignoring which
// application issued the cookie. Identity is the PRINCIPAL, not the door it
// came through.
func (i Id) Is(owner, name string) bool { return i.Owner == owner && i.Name == name }

// Cookie is the tamper-evident session a signed cookie carries: every identity
// the browser is signed in as, and which one is ACTIVE.
//
// A list, not a single identity, because a human holds several — z@hanzo.ai for
// one org and a@hanzo.ai for another — and the CLI has modelled it that way
// since multi-identity landed there (`hanzo auth list` / `use`). The browser was
// the surface that never got the model, which is why signing into a second
// account silently destroyed the first. Adding an identity APPENDS; nothing is
// clobbered.
//
// Active is an INDEX rather than a copy of the identity, so "which one is
// active" has exactly one representation and cannot disagree with the list.
// Out-of-range is not an error to the reader — Current() reports no session,
// which is the fail-secure answer.
type Cookie struct {
	Ids    []Id  `json:"i"`
	Active int   `json:"k"`
	Expiry int64 `json:"e"` // unix seconds
}

// Current returns the active identity. ok=false when the cookie carries none —
// including a pre-multi-identity cookie, whose payload decodes to an empty list
// and therefore reads as "not signed in" rather than as some guessed identity.
func (c *Cookie) Current() (Id, bool) {
	if c == nil || c.Active < 0 || c.Active >= len(c.Ids) {
		return Id{}, false
	}
	return c.Ids[c.Active], true
}

// With returns the cookie that also holds id, made active. Signing in again as
// an identity already held REPLACES its entry (a fresh sid supersedes the old
// one for that identity) rather than duplicating it.
func (c Cookie) With(id Id) Cookie {
	// Copy before writing: Cookie is a value, but its slice header is not, so an
	// in-place write would reach through into the caller's backing array.
	c.Ids = append([]Id{}, c.Ids...)
	for n, held := range c.Ids {
		if held.Is(id.Owner, id.Name) {
			c.Ids[n] = id
			c.Active = n
			return c
		}
	}
	c.Ids = append(c.Ids, id)
	c.Active = len(c.Ids) - 1
	return c
}

// Using returns the cookie with (owner, name) made active, and whether it was
// held at all. A miss changes nothing — never a silent fallback to another
// identity, which would act as a principal the caller did not name.
func (c Cookie) Using(owner, name string) (Cookie, bool) {
	for n, held := range c.Ids {
		if held.Is(owner, name) {
			c.Active = n
			return c, true
		}
	}
	return c, false
}

// Without returns the cookie with (owner, name) removed, that identity's entry
// (for sid revocation by the caller), and whether it was held.
//
// Dropping the ACTIVE identity signs you out of it and does NOT silently promote
// whichever identity is left — Active goes out of range, so the browser holds no
// active session until one is chosen. Same law as `hanzo auth logout`.
func (c Cookie) Without(owner, name string) (Cookie, Id, bool) {
	for n, held := range c.Ids {
		if !held.Is(owner, name) {
			continue
		}
		c.Ids = append(append([]Id{}, c.Ids[:n]...), c.Ids[n+1:]...)
		switch {
		case c.Active == n:
			c.Active = -1 // signed out of the active identity: nothing is active
		case c.Active > n:
			c.Active--
		}
		return c, held, true
	}
	return c, Id{}, false
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
// Any identity left without a SID gets a fresh one; Expiry ≤ 0 defaults to ttl
// from now.
func Issue(c Cookie, key []byte, ttl time.Duration) string {
	for n := range c.Ids {
		if c.Ids[n].SID == "" {
			c.Ids[n].SID = NewSID()
		}
	}
	if c.Expiry <= 0 {
		c.Expiry = time.Now().Add(ttl).Unix()
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
