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
// from now.
func Issue(c Cookie, key []byte, ttl time.Duration) string {
	if c.SID == "" {
		c.SID = NewSID()
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
